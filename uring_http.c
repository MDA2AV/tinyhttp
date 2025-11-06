#define _GNU_SOURCE
#include <liburing.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define RING_ENTRIES  8192
#define MAX_CONN      65536
#define RECV_BUF_SZ   8192
#define STREAM_CHUNK  (16*1024)
#define BACKLOG       16384
#define BATCH_CQES    256
#define PRIME_ACCEPTS 2048

typedef enum { UD_ACCEPT = 1, UD_RECV = 2, UD_SEND = 3 } ud_kind;
static inline uint64_t pack_ud(ud_kind k, int fd){ return ((uint64_t)k<<32)|(uint32_t)fd; }
static inline ud_kind ud_kind_of(uint64_t ud){ return (ud_kind)(ud>>32); }
static inline int ud_fd_of(uint64_t ud){ return (int)(ud & 0xffffffffu); }

typedef enum { REQ_PP=1, REQ_STREAM=2 } req_kind;

typedef struct {
  int fd;
  bool alive;
  bool sending;
  uint8_t  rbuf[RECV_BUF_SZ];
  int      rlen;
  size_t   stream_left;
  size_t   out_off, out_len;
  uint8_t* out_buf;
} Conn;

static Conn* conns[MAX_CONN];
static struct io_uring ring;
static volatile sig_atomic_t stop_flag=0;

static const char OK_HDR[] =
  "HTTP/1.1 200 OK\r\n"
  "Content-Length: 2\r\n"
  "Connection: keep-alive\r\n"
  "Content-Type: text/plain\r\n"
  "\r\n"
  "OK";

static char    stream_hdr[128];
static uint8_t stream_chunk[STREAM_CHUNK];

static void on_sigint(int s){ (void)s; stop_flag=1; }
static int set_nonblock(int fd){ int fl=fcntl(fd,F_GETFL,0); if(fl<0) return -1; return fcntl(fd,F_SETFL,fl|O_NONBLOCK); }
static int set_tcp_nodelay(int fd){ int yes=1; return setsockopt(fd,IPPROTO_TCP,TCP_NODELAY,&yes,sizeof(yes)); }

static int create_listen(const char* ip, uint16_t port){
  int fd=socket(AF_INET,SOCK_STREAM,0);
  int yes=1; setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof(yes));
#ifdef SO_REUSEPORT
  setsockopt(fd,SOL_SOCKET,SO_REUSEPORT,&yes,sizeof(yes));
#endif
  struct sockaddr_in a={0}; a.sin_family=AF_INET; a.sin_port=htons(port); inet_pton(AF_INET,ip,&a.sin_addr);
  bind(fd,(struct sockaddr*)&a,sizeof(a)); listen(fd,BACKLOG); set_nonblock(fd); return fd;
}

static Conn* conn_get(int fd){
  Conn* c=conns[fd];
  if(!c) c=conns[fd]=calloc(1,sizeof(Conn));
  c->fd=fd; c->alive=true; c->sending=false; c->rlen=0; c->stream_left=0; c->out_buf=NULL; c->out_off=c->out_len=0;
  return c;
}
static void conn_close(int fd){ Conn* c=conns[fd]; if(c){ close(fd); c->alive=false; } }

static struct io_uring_sqe* sqe_get(){
  struct io_uring_sqe* sqe=io_uring_get_sqe(&ring);
  if(!sqe){ io_uring_submit(&ring); sqe=io_uring_get_sqe(&ring); }
  return sqe;
}
static inline void flush_if_ready(){ if(io_uring_sq_ready(&ring)>0) io_uring_submit(&ring); }

static void submit_accept(int lfd){
  struct io_uring_sqe* sqe=sqe_get();
  io_uring_prep_accept(sqe, lfd, NULL, NULL, SOCK_NONBLOCK);
  io_uring_sqe_set_data64(sqe, pack_ud(UD_ACCEPT, lfd));
}
static void submit_recv(Conn* c){
  struct io_uring_sqe* sqe=sqe_get();
  io_uring_prep_recv(sqe, c->fd, c->rbuf + c->rlen, RECV_BUF_SZ - c->rlen, 0);
  io_uring_sqe_set_data64(sqe, pack_ud(UD_RECV, c->fd));
}
static void submit_send(Conn* c){
  size_t len=c->out_len - c->out_off;
  struct io_uring_sqe* sqe=sqe_get();
  io_uring_prep_send(sqe, c->fd, c->out_buf + c->out_off, len, 0);
  io_uring_sqe_set_data64(sqe, pack_ud(UD_SEND, c->fd));
  c->sending=true;
}

static int parse_one(uint8_t* buf,int len, req_kind* kind,size_t* outN){
  const char* end=NULL;
  for(int i=3;i<len;i++) if(buf[i-3]=='\r'&&buf[i-2]=='\n'&&buf[i-1]=='\r'&&buf[i]=='\n'){ end=(char*)buf+i+1; break; }
  if(!end) return 0;
  char* sp1=memmem(buf, end-(char*)buf, " ", 1);
  char* sp2=memmem(sp1+1, end-sp1-1, " ", 1);
  size_t path_len=sp2-(sp1+1);
  char path[256]; if(path_len>=sizeof(path)) path_len=sizeof(path)-1; memcpy(path,sp1+1,path_len); path[path_len]=0;
  if(!strncmp(path,"/pp",3)) *kind=REQ_PP;
  else if(!strncmp(path,"/stream",7)){
    size_t n=0; char* q=strchr(path,'?'); if(q){ char* e=strchr(q,'='); if(e) n=strtoull(e+1,NULL,10); }
    if(n==0) n=1024*1024; *outN=n; *kind=REQ_STREAM;
  } else *kind=REQ_PP;
  return (int)((uint8_t*)end - buf);
}

static void begin_pp(Conn* c){ c->out_buf=(uint8_t*)OK_HDR; c->out_len=sizeof(OK_HDR)-1; c->out_off=0; submit_send(c); }
static void begin_stream_h(Conn* c,size_t n){
  int hdr_len=snprintf(stream_hdr,sizeof(stream_hdr),
    "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nConnection: keep-alive\r\nContent-Length: %zu\r\n\r\n", n);
  c->out_buf=(uint8_t*)stream_hdr; c->out_len=hdr_len; c->out_off=0; c->stream_left=n; submit_send(c);
}
static void stream_chunk_send(Conn* c){
  if(!c->stream_left){ submit_recv(c); return; }
  size_t to = c->stream_left<STREAM_CHUNK ? c->stream_left : STREAM_CHUNK;
  c->out_buf=stream_chunk; c->out_len=to; c->out_off=0; c->stream_left-=to; submit_send(c);
}

static void parse_loop(Conn* c){
  int used_total=0;
  while(1){
    req_kind k=0; size_t n=0;
    int used=parse_one(c->rbuf+used_total, c->rlen-used_total, &k, &n);
    if(used<=0) break;
    used_total+=used;
    if(k==REQ_PP) begin_pp(c); else begin_stream_h(c,n);
  }
  if(used_total>0){
    int remain=c->rlen-used_total; if(remain>0) memmove(c->rbuf, c->rbuf+used_total, remain); c->rlen=remain;
  }
  if(!c->sending && c->rlen<RECV_BUF_SZ) submit_recv(c);
}

int main(int argc,char**argv){
  if(argc<3){ fprintf(stderr,"usage: %s <ip> <port>\n", argv[0]); return 1; }
  const char* ip=argv[1]; uint16_t port=(uint16_t)atoi(argv[2]);
  for(size_t i=0;i<STREAM_CHUNK;i++) stream_chunk[i]=(uint8_t)(i&0xFF);
  signal(SIGINT,on_sigint);
  int lfd=create_listen(ip,port);

  struct io_uring_params p; memset(&p,0,sizeof(p));
  p.flags |= IORING_SETUP_COOP_TASKRUN | IORING_SETUP_SINGLE_ISSUER;
  if(io_uring_queue_init_params(RING_ENTRIES,&ring,&p)<0){ perror("io_uring_queue_init_params"); return 1; }

  for(int i=0;i<PRIME_ACCEPTS;i++) submit_accept(lfd);
  flush_if_ready();

  while(!stop_flag){
    struct io_uring_cqe* cqes[BATCH_CQES];
    int got=io_uring_peek_batch_cqe(&ring, cqes, BATCH_CQES);
    if(got<=0){
      struct io_uring_cqe* cqe=NULL;
      if(io_uring_wait_cqe(&ring,&cqe)==0){ cqes[0]=cqe; got=1; }
      else continue;
    }

    for(int i=0;i<got;i++){
      struct io_uring_cqe* cqe=cqes[i];
      uint64_t ud=io_uring_cqe_get_data64(cqe);
      ud_kind k=ud_kind_of(ud);
      int res=cqe->res;

      if(k==UD_ACCEPT){
        if(res>=0){
          int fd=res; set_nonblock(fd); set_tcp_nodelay(fd);
          Conn* c=conn_get(fd);
          submit_recv(c);
          submit_accept(lfd);
        } else {
          submit_accept(lfd);
        }
      } else if(k==UD_RECV){
        int fd=ud_fd_of(ud); Conn* c=conns[fd];
        if(res<=0){ conn_close(fd); }
        else { c->rlen+=res; parse_loop(c); }
      } else if(k==UD_SEND){
        int fd=ud_fd_of(ud); Conn* c=conns[fd];
        if(res<=0){ conn_close(fd); }
        else{
          c->out_off += (size_t)res;
          if(c->out_off < c->out_len){
            submit_send(c);
          } else {
            c->sending=false;
            if(c->out_buf==(uint8_t*)stream_hdr)      stream_chunk_send(c);
            else if(c->out_buf==stream_chunk){
              if(c->stream_left>0) stream_chunk_send(c);
              else submit_recv(c);
            } else {
              if(c->rlen>0) parse_loop(c);
              else submit_recv(c);
            }
          }
        }
      }

      io_uring_cqe_seen(&ring,cqe);
    }

    flush_if_ready();
  }

  close(lfd);
  io_uring_queue_exit(&ring);
  return 0;
}

