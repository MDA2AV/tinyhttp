This is the tiny boi

Install dependencies: sudo apt install liburing-dev

How to build: gcc -O3 -march=native -Wall -Wextra uring_http.c -luring -o uring_http
How to run: ./uring_http 0.0.0.0 8081
