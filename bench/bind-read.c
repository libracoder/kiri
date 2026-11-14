#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    int fd = open(argv[1], O_RDONLY);
    if (fd < 0) { perror("open"); return 1; }
    int advised = posix_fadvise(fd, 0, 0, POSIX_FADV_DONTNEED);
    if (advised) { errno = advised; perror("posix_fadvise"); return 1; }
    char *buf = malloc(1024 * 1024);
    if (!buf) return 1;
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    size_t total = 0;
    ssize_t n;
    while ((n = read(fd, buf, 1024 * 1024)) > 0) total += (size_t)n;
    if (n < 0) { perror("read"); return 1; }
    clock_gettime(CLOCK_MONOTONIC, &end);
    double seconds = end.tv_sec - start.tv_sec + (end.tv_nsec - start.tv_nsec) / 1e9;
    printf("{\"bytes\":%zu,\"seconds\":%.9f,\"mibPerSecond\":%.3f}\n", total, seconds, total / 1048576.0 / seconds);
    close(fd);
    free(buf);
    return total ? 0 : 1;
}
