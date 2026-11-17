#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static void die(const char *s) { perror(s); exit(1); }
static double clock_s(void) { struct timespec t; if (clock_gettime(CLOCK_MONOTONIC, &t)) die("clock"); return t.tv_sec + t.tv_nsec / 1e9; }
int main(int argc, char **argv) {
    if (argc != 3) return 2;
    const char *mode = argv[1], *root = argv[2];
    char path[4096], data[4096];
    uint64_t count = 0, bytes = 0, check = 0;
    double start = clock_s();
    if (!strcmp(mode, "seq-cold") || !strcmp(mode, "seq-warm")) {
        snprintf(path, sizeof path, "%s/fixture.bin", root);
        int fd = open(path, O_RDONLY); if (fd < 0) die("open");
        if (!strcmp(mode, "seq-cold")) { int e = posix_fadvise(fd, 0, 0, POSIX_FADV_DONTNEED); if (e) { errno = e; die("fadvise"); } }
        size_t size = 1 << 20;
        char *buffer = malloc(size); if (!buffer) die("malloc");
        ssize_t n;
        while ((n = read(fd, buffer, size)) > 0) { bytes += (uint64_t)n; check += (unsigned char)buffer[0]; ++count; }
        if (n < 0) die("read");
        if (close(fd)) die("close"); free(buffer);
        if (bytes != 536870912) return 3;
    } else if (!strcmp(mode, "metadata") || !strcmp(mode, "small-read")) {
        for (unsigned i = 0; i < 4096; ++i) {
            snprintf(path, sizeof path, "%s/tree/f%04u.dat", root, i);
            struct stat s; if (stat(path, &s)) die("stat");
            if (s.st_size != 256) return 3;
            if (!strcmp(mode, "small-read")) {
                int fd = open(path, O_RDONLY); if (fd < 0) die("open");
                ssize_t n = read(fd, data, sizeof data); if (n != 256) return 3;
                if ((unsigned char)data[0] != i % 251) return 4;
                if (close(fd)) die("close"); check += (unsigned char)data[0];
            }
            bytes += (uint64_t)s.st_size; ++count;
        }
    } else if (!strcmp(mode, "durable-write")) {
        for (unsigned i = 0; i < 64; ++i) {
            snprintf(path, sizeof path, "%s/writes/f%04u.dat", root, i);
            memset(data, (int)(i % 251), sizeof data);
            int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644); if (fd < 0) die("open");
            if (write(fd, data, sizeof data) != sizeof data) die("write");
            if (fdatasync(fd)) die("fdatasync");
            if (close(fd)) die("close"); bytes += sizeof data; ++count;
        }
        snprintf(path, sizeof path, "%s/writes", root);
        int fd = open(path, O_RDONLY | O_DIRECTORY); if (fd < 0) die("open directory");
        if (fsync(fd)) die("fsync directory"); if (close(fd)) die("close directory");
    } else if (!strcmp(mode, "cpu")) {
        uint64_t v = 0x123456789abcdef0;
        for (unsigned i = 0; i < 20000000; ++i) { v ^= v << 13; v ^= v >> 7; v ^= v << 17; }
        check = v; count = 20000000;
    } else return 2;
    printf("{\"mode\":\"%s\",\"seconds\":%.9f,\"count\":%llu,\"bytes\":%llu,\"checksum\":\"%016llx\"}\n", mode, clock_s()-start, (unsigned long long)count, (unsigned long long)bytes, (unsigned long long)check);
    return 0;
}
