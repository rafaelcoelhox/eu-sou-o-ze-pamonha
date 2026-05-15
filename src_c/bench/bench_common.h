#ifndef RINHA_BENCH_COMMON_H
#define RINHA_BENCH_COMMON_H

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

typedef struct {
    char *data;
    size_t len;
} BenchFile;

typedef struct {
    const char *ptr;
    size_t len;
} BenchJsonSpan;

static uint64_t bench_now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static BenchFile bench_read_file(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        perror(path);
        exit(1);
    }

    struct stat st;
    if (fstat(fd, &st) < 0) {
        perror("fstat");
        exit(1);
    }

    size_t len = (size_t)st.st_size;
    char *data = malloc(len + 1);
    if (!data) {
        fputs("OOM\n", stderr);
        exit(1);
    }

    size_t off = 0;
    while (off < len) {
        ssize_t n = read(fd, data + off, len - off);
        if (n > 0) {
            off += (size_t)n;
            continue;
        }
        if (n < 0 && errno == EINTR) {
            continue;
        }
        perror("read");
        exit(1);
    }

    close(fd);
    data[len] = '\0';
    return (BenchFile){ .data = data, .len = len };
}

static int bench_next_json_object(
    const char *buf,
    size_t len,
    size_t *pos,
    BenchJsonSpan *out)
{
    int depth = 0;
    int in_str = 0;
    int esc = 0;
    size_t start = 0;

    for (size_t i = *pos; i < len; i++) {
        unsigned char c = (unsigned char)buf[i];

        if (in_str) {
            if (esc) {
                esc = 0;
            } else if (c == '\\') {
                esc = 1;
            } else if (c == '"') {
                in_str = 0;
            }
            continue;
        }

        if (c == '"') {
            in_str = 1;
            continue;
        }

        if (c == '{') {
            if (depth == 0) {
                start = i;
            }
            depth++;
            continue;
        }

        if (c == '}' && depth > 0) {
            depth--;
            if (depth == 0) {
                out->ptr = buf + start;
                out->len = i - start + 1;
                *pos = i + 1;
                return 1;
            }
        }
    }

    return 0;
}

static size_t bench_count_json_objects(const char *buf, size_t len) {
    size_t pos = 0;
    size_t count = 0;
    BenchJsonSpan span;

    while (bench_next_json_object(buf, len, &pos, &span)) {
        count++;
    }

    return count;
}

static long bench_arg_long(char **argv, int argc, int idx, long fallback) {
    if (idx >= argc || !argv[idx] || !*argv[idx]) {
        return fallback;
    }

    char *end = NULL;
    long v = strtol(argv[idx], &end, 10);
    return (end && *end == '\0' && v > 0) ? v : fallback;
}

static long bench_arg_long_min(
    char **argv,
    int argc,
    int idx,
    long fallback,
    long min_value)
{
    if (idx >= argc || !argv[idx] || !*argv[idx]) {
        return fallback;
    }

    char *end = NULL;
    long v = strtol(argv[idx], &end, 10);
    return (end && *end == '\0' && v >= min_value) ? v : fallback;
}

static double bench_ns_per_op(uint64_t elapsed_ns, uint64_t ops) {
    return ops ? (double)elapsed_ns / (double)ops : 0.0;
}

#endif
