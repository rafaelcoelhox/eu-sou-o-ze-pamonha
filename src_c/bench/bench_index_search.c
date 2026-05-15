#define _GNU_SOURCE
#define RINHA_API_NO_MAIN
#include "../api.c"

#include <limits.h>
#include "bench_common.h"

typedef struct {
    float v[DIMS];
} BenchQuery;

static volatile uint64_t bench_search_sink;

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <index.ivf> <payloads.json> [iterations]\n", argv[0]);
        return 1;
    }

    long iterations = bench_arg_long(argv, argc, 3, 1000);

    load_index(argv[1]);

    BenchFile file = bench_read_file(argv[2]);
    size_t capacity = bench_count_json_objects(file.data, file.len);
    if (capacity == 0) {
        fputs("no JSON objects found\n", stderr);
        return 1;
    }

    BenchQuery *queries = malloc(capacity * sizeof(*queries));
    if (!queries) {
        fputs("OOM\n", stderr);
        return 1;
    }

    size_t pos = 0;
    size_t qn = 0;
    BenchJsonSpan span;

    while (bench_next_json_object(file.data, file.len, &pos, &span)) {
        if (span.len > (size_t)INT_MAX) {
            continue;
        }

        Payload px;
        if (!parse_json(span.ptr, (int)span.len, &px)) {
            continue;
        }

        vectorize(&px, queries[qn].v);
        qn++;
    }

    if (qn == 0) {
        fputs("no parseable payloads found\n", stderr);
        return 1;
    }

    for (size_t i = 0; i < qn; i++) {
        bench_search_sink += knn5_search(queries[i].v);
    }

    uint64_t start = bench_now_ns();
    for (long it = 0; it < iterations; it++) {
        for (size_t i = 0; i < qn; i++) {
            bench_search_sink += knn5_search(queries[i].v);
        }
    }
    uint64_t elapsed = bench_now_ns() - start;
    uint64_t ops = (uint64_t)iterations * (uint64_t)qn;

    printf(
        "queries=%zu iterations=%ld ops=%llu elapsed_ms=%.3f ns_per_query=%.2f sink=%llu\n",
        qn,
        iterations,
        (unsigned long long)ops,
        (double)elapsed / 1000000.0,
        bench_ns_per_op(elapsed, ops),
        (unsigned long long)bench_search_sink
    );

    free(queries);
    free(file.data);
    return 0;
}
