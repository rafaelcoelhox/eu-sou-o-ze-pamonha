#define _GNU_SOURCE
#define RINHA_API_NO_MAIN
#include "../api.c"

#include <limits.h>
#include "bench_common.h"

static volatile double bench_json_sink_f;
static volatile uint32_t bench_json_sink_u;

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <payloads.json> [iterations] [vectorize=0]\n", argv[0]);
        return 1;
    }

    long iterations = bench_arg_long(argv, argc, 2, 1000);
    int do_vectorize = argc >= 4 && atoi(argv[3]) != 0;

    BenchFile file = bench_read_file(argv[1]);
    size_t payloads = bench_count_json_objects(file.data, file.len);
    if (payloads == 0) {
        fputs("no JSON objects found\n", stderr);
        return 1;
    }

    uint64_t start = bench_now_ns();
    uint64_t ok = 0;

    for (long it = 0; it < iterations; it++) {
        size_t pos = 0;
        BenchJsonSpan span;

        while (bench_next_json_object(file.data, file.len, &pos, &span)) {
            if (span.len > (size_t)INT_MAX) {
                continue;
            }

            Payload px;
            if (!parse_json(span.ptr, (int)span.len, &px)) {
                continue;
            }

            if (do_vectorize) {
                float v[DIMS];
                vectorize(&px, v);
                bench_json_sink_f += (double)v[0] + (double)v[12];
            } else {
                bench_json_sink_f += (double)px.amount;
            }

            bench_json_sink_u += px.mcc + px.tx_count_24h + px.installments;
            ok++;
        }
    }

    uint64_t elapsed = bench_now_ns() - start;
    uint64_t expected = (uint64_t)payloads * (uint64_t)iterations;

    printf(
        "payloads=%zu iterations=%ld mode=%s ok=%llu/%llu elapsed_ms=%.3f ns_per_payload=%.2f\n",
        payloads,
        iterations,
        do_vectorize ? "parse+vectorize" : "parse",
        (unsigned long long)ok,
        (unsigned long long)expected,
        (double)elapsed / 1000000.0,
        bench_ns_per_op(elapsed, ok)
    );

    free(file.data);
    return ok == expected ? 0 : 1;
}
