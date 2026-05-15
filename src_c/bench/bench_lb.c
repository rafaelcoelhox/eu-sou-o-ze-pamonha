#define _GNU_SOURCE
#define RINHA_LB_NO_MAIN
#include "../lb.c"

#include "bench_common.h"

static volatile uint64_t bench_lb_sink;

int main(int argc, char **argv) {
    long iterations = bench_arg_long(argv, argc, 1, 100000000);
    int configured_upstreams = (int)bench_arg_long(argv, argc, 2, 2);

    if (configured_upstreams <= 0 || configured_upstreams > MAX_UPSTREAMS) {
        fprintf(stderr, "invalid upstream_count: %d\n", configured_upstreams);
        return 1;
    }

    upstream_count = configured_upstreams;
    rr_next = 0;

    uint64_t start = bench_now_ns();
    for (long i = 0; i < iterations; i++) {
        bench_lb_sink += (uint64_t)next_upstream_idx();
    }
    uint64_t elapsed = bench_now_ns() - start;

    printf(
        "iterations=%ld upstreams=%d elapsed_ms=%.3f ns_per_pick=%.2f sink=%llu\n",
        iterations,
        configured_upstreams,
        (double)elapsed / 1000000.0,
        bench_ns_per_op(elapsed, (uint64_t)iterations),
        (unsigned long long)bench_lb_sink
    );

    return 0;
}
