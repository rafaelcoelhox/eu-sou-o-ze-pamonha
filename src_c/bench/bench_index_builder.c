#define _GNU_SOURCE
#define RINHA_BUILD_IVF_NO_MAIN
#include "../build_ivf.c"

#include "bench_common.h"

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <references.json.gz> [leaf=128] [out.ivf|-]\n", argv[0]);
        return 1;
    }

    int leaf = (int)bench_arg_long(argv, argc, 2, DEFAULT_LEAF_SIZE);
    const char *out = argc >= 4 ? argv[3] : "-";
    if (leaf < LANES || leaf > 1024) leaf = DEFAULT_LEAF_SIZE;

    uint64_t t0 = bench_now_ns();
    load_references(argv[1]);
    uint64_t t_load = bench_now_ns();

    int wrote = strcmp(out, "-") != 0;
    if (wrote) {
        write_index(out, leaf);
    }
    uint64_t t_write = bench_now_ns();

    printf(
        "references=%d leaf=%d load_ms=%.3f write_ms=%.3f wrote=%s\n",
        g_n,
        leaf,
        (double)(t_load - t0) / 1000000.0,
        (double)(t_write - t_load) / 1000000.0,
        wrote ? out : "no"
    );

    free(g_qvecs);
    free(g_lbls);
    free(g_nodes);
    free(g_block_vecs);
    free(g_block_lbls);
    return 0;
}
