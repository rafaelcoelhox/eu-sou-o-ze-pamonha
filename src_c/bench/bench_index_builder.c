#define _GNU_SOURCE
#define RINHA_BUILD_IVF_NO_MAIN
#include "../build_ivf.c"

#include "bench_common.h"

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <references.json.gz> [k=4096] [iters=50] [out.ivf|-]\n", argv[0]);
        return 1;
    }

    int k = (int)bench_arg_long(argv, argc, 2, DEFAULT_K);
    int iters = (int)bench_arg_long_min(argv, argc, 3, KMEANS_ITERS, 0);
    const char *out = argc >= 5 ? argv[4] : "-";

    if (k <= 0 || k > 65535) {
        fprintf(stderr, "invalid k: %d\n", k);
        return 1;
    }

    g_rng = 0xf3a8c01d4e729b56ULL;

    uint64_t t0 = bench_now_ns();
    load_references(argv[1]);
    uint64_t t_load = bench_now_ns();

    float *centroids = malloc((size_t)k * DIMS * sizeof(float));
    float *ct = malloc((size_t)DIMS * k * sizeof(float));
    uint16_t *asgn = calloc((size_t)g_n, sizeof(uint16_t));
    if (!centroids || !ct || !asgn) {
        fputs("OOM\n", stderr);
        return 1;
    }

    kmeanspp_init(centroids, k);
    centroid_transpose(centroids, ct, k);
    uint64_t t_init = bench_now_ns();

    size_t changed = 0;
    for (int iter = 0; iter < iters; iter++) {
        changed = parallel_assign(ct, k, asgn);
        recompute_centroids(centroids, asgn, k);
        centroid_transpose(centroids, ct, k);
    }
    uint64_t t_kmeans = bench_now_ns();

    int wrote = strcmp(out, "-") != 0;
    if (wrote) {
        write_ivf(out, centroids, k, asgn);
    }
    uint64_t t_write = bench_now_ns();

    printf(
        "references=%d k=%d iters=%d last_changed=%zu load_ms=%.3f init_ms=%.3f kmeans_ms=%.3f write_ms=%.3f wrote=%s\n",
        g_n,
        k,
        iters,
        changed,
        (double)(t_load - t0) / 1000000.0,
        (double)(t_init - t_load) / 1000000.0,
        (double)(t_kmeans - t_init) / 1000000.0,
        (double)(t_write - t_kmeans) / 1000000.0,
        wrote ? out : "no"
    );

    free(centroids);
    free(ct);
    free(asgn);
    free(g_vecs);
    free(g_lbls);
    return 0;
}
