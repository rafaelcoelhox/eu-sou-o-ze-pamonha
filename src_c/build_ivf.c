#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#include <float.h>
#include <pthread.h>
#include <unistd.h>
#include <zlib.h>
#include <immintrin.h>

#define DIMS          14
#define DEFAULT_K     4096
#define KMEANS_ITERS  50
#define INIT_SAMPLE   50000
#define BLOCK_VECS    16      
#define QUANT_SCALE   10000.0f 
#define MAX_THREADS   16

static const char MAGIC[8] = {'C','I','V','F','2',0,0,0};

typedef struct __attribute__((packed)) {
    char     magic[8];
    uint32_t n, k, d, total_blocks, padded_n;
} IndexHeader;

static uint64_t g_rng;

static uint64_t rng_next(void) {
    g_rng = g_rng * 6364136223846793005ULL + 1442695040888963407ULL;
    return g_rng;
}
static size_t rng_usize(size_t n) { return (size_t)((rng_next() >> 33) % n); }
static double rng_f64(void)       { return (double)(rng_next() >> 11) / (double)(1ULL << 53); }

#define GZ_BUF   (128 * 1024)
#define GZ_SLIDE (32 * 1024)

typedef struct {
    gzFile gz;
    unsigned char buf[GZ_BUF + 256];
    int pos, len, eof;
} GzStream;

static void stream_refill(GzStream *r) {
    if (r->eof) return;
    if (r->pos > GZ_SLIDE) {
        int keep = r->len - r->pos;
        if (keep > 0) memmove(r->buf, r->buf + r->pos, keep);
        r->len = keep; r->pos = 0;
    }
    int n = gzread(r->gz, r->buf + r->len, GZ_BUF - r->len);
    if (n <= 0) r->eof = 1; else r->len += n;
}

static void stream_ensure(GzStream *r, int need) {
    while (r->len - r->pos < need && !r->eof) stream_refill(r);
}

static int stream_peek(GzStream *r) {
    if (r->pos >= r->len) stream_refill(r);
    return r->pos < r->len ? r->buf[r->pos] : -1;
}

static int stream_getc(GzStream *r) {
    if (r->pos >= r->len) stream_refill(r);
    return r->pos < r->len ? (int)r->buf[r->pos++] : -1;
}

static int stream_skip(GzStream *r, int c) {
    for (;;) {
        if (r->pos >= r->len) { stream_refill(r); if (r->eof) return 0; }
        while (r->pos < r->len) { if (r->buf[r->pos++] == c) return 1; }
    }
}

static float stream_f32(GzStream *r) {
    stream_ensure(r, 64);
    const unsigned char *s = r->buf + r->pos;
    int len = r->len - r->pos, i = 0, neg = 0;
    if (i < len && s[i] == '-') { neg = 1; i++; }
    double v = 0;
    while (i < len && s[i] >= '0' && s[i] <= '9') { v = v*10 + (s[i]-'0'); i++; }
    if (i < len && s[i] == '.') {
        i++; double f = 0.1;
        while (i < len && s[i] >= '0' && s[i] <= '9') { v += (s[i]-'0')*f; f *= 0.1; i++; }
    }
    if (i < len && (s[i]|32) == 'e') {
        i++; int es = 1;
        if (i < len && s[i] == '-') { es = -1; i++; }
        else if (i < len && s[i] == '+') i++;
        int e = 0;
        while (i < len && s[i] >= '0' && s[i] <= '9') { e = e*10 + (s[i]-'0'); i++; }
        v *= pow(10.0, es*e);
    }
    r->pos += i;
    return (float)(neg ? -v : v);
}

static float   *g_vecs = NULL;  
static uint8_t *g_lbls = NULL;  
static int      g_n    = 0;

static void load_references(const char *path) {
    gzFile gz = gzopen(path, "rb");
    if (!gz) { perror(path); exit(1); }
    gzbuffer(gz, 1 << 20);

    GzStream r = {.gz=gz, .pos=0, .len=0, .eof=0};

    int cap = 3200000;
    g_vecs = malloc((size_t)cap * DIMS * sizeof(float));
    g_lbls = malloc((size_t)cap);
    if (!g_vecs || !g_lbls) { fputs("OOM\n", stderr); exit(1); }

    stream_skip(&r, '[');

    int n = 0;
    for (;;) {
        int c;
        for (;;) { c = stream_getc(&r); if (c=='{') break; if (c==']'||c<0) goto done; }
        if (!stream_skip(&r, '[')) break;

        if (n >= cap) {
            cap = cap * 3 / 2;
            g_vecs = realloc(g_vecs, (size_t)cap * DIMS * sizeof(float));
            g_lbls = realloc(g_lbls, (size_t)cap);
            if (!g_vecs || !g_lbls) { fputs("OOM\n", stderr); exit(1); }
        }

        float *vp = &g_vecs[(size_t)n * DIMS];
        for (int d = 0; d < DIMS; d++) {
            while (stream_peek(&r)==',' || stream_peek(&r)==' ') stream_getc(&r);
            vp[d] = stream_f32(&r);
        }
        stream_skip(&r, ']');
        stream_skip(&r, ':');
        stream_skip(&r, '"');
        int fc = stream_getc(&r);
        g_lbls[n] = (fc == 'f') ? 1 : 0;
        stream_skip(&r, '}');

        n++;
    }
done:
    gzclose(gz);
    g_n = n;
}

static inline float sq_dist(const float *a, const float *b) {
    float d = 0;
    for (int i = 0; i < DIMS; i++) { float x = a[i]-b[i]; d += x*x; }
    return d;
}

static uint16_t nearest_centroid(const float *v, const float *ct, int k) {
    float dists[4096];
    int ci;

    { const float *cp = ct; __m256 qd = _mm256_set1_ps(v[0]);
      for (ci=0; ci+16<=k; ci+=16) {
        __m256 d0=_mm256_sub_ps(_mm256_loadu_ps(cp+ci),   qd);
        __m256 d1=_mm256_sub_ps(_mm256_loadu_ps(cp+ci+8), qd);
        _mm256_storeu_ps(dists+ci,   _mm256_mul_ps(d0,d0));
        _mm256_storeu_ps(dists+ci+8, _mm256_mul_ps(d1,d1));
      }
      for (; ci<k; ci++) { float d=cp[ci]-v[0]; dists[ci]=d*d; }
    }
    for (int d=1; d<DIMS; d++) {
        const float *cp = ct+d*k; __m256 qd = _mm256_set1_ps(v[d]);
        for (ci=0; ci+16<=k; ci+=16) {
          __m256 a0=_mm256_loadu_ps(dists+ci),   a1=_mm256_loadu_ps(dists+ci+8);
          __m256 c0=_mm256_loadu_ps(cp+ci),       c1=_mm256_loadu_ps(cp+ci+8);
          _mm256_storeu_ps(dists+ci,   _mm256_fmadd_ps(_mm256_sub_ps(c0,qd),_mm256_sub_ps(c0,qd),a0));
          _mm256_storeu_ps(dists+ci+8, _mm256_fmadd_ps(_mm256_sub_ps(c1,qd),_mm256_sub_ps(c1,qd),a1));
        }
        for (; ci<k; ci++) { float dd=cp[ci]-v[d]; dists[ci]+=dd*dd; }
    }
    uint16_t best=0; float bv=dists[0];
    for (ci=1; ci<k; ci++) if (dists[ci]<bv) { bv=dists[ci]; best=(uint16_t)ci; }
    return best;
}

static void kmeanspp_init(float *centroids, int k) {
    int n = g_n;
    int ss = n < INIT_SAMPLE ? n : INIT_SAMPLE;
    if (ss <= 0) exit(1);
    int *sample = malloc((size_t)ss * sizeof(int));
    for (int i = 0; i < ss; i++) sample[i] = (int)rng_usize((size_t)n);

    int first = sample[rng_usize((size_t)ss)];
    memcpy(centroids, &g_vecs[(size_t)first*DIMS], DIMS*sizeof(float));

    float *min_d2 = malloc((size_t)ss * sizeof(float));
    for (int i = 0; i < ss; i++) min_d2[i] = FLT_MAX;

    for (int ci = 1; ci < k; ci++) {
        const float *last = centroids + (ci-1)*DIMS;
        for (int i = 0; i < ss; i++) {
            float d = sq_dist(&g_vecs[(size_t)sample[i]*DIMS], last);
            if (d < min_d2[i]) min_d2[i] = d;
        }
        double total = 0;
        for (int i = 0; i < ss; i++) total += min_d2[i];
        double r = rng_f64() * total, cum = 0;
        int chosen = ss - 1;
        for (int i = 0; i < ss; i++) { cum += min_d2[i]; if (cum >= r) { chosen=i; break; } }
        memcpy(centroids + ci*DIMS, &g_vecs[(size_t)sample[chosen]*DIMS], DIMS*sizeof(float));
    }
    free(sample); free(min_d2);
}

static void centroid_transpose(const float *c, float *ct, int k) {
    for (int d = 0; d < DIMS; d++)
        for (int i = 0; i < k; i++)
            ct[d*k+i] = c[i*DIMS+d];
}

typedef struct {
    const float *ct;
    uint16_t *asgn;
    int k, start, end;
    size_t changed;
} WorkSlice;

static void *assign_slice(void *arg) {
    WorkSlice *a = arg;
    a->changed = 0;
    for (int i = a->start; i < a->end; i++) {
        uint16_t best = nearest_centroid(&g_vecs[(size_t)i*DIMS], a->ct, a->k);
        if (best != a->asgn[i]) { a->asgn[i] = best; a->changed++; }
    }
    return NULL;
}

static size_t parallel_assign(const float *ct, int k, uint16_t *asgn) {
    int nt = (int)sysconf(_SC_NPROCESSORS_ONLN);
    if (nt < 1) nt = 1;
    if (nt > MAX_THREADS) nt = MAX_THREADS;

    pthread_t thr[MAX_THREADS];
    WorkSlice arg[MAX_THREADS];
    int chunk = (g_n + nt - 1) / nt;

    for (int t = 0; t < nt; t++) {
        arg[t] = (WorkSlice){ .ct=ct, .asgn=asgn, .k=k,
                              .start=t*chunk,
                              .end=(t+1)*chunk < g_n ? (t+1)*chunk : g_n };
        pthread_create(&thr[t], NULL, assign_slice, &arg[t]);
    }
    size_t changed = 0;
    for (int t = 0; t < nt; t++) { pthread_join(thr[t], NULL); changed += arg[t].changed; }
    return changed;
}

static void recompute_centroids(float *centroids, const uint16_t *asgn, int k) {
    double *sums  = calloc((size_t)k * DIMS, sizeof(double));
    uint32_t *cnt = calloc((size_t)k, sizeof(uint32_t));
    for (int i = 0; i < g_n; i++) {
        int ci = asgn[i]; cnt[ci]++;
        const float *vp = &g_vecs[(size_t)i*DIMS];
        double *sp = &sums[(size_t)ci*DIMS];
        for (int d = 0; d < DIMS; d++) sp[d] += vp[d];
    }
    for (int ci = 0; ci < k; ci++) {
        if (!cnt[ci]) continue;
        double inv = 1.0 / cnt[ci];
        float *cp = centroids + ci*DIMS;
        double *sp = &sums[(size_t)ci*DIMS];
        for (int d = 0; d < DIMS; d++) cp[d] = (float)(sp[d] * inv);
    }
    free(sums); free(cnt);
}


static void write_ivf(const char *path, const float *centroids, int k, const uint16_t *asgn) {
    int n = g_n;

    int **cvecs = calloc((size_t)k, sizeof(int*));
    int  *csz   = calloc((size_t)k, sizeof(int));
    int  *ccap  = calloc((size_t)k, sizeof(int));
    for (int i = 0; i < n; i++) {
        int ci = asgn[i];
        if (csz[ci] >= ccap[ci]) {
            ccap[ci] = ccap[ci] ? ccap[ci]*2 : 8;
            cvecs[ci] = realloc(cvecs[ci], (size_t)ccap[ci]*sizeof(int));
        }
        cvecs[ci][csz[ci]++] = i;
    }

    uint32_t *boff = malloc((size_t)(k+1)*sizeof(uint32_t));
    uint32_t total_blocks = 0;
    for (int ci = 0; ci < k; ci++) {
        boff[ci] = total_blocks;
        total_blocks += (uint32_t)((csz[ci] + BLOCK_VECS - 1) / BLOCK_VECS);
    }
    boff[k] = total_blocks;
    uint32_t padded_n = total_blocks * BLOCK_VECS;

    uint8_t  *labels = calloc(padded_n, 1);
    int16_t  *blocks = calloc((size_t)total_blocks * DIMS * BLOCK_VECS, sizeof(int16_t));

    for (int ci = 0; ci < k; ci++) {
        uint32_t bs = boff[ci];
        int sz = csz[ci], *vs = cvecs[ci];
        uint32_t nb = boff[ci+1] - bs;

        for (uint32_t bk = 0; bk < nb; bk++) {
            size_t bb = (size_t)(bs+bk) * DIMS * BLOCK_VECS;
            size_t lb = (size_t)(bs+bk) * BLOCK_VECS;
            for (int slot = 0; slot < BLOCK_VECS; slot++) {
                int vi = (int)bk*BLOCK_VECS + slot;
                if (vi < sz) {
                    const float *vp = &g_vecs[(size_t)vs[vi]*DIMS];
                    for (int d = 0; d < DIMS; d++) {
                        float q = roundf(vp[d] * QUANT_SCALE);
                        if (q < -32767.f) q = -32767.f;
                        if (q >  32767.f) q =  32767.f;
                        blocks[bb + d*BLOCK_VECS + slot] = (int16_t)q;
                    }
                    labels[lb+slot] = g_lbls[vs[vi]];
                } else {
                    for (int d = 0; d < DIMS; d++)
                        blocks[bb + d*BLOCK_VECS + slot] = INT16_MAX;
                    labels[lb+slot] = 0;
                }
            }
        }
    }

    float *ct = malloc((size_t)DIMS * k * sizeof(float));
    for (int ci = 0; ci < k; ci++)
        for (int d = 0; d < DIMS; d++)
            ct[d*k+ci] = centroids[ci*DIMS+d];

    FILE *f = fopen(path, "wb");
    if (!f) { perror(path); exit(1); }

    IndexHeader hdr;
    memcpy(hdr.magic, MAGIC, 8);
    hdr.n = (uint32_t)n; hdr.k = (uint32_t)k;
    hdr.d = DIMS; hdr.total_blocks = total_blocks; hdr.padded_n = padded_n;

    fwrite(&hdr,    sizeof(hdr),     1,              f);
    fwrite(ct,      sizeof(float),   (size_t)DIMS*k, f);
    fwrite(boff,    sizeof(uint32_t),(size_t)(k+1),  f);
    fwrite(labels,  1,                padded_n,       f);
    fwrite(blocks,  sizeof(int16_t), (size_t)total_blocks*DIMS*BLOCK_VECS, f);
    fclose(f);

    free(ct); free(boff); free(labels); free(blocks);
    for (int ci = 0; ci < k; ci++) free(cvecs[ci]);
    free(cvecs); free(csz); free(ccap);
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <references.json.gz> <output.ivf> [N_CLUSTERS]\n", argv[0]);
        return 1;
    }
    int k = (argc >= 4) ? atoi(argv[3]) : DEFAULT_K;

    g_rng = 0xf3a8c01d4e729b56ULL;

    load_references(argv[1]);

    float *centroids = malloc((size_t)k * DIMS * sizeof(float));
    float *ct        = malloc((size_t)DIMS * k * sizeof(float));
    uint16_t *asgn   = calloc((size_t)g_n, sizeof(uint16_t));

    kmeanspp_init(centroids, k);
    centroid_transpose(centroids, ct, k);

    for (int iter = 0; iter < KMEANS_ITERS; iter++) {
        size_t changed = parallel_assign(ct, k, asgn);
        recompute_centroids(centroids, asgn, k);
        centroid_transpose(centroids, ct, k);
        if (changed * 1000 < (size_t)g_n) break;
    }

    write_ivf(argv[2], centroids, k, asgn);

    free(centroids); free(ct); free(asgn);
    free(g_vecs); free(g_lbls);
    return 0;
}
