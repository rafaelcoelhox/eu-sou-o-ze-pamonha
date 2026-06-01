#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#include <float.h>
#include <unistd.h>
#include <zlib.h>

/*
 * build_ivf  -> constrói o índice "DFKNN001" (KD-tree particionado), o mesmo
 * formato consumido por api.c::load_index. Porta direta de
 * detecta-fraude/src/index.rs (write_kd_pair_to / build_tree).
 *
 * O nome do binário continua "build_ivf" por compatibilidade com Makefile,
 * Dockerfile e benches, mas o índice gerado já não é IVF/k-means: é a árvore
 * KD particionada por partition_key, com blocos AVX2 pair-interleaved.
 */

#define DIMS          14
#define STORE_DIM     16
#define LANES         8
#define BLOCK_BYTES   (DIMS * LANES * 2)        /* 14*8*2 = 224 bytes        */
#define HEADER_SIZE   64
#define PART_SIZE     76
#define NODE_SIZE     80
#define MCC_TABLE_SIZE 1024
#define DEFAULT_LEAF_SIZE 128
#define SCALE         10000
#define KD_PAIR_VERSION 6

#define LABEL_LEGIT   0
#define LABEL_FRAUD   1

static const char MAGIC[8] = {'D','F','K','N','N','0','0','1'};

typedef struct __attribute__((packed)) {
    char     magic[8];
    uint32_t version;
    uint32_t scale;
    uint32_t dim;
    uint32_t store_dim;
    uint32_t n_points;
    uint32_t part_count;
    uint32_t node_count;
    uint32_t block_count;
    uint32_t mcc_table_offset;
    uint8_t  _pad[20];
} Header;

_Static_assert(sizeof(Header) == HEADER_SIZE, "header size");

/* Quantização ------------------------------------------------------------- */

static inline int16_t quantize(double v) {
    if (v <= -1.0) return -(int16_t)SCALE;
    if (v <= 0.0)  return 0;
    if (v >= 1.0)  return (int16_t)SCALE;
    return (int16_t)round(v * (double)SCALE);   /* metade p/ longe de zero (= Rust f64::round) */
}

/* MCC risk (idêntico a consts.rs) ----------------------------------------- */

static const struct { uint32_t code; double risk; } MCC_RISK[] = {
    {5411, 0.15}, {5812, 0.30}, {5912, 0.20}, {5944, 0.45}, {7801, 0.80},
    {7802, 0.75}, {7995, 0.85}, {4511, 0.35}, {5311, 0.25}, {5999, 0.50},
};
#define MCC_RISK_N (int)(sizeof(MCC_RISK)/sizeof(MCC_RISK[0]))
#define DEFAULT_MCC_RISK 0.5

static void build_mcc_table(int16_t *table) {
    int16_t def = quantize(DEFAULT_MCC_RISK);
    for (int i = 0; i < MCC_TABLE_SIZE; i++) table[i] = def;
    for (int i = 0; i < MCC_RISK_N; i++)
        table[MCC_RISK[i].code % MCC_TABLE_SIZE] = quantize(MCC_RISK[i].risk);
}

/* Gzip JSON stream reader ------------------------------------------------- */

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

static double stream_f64(GzStream *r) {
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
    return neg ? -v : v;
}

/* Reference dataset (quantizado direto para i16) -------------------------- */

static int16_t *g_qvecs = NULL;   /* [n][STORE_DIM]                          */
static uint8_t *g_lbls  = NULL;
static int      g_n     = 0;

static void load_references(const char *path) {
    gzFile gz = gzopen(path, "rb");
    if (!gz) { perror(path); exit(1); }
    gzbuffer(gz, 1 << 20);

    GzStream r = {.gz=gz, .pos=0, .len=0, .eof=0};

    int cap = 3200000;
    g_qvecs = malloc((size_t)cap * STORE_DIM * sizeof(int16_t));
    g_lbls  = malloc((size_t)cap);
    if (!g_qvecs || !g_lbls) { fputs("OOM\n", stderr); exit(1); }

    stream_skip(&r, '[');

    int n = 0;
    for (;;) {
        int c;
        for (;;) { c = stream_getc(&r); if (c=='{') break; if (c==']'||c<0) goto done; }
        if (!stream_skip(&r, '[')) break;

        if (n >= cap) {
            cap = cap * 3 / 2;
            g_qvecs = realloc(g_qvecs, (size_t)cap * STORE_DIM * sizeof(int16_t));
            g_lbls  = realloc(g_lbls, (size_t)cap);
            if (!g_qvecs || !g_lbls) { fputs("OOM\n", stderr); exit(1); }
        }

        int16_t *qp = &g_qvecs[(size_t)n * STORE_DIM];
        for (int d = 0; d < DIMS; d++) {
            while (stream_peek(&r)==',' || stream_peek(&r)==' ') stream_getc(&r);
            qp[d] = quantize(stream_f64(&r));
        }
        for (int d = DIMS; d < STORE_DIM; d++) qp[d] = 0;   /* padding */

        stream_skip(&r, ']');
        stream_skip(&r, ':');
        stream_skip(&r, '"');
        int fc = stream_getc(&r);
        g_lbls[n] = (fc == 'f') ? LABEL_FRAUD : LABEL_LEGIT;
        stream_skip(&r, '}');

        n++;
    }
done:
    gzclose(gz);
    g_n = n;
}

/* partition_key (idêntico a index.rs::partition_key) ---------------------- */

static uint32_t partition_key(const int16_t *v) {
    uint32_t key = 0;
    if (v[5] >= 0)  key |= 1u << 0;
    if (v[9] > 0)   key |= 1u << 1;
    if (v[10] > 0)  key |= 1u << 2;
    if (v[11] > 0)  key |= 1u << 3;
    int16_t mr = v[12];
    if (mr <= 2047) { /* 0 */ }
    else if (mr <= 4095) key |= 1u << 4;
    else if (mr <= 6143) key |= 2u << 4;
    else                 key |= 3u << 4;
    if (v[2] > 4096) key |= 1u << 6;
    if (v[8] > 2048) key |= 1u << 7;
    return key;
}

/* KD-tree builder --------------------------------------------------------- */

typedef struct {
    int32_t left, right, start, len;
    int16_t min[STORE_DIM];
    int16_t max[STORE_DIM];
} BuildNode;

static BuildNode *g_nodes = NULL;
static size_t     g_node_n = 0, g_node_cap = 0;

/* blocos: vetor i16[STORE_DIM] + label por slot                            */
static int16_t  *g_block_vecs = NULL;   /* [slot][STORE_DIM] */
static uint8_t  *g_block_lbls = NULL;
static size_t    g_block_n = 0, g_block_cap = 0;

static size_t node_push(void) {
    if (g_node_n >= g_node_cap) {
        g_node_cap = g_node_cap ? g_node_cap * 2 : 4096;
        g_nodes = realloc(g_nodes, g_node_cap * sizeof(BuildNode));
        if (!g_nodes) { fputs("OOM nodes\n", stderr); exit(1); }
    }
    return g_node_n++;
}

static void block_reserve(size_t extra) {
    if (g_block_n + extra > g_block_cap) {
        while (g_block_n + extra > g_block_cap)
            g_block_cap = g_block_cap ? g_block_cap * 2 : (1 << 16);
        g_block_vecs = realloc(g_block_vecs, g_block_cap * STORE_DIM * sizeof(int16_t));
        g_block_lbls = realloc(g_block_lbls, g_block_cap);
        if (!g_block_vecs || !g_block_lbls) { fputs("OOM blocks\n", stderr); exit(1); }
    }
}

static void bounds(const int *idx, int n, int16_t *lo, int16_t *hi) {
    for (int d = 0; d < STORE_DIM; d++) { lo[d] = INT16_MAX; hi[d] = INT16_MIN; }
    for (int i = 0; i < n; i++) {
        const int16_t *v = &g_qvecs[(size_t)idx[i] * STORE_DIM];
        for (int d = 0; d < STORE_DIM; d++) {
            if (v[d] < lo[d]) lo[d] = v[d];
            if (v[d] > hi[d]) hi[d] = v[d];
        }
    }
}

static int widest_dim(const int16_t *lo, const int16_t *hi) {
    int best = 0; int32_t bw = INT32_MIN;
    for (int d = 0; d < DIMS; d++) {
        int32_t w = (int32_t)hi[d] - (int32_t)lo[d];
        if (w > bw) { bw = w; best = d; }
    }
    return best;
}

static int g_split_dim;
static int cmp_split(const void *a, const void *b) {
    int ia = *(const int *)a, ib = *(const int *)b;
    int16_t va = g_qvecs[(size_t)ia * STORE_DIM + g_split_dim];
    int16_t vb = g_qvecs[(size_t)ib * STORE_DIM + g_split_dim];
    return (va > vb) - (va < vb);
}

/* Constrói recursivamente; retorna índice do nó. */
static size_t build_tree(int *idx, int n, int leaf_size) {
    int16_t lo[STORE_DIM], hi[STORE_DIM];
    bounds(idx, n, lo, hi);

    size_t node_idx = node_push();
    BuildNode *node = &g_nodes[node_idx];
    node->left = -1; node->right = -1; node->start = 0; node->len = n;
    memcpy(node->min, lo, sizeof(lo));
    memcpy(node->max, hi, sizeof(hi));

    if (n <= leaf_size) {
        size_t start_slot = g_block_n;
        block_reserve((size_t)n + LANES);
        for (int i = 0; i < n; i++) {
            memcpy(&g_block_vecs[g_block_n * STORE_DIM],
                   &g_qvecs[(size_t)idx[i] * STORE_DIM], STORE_DIM * sizeof(int16_t));
            g_block_lbls[g_block_n] = g_lbls[idx[i]];
            g_block_n++;
        }
        while (g_block_n % LANES != 0) {
            int16_t *slot = &g_block_vecs[g_block_n * STORE_DIM];
            for (int d = 0; d < STORE_DIM; d++) slot[d] = INT16_MAX;
            g_block_lbls[g_block_n] = LABEL_LEGIT;
            g_block_n++;
        }
        node = &g_nodes[node_idx];   /* node_push pode ter realocado */
        node->start = (int32_t)start_slot;
        node->len = n;
        return node_idx;
    }

    int split = widest_dim(lo, hi);
    g_split_dim = split;
    qsort(idx, n, sizeof(int), cmp_split);
    int mid = n / 2;

    size_t left  = build_tree(idx, mid, leaf_size);
    size_t right = build_tree(idx + mid, n - mid, leaf_size);

    node = &g_nodes[node_idx];
    node->left  = (int32_t)left;
    node->right = (int32_t)right;
    node->start = g_nodes[left].start;
    node->len   = g_nodes[left].len + g_nodes[right].len;
    return node_idx;
}

/* Layout pair-interleaved: índice i16 dentro do bloco ---------------------- */
static inline size_t ivf_pair_offset(int d, int lane) {
    return (size_t)(d / 2) * LANES * 2 + (size_t)lane * 2 + (size_t)(d & 1);
}

/* Escrita do índice ------------------------------------------------------- */

static void put_u32(uint8_t *p, uint32_t v) { memcpy(p, &v, 4); }
static void put_i32(uint8_t *p, int32_t v)  { memcpy(p, &v, 4); }
static void write_qv(uint8_t *dst, const int16_t *v) {
    memcpy(dst, v, STORE_DIM * sizeof(int16_t));
}

typedef struct { uint32_t key; int32_t root; } PartitionRoot;

static void write_index(const char *path, int leaf_size) {
    /* buckets por partition_key */
    int *bucket_idx[256];
    int  bucket_n[256] = {0};
    int  bucket_cap[256] = {0};
    for (int k = 0; k < 256; k++) bucket_idx[k] = NULL;

    for (int i = 0; i < g_n; i++) {
        uint32_t key = partition_key(&g_qvecs[(size_t)i * STORE_DIM]);
        if (bucket_n[key] >= bucket_cap[key]) {
            bucket_cap[key] = bucket_cap[key] ? bucket_cap[key] * 2 : 1024;
            bucket_idx[key] = realloc(bucket_idx[key], (size_t)bucket_cap[key] * sizeof(int));
            if (!bucket_idx[key]) { fputs("OOM bucket\n", stderr); exit(1); }
        }
        bucket_idx[key][bucket_n[key]++] = i;
    }

    PartitionRoot roots[256];
    int part_count = 0;
    for (int k = 0; k < 256; k++) {
        if (bucket_n[k] == 0) continue;
        size_t root = build_tree(bucket_idx[k], bucket_n[k], leaf_size);
        roots[part_count].key = (uint32_t)k;
        roots[part_count].root = (int32_t)root;
        part_count++;
        free(bucket_idx[k]);
    }

    if (g_block_n % LANES != 0) { fputs("block align bug\n", stderr); exit(1); }
    size_t block_count = g_block_n / LANES;

    size_t partitions_off = HEADER_SIZE;
    size_t nodes_off   = partitions_off + (size_t)part_count * PART_SIZE;
    size_t vectors_off = nodes_off + g_node_n * NODE_SIZE;
    size_t labels_off  = vectors_off + block_count * BLOCK_BYTES;
    size_t mcc_off     = labels_off + block_count * LANES;
    size_t total       = mcc_off + (size_t)MCC_TABLE_SIZE * 2;

    uint8_t *out = calloc(total, 1);
    if (!out) { fputs("OOM out\n", stderr); exit(1); }

    Header hdr;
    memset(&hdr, 0, sizeof(hdr));
    memcpy(hdr.magic, MAGIC, 8);
    hdr.version = KD_PAIR_VERSION;
    hdr.scale = SCALE;
    hdr.dim = DIMS;
    hdr.store_dim = STORE_DIM;
    hdr.n_points = (uint32_t)g_n;
    hdr.part_count = (uint32_t)part_count;
    hdr.node_count = (uint32_t)g_node_n;
    hdr.block_count = (uint32_t)block_count;
    hdr.mcc_table_offset = (uint32_t)mcc_off;
    memcpy(out, &hdr, HEADER_SIZE);

    for (int i = 0; i < part_count; i++) {
        size_t off = partitions_off + (size_t)i * PART_SIZE;
        BuildNode *n = &g_nodes[roots[i].root];
        put_u32(out + off,      roots[i].key);
        put_i32(out + off + 4,  roots[i].root);
        put_i32(out + off + 8,  n->len);
        write_qv(out + off + 12, n->min);
        write_qv(out + off + 44, n->max);
    }

    for (size_t i = 0; i < g_node_n; i++) {
        size_t off = nodes_off + i * NODE_SIZE;
        BuildNode *n = &g_nodes[i];
        put_i32(out + off,     n->left);
        put_i32(out + off + 4, n->right);
        int32_t start_block = (n->left < 0) ? (n->start / LANES) : n->start;
        put_i32(out + off + 8,  start_block);
        put_i32(out + off + 12, n->len);
        write_qv(out + off + 16, n->min);
        write_qv(out + off + 48, n->max);
    }

    /* vetores em layout pair-interleaved */
    for (size_t b = 0; b < block_count; b++) {
        size_t block_off = vectors_off + b * BLOCK_BYTES;
        for (int d = 0; d < DIMS; d++) {
            for (int lane = 0; lane < LANES; lane++) {
                size_t slot = b * LANES + lane;
                int16_t val = g_block_vecs[slot * STORE_DIM + d];
                size_t dst = block_off + ivf_pair_offset(d, lane) * 2;
                memcpy(out + dst, &val, 2);
            }
        }
    }

    for (size_t b = 0; b < block_count; b++) {
        size_t base = labels_off + b * LANES;
        for (int lane = 0; lane < LANES; lane++)
            out[base + lane] = g_block_lbls[b * LANES + lane];
    }

    int16_t mcc_table[MCC_TABLE_SIZE];
    build_mcc_table(mcc_table);
    for (int i = 0; i < MCC_TABLE_SIZE; i++)
        memcpy(out + mcc_off + (size_t)i * 2, &mcc_table[i], 2);

    FILE *f = fopen(path, "wb");
    if (!f) { perror(path); exit(1); }
    if (fwrite(out, 1, total, f) != total) { perror("write index"); exit(1); }
    fclose(f);
    free(out);

    fprintf(stderr,
        "[builder] %d pontos, %d partições, %zu nós, %zu blocos -> %s (%.1f MB)\n",
        g_n, part_count, g_node_n, block_count, path, total / 1e6);
}

static int leaf_size_from_env(void) {
    const char *e = getenv("KD_LEAF_SIZE");
    if (!e || !*e) return DEFAULT_LEAF_SIZE;
    int v = atoi(e);
    if (v >= LANES && v <= 1024) return v;
    return DEFAULT_LEAF_SIZE;
}

#ifndef RINHA_BUILD_IVF_NO_MAIN

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <references.json.gz> <output.ivf> [ignored]\n", argv[0]);
        return 1;
    }
    /* 3º argumento posicional (antes N_CLUSTERS do IVF) é ignorado; o tamanho
     * da folha vem de KD_LEAF_SIZE. Mantido para não quebrar o Dockerfile. */
    int leaf_size = leaf_size_from_env();

    load_references(argv[1]);
    if (g_n == 0) { fputs("no references\n", stderr); return 1; }

    write_index(argv[2], leaf_size);

    free(g_qvecs); free(g_lbls); free(g_nodes);
    free(g_block_vecs); free(g_block_lbls);
    return 0;
}
#endif
