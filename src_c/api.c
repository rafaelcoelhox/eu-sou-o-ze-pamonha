#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <signal.h>
#include <immintrin.h>

/*
 * canjica / pamonha -> worker HTTP de detecção de fraude.
 *
 * Porta direta da solução Rust detecta-fraude: índice KD-tree particionado
 * (formato "DFKNN001" v6), vetorização i16 (SCALE=10000, STORE_DIM=16) e
 * busca KNN (K=5) com early-exit e probing de partições por lower-bound.
 *
 * O transporte (epoll edge-triggered + intake de FDs via SCM_RIGHTS no socket
 * de controle SEQPACKET) é o equivalente em C do servidor da referência e é
 * compartilhado com o LB carro-da-pamonha.
 */

#define DIMS         14
#define STORE_DIM    16
#define LANES         8
#define K             5
#define IVF_PAIRS    (DIMS / 2)          /* 7 pares por bloco                 */
#define SCALE        10000
#define BLOCK_BYTES  (DIMS * LANES * 2)  /* 224 bytes por bloco               */
#define HEADER_SIZE  64
#define PART_SIZE    76
#define NODE_SIZE    80
#define MCC_TABLE_SIZE 1024
#define KD_PAIR_VERSION 6

#define LABEL_LEGIT  0
#define LABEL_FRAUD  1

/* early-exit: best[K-1] <= (SCALE*140/1000)^2 = 1400^2 */
#define EARLY_DISTANCE_MILLI 140
#define EARLY_DISTANCE_LIMIT \
    ((int64_t)((int64_t)SCALE * EARLY_DISTANCE_MILLI / 1000) * \
              ((int64_t)SCALE * EARLY_DISTANCE_MILLI / 1000))

/* normalização (consts.rs) */
#define MAX_AMOUNT             10000.0
#define MAX_INSTALLMENTS          12.0
#define AMOUNT_VS_AVG_RATIO       10.0
#define MAX_MINUTES             1440.0
#define MAX_KM                  1000.0
#define MAX_TX_COUNT_24H          20.0
#define MAX_MERCHANT_AVG_AMOUNT 10000.0
#define DEFAULT_MCC_RISK           0.5

#define MAX_CONNS   512
#define RX_BUF_SZ  16384
#define MAX_IOVECS   16
#define MAX_REQ_HEAD 4096
#define MAX_BODY     4096

/* Respostas HTTP (idênticas à referência: sem Content-Type) --------------- */

#define R_HDR(N) "HTTP/1.1 200 OK\r\nContent-Length: " N "\r\n\r\n"
static const char *RESP_FRAUD[6] = {
    R_HDR("35") "{\"approved\":true,\"fraud_score\":0.0}",
    R_HDR("35") "{\"approved\":true,\"fraud_score\":0.2}",
    R_HDR("35") "{\"approved\":true,\"fraud_score\":0.4}",
    R_HDR("36") "{\"approved\":false,\"fraud_score\":0.6}",
    R_HDR("36") "{\"approved\":false,\"fraud_score\":0.8}",
    R_HDR("36") "{\"approved\":false,\"fraud_score\":1.0}",
};
static size_t RESP_FRAUD_LEN[6];
static const char RESP_READY[] = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
/* fallback (rota desconhecida / parse falho) = aprovado, score 0.0 */
#define RESP_FALLBACK_IDX 0

/* Quantização ------------------------------------------------------------- */

static inline int16_t quantize(double v) {
    if (v <= -1.0) return -(int16_t)SCALE;
    if (v <= 0.0)  return 0;
    if (v >= 1.0)  return (int16_t)SCALE;
    return (int16_t)round(v * (double)SCALE);
}
static inline double clamp01(double v) {
    if (v < 0.0) return 0.0;
    if (v > 1.0) return 1.0;
    return v;
}
static inline int16_t quantize_clamped(double v) { return quantize(clamp01(v)); }

static double mcc_risk_lookup(const char *mcc, int len) {
    if (len != 4) return DEFAULT_MCC_RISK;
    uint32_t code = 0;
    for (int i = 0; i < 4; i++) {
        char c = mcc[i];
        if (c < '0' || c > '9') return DEFAULT_MCC_RISK;
        code = code * 10 + (uint32_t)(c - '0');
    }
    switch (code) {
        case 5411: return 0.15;
        case 5812: return 0.30;
        case 5912: return 0.20;
        case 5944: return 0.45;
        case 7801: return 0.80;
        case 7802: return 0.75;
        case 7995: return 0.85;
        case 4511: return 0.35;
        case 5311: return 0.25;
        case 5999: return 0.50;
        default:   return DEFAULT_MCC_RISK;
    }
}

/* Índice DFKNN001 mapeado -------------------------------------------------- */

typedef struct __attribute__((packed)) {
    char     magic[8];
    uint32_t version, scale, dim, store_dim, n_points;
    uint32_t part_count, node_count, block_count, mcc_table_offset;
    uint8_t  _pad[20];
} Header;

static const uint8_t *g_parts;
static const uint8_t *g_nodes;
static const int16_t *g_vectors;
static const uint8_t *g_labels;
static uint32_t       g_part_count, g_node_count, g_block_count, g_n_points;
static int32_t        g_part_by_key[256];

static inline int32_t rd_i32(const uint8_t *p) { int32_t v; __builtin_memcpy(&v, p, 4); return v; }
static inline uint32_t rd_u32(const uint8_t *p) { uint32_t v; __builtin_memcpy(&v, p, 4); return v; }

static void load_index(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) { perror(path); exit(1); }
    struct stat st;
    if (fstat(fd, &st) < 0) { perror("fstat"); exit(1); }
    size_t sz = (size_t)st.st_size;

    uint8_t *base = mmap(NULL, sz, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
    if (base == MAP_FAILED) { perror("mmap index"); exit(1); }
    madvise(base, sz, MADV_HUGEPAGE);

    size_t rem = sz; uint8_t *wp = base;
    while (rem > 0) {
        ssize_t n = read(fd, wp, rem < (1u << 20) ? rem : (1u << 20));
        if (n <= 0) { perror("read index"); exit(1); }
        wp += n; rem -= (size_t)n;
    }
    close(fd);
    mlock(base, sz);

    Header hdr;
    __builtin_memcpy(&hdr, base, sizeof(hdr));
    if (memcmp(hdr.magic, "DFKNN001", 8) != 0 || hdr.version != KD_PAIR_VERSION) {
        fputs("Invalid index magic/version\n", stderr); exit(1);
    }
    if (hdr.scale != SCALE || hdr.dim != DIMS || hdr.store_dim != STORE_DIM) {
        fputs("Index dim/scale mismatch\n", stderr); exit(1);
    }

    g_part_count = hdr.part_count;
    g_node_count = hdr.node_count;
    g_block_count = hdr.block_count;
    g_n_points = hdr.n_points;

    size_t parts_off = HEADER_SIZE;
    size_t nodes_off = parts_off + (size_t)g_part_count * PART_SIZE;
    size_t vectors_off = nodes_off + (size_t)g_node_count * NODE_SIZE;
    size_t labels_off = vectors_off + (size_t)g_block_count * BLOCK_BYTES;
    size_t mcc_off = labels_off + (size_t)g_block_count * LANES;
    size_t end = mcc_off + (size_t)MCC_TABLE_SIZE * 2;
    if (end != sz || hdr.mcc_table_offset != mcc_off) {
        fputs("Index size mismatch\n", stderr); exit(1);
    }

    g_parts = base + parts_off;
    g_nodes = base + nodes_off;
    g_vectors = (const int16_t *)(base + vectors_off);
    g_labels = base + labels_off;

    for (int i = 0; i < 256; i++) g_part_by_key[i] = -1;
    for (uint32_t i = 0; i < g_part_count; i++) {
        uint32_t key = rd_u32(g_parts + (size_t)i * PART_SIZE);
        if (key < 256) g_part_by_key[key] = (int32_t)i;
    }
}

/* Datas (time.rs) --------------------------------------------------------- */

typedef struct { int64_t epoch_min; uint8_t hour; uint8_t weekday; } Stamp;

static int64_t days_from_civil(int y, unsigned m, unsigned d) {
    y -= (m <= 2);
    int era = (y >= 0 ? y : y - 399) / 400;
    unsigned yoe = (unsigned)(y - era * 400);
    unsigned doy = (153 * (m > 2 ? m - 3 : m + 9) + 2) / 5 + d - 1;
    unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return (int64_t)era * 146097 + (int64_t)doe - 719468;
}

static inline unsigned dig2(const char *b) { return (unsigned)((b[0]-'0')*10 + (b[1]-'0')); }
static inline unsigned dig4(const char *b) {
    return (unsigned)((b[0]-'0')*1000 + (b[1]-'0')*100 + (b[2]-'0')*10 + (b[3]-'0'));
}

static int parse_iso8601(const char *s, int len, Stamp *out) {
    if (len < 20) return 0;
    unsigned year = dig4(s);
    unsigned month = dig2(s + 5);
    unsigned day = dig2(s + 8);
    unsigned hour = dig2(s + 11);
    unsigned minute = dig2(s + 14);
    unsigned second = dig2(s + 17);
    if (month == 0 || month > 12 || day == 0 || day > 31 ||
        hour > 23 || minute > 59 || second > 60) return 0;
    int64_t days = days_from_civil((int)year, month, day);
    int64_t total = days * 86400 + (int64_t)hour * 3600 + (int64_t)minute * 60 + (int64_t)second;
    out->epoch_min = total >= 0 ? total / 60 : -((-total + 59) / 60);
    int64_t r = ((days % 7) + 7) % 7;
    out->weekday = (uint8_t)((r + 3) % 7);
    out->hour = (uint8_t)hour;
    return 1;
}

/* Parser JSON por chave (parse.rs) ---------------------------------------- */

typedef struct {
    double amount;
    uint32_t installments;
    Stamp requested_at;
    double customer_avg;
    uint32_t tx_count_24h;
    const char *known_buf; int known_len;
    const char *merchant_id; int merchant_id_len;
    const char *merchant_mcc; int merchant_mcc_len;
    double merchant_avg;
    int is_online, card_present;
    double km_from_home;
    int has_last_tx;
    Stamp last_tx_stamp;
    double last_tx_km;
} Payload;

static inline int p_skip_ws(const char *b, int n, int i) {
    while (i < n) { char c = b[i]; if (c==' '||c=='\t'||c=='\n'||c=='\r') i++; else break; }
    return i;
}
static inline int p_expect(const char *b, int n, int i, char c) {
    i = p_skip_ws(b, n, i);
    if (i >= n || b[i] != c) return -1;
    return i + 1;
}
static int p_read_string(const char *b, int n, int i, const char **s, int *sl) {
    i = p_skip_ws(b, n, i);
    if (i >= n || b[i] != '"') return -1;
    int start = i + 1, j = start;
    while (j < n && b[j] != '"') j++;
    if (j >= n) return -1;
    *s = b + start; *sl = j - start;
    return j + 1;
}
static double parse_double_span(const char *b, int len) {
    char tmp[64];
    if (len <= 0) return 0.0;
    if (len > 63) len = 63;
    memcpy(tmp, b, (size_t)len);
    tmp[len] = '\0';
    return strtod(tmp, NULL);
}
static int p_read_f64(const char *b, int n, int i, double *out) {
    i = p_skip_ws(b, n, i);
    int start = i, j = i;
    if (j < n && (b[j]=='-' || b[j]=='+')) j++;
    while (j < n) {
        char c = b[j];
        if ((c>='0'&&c<='9')||c=='.'||c=='e'||c=='E'||c=='-'||c=='+') j++;
        else break;
    }
    if (j == start) return -1;
    *out = parse_double_span(b + start, j - start);
    return j;
}
static int p_read_u32(const char *b, int n, int i, uint32_t *out) {
    i = p_skip_ws(b, n, i);
    int start = i, j = i;
    uint32_t v = 0;
    while (j < n && b[j] >= '0' && b[j] <= '9') { v = v*10 + (uint32_t)(b[j]-'0'); j++; }
    if (j == start) return -1;
    *out = v;
    return j;
}
static int p_read_bool(const char *b, int n, int i, int *out) {
    i = p_skip_ws(b, n, i);
    if (i + 4 <= n && memcmp(b+i, "true", 4) == 0) { *out = 1; return i + 4; }
    if (i + 5 <= n && memcmp(b+i, "false", 5) == 0) { *out = 0; return i + 5; }
    return -1;
}
static int p_is_null(const char *b, int n, int i) {
    i = p_skip_ws(b, n, i);
    return i + 4 <= n && memcmp(b+i, "null", 4) == 0;
}
static int p_skip_value(const char *b, int n, int i) {
    i = p_skip_ws(b, n, i);
    if (i >= n) return -1;
    char c = b[i];
    if (c == '"') {
        i++;
        while (i < n && b[i] != '"') i++;
        if (i >= n) return -1;
        return i + 1;
    }
    if (c == '{' || c == '[') {
        char open = c, close = (c == '{') ? '}' : ']';
        int depth = 1; i++;
        while (i < n && depth > 0) {
            char d = b[i];
            if (d == '"') {
                i++;
                while (i < n && b[i] != '"') i++;
            } else if (d == open) depth++;
            else if (d == close) depth--;
            i++;
        }
        if (depth != 0) return -1;
        return i;
    }
    if (c == 't') return i + 4;
    if (c == 'f') return i + 5;
    if (c == 'n') return i + 4;
    while (i < n) {
        char d = b[i];
        if (d==','||d=='}'||d==']'||d==' '||d=='\n'||d=='\r'||d=='\t') break;
        i++;
    }
    return i;
}
static int p_read_array_raw(const char *b, int n, int i, const char **s, int *sl) {
    i = p_skip_ws(b, n, i);
    if (i >= n || b[i] != '[') return -1;
    int start = i;
    int end = p_skip_value(b, n, i);
    if (end < 0) return -1;
    *s = b + start; *sl = end - start;
    return end;
}

/* dispatcher de campos aninhados; retorna nova posição, -2 (skip) ou -1 (erro) */
typedef int (*kv_fn)(const char *b, int n, const char *k, int kl, int v, Payload *p);

static int for_each_kv(const char *b, int n, int start, kv_fn fn, Payload *p) {
    int i = p_expect(b, n, start, '{');
    if (i < 0) return -1;
    for (;;) {
        i = p_skip_ws(b, n, i);
        if (i < n && b[i] == '}') return i + 1;
        const char *key; int kl;
        int next = p_read_string(b, n, i, &key, &kl);
        if (next < 0) return -1;
        i = p_expect(b, n, next, ':');
        if (i < 0) return -1;
        i = p_skip_ws(b, n, i);
        int consumed = fn(b, n, key, kl, i, p);
        if (consumed == -1) return -1;
        if (consumed == -2) { i = p_skip_value(b, n, i); if (i < 0) return -1; }
        else i = consumed;
        i = p_skip_ws(b, n, i);
        if (i < n && b[i] == ',') { i++; continue; }
        if (i < n && b[i] == '}') return i + 1;
        return -1;
    }
}

#define KEY_IS(s) (kl == (int)sizeof(s)-1 && memcmp(k, s, kl) == 0)

static int tx_kv(const char *b, int n, const char *k, int kl, int v, Payload *p) {
    if (KEY_IS("amount"))       return p_read_f64(b, n, v, &p->amount);
    if (KEY_IS("installments")) return p_read_u32(b, n, v, &p->installments);
    if (KEY_IS("requested_at")) {
        const char *s; int sl;
        int e = p_read_string(b, n, v, &s, &sl);
        if (e < 0) return -1;
        if (!parse_iso8601(s, sl, &p->requested_at)) return -1;
        return e;
    }
    return -2;
}
static int customer_kv(const char *b, int n, const char *k, int kl, int v, Payload *p) {
    if (KEY_IS("avg_amount"))      return p_read_f64(b, n, v, &p->customer_avg);
    if (KEY_IS("tx_count_24h"))    return p_read_u32(b, n, v, &p->tx_count_24h);
    if (KEY_IS("known_merchants")) return p_read_array_raw(b, n, v, &p->known_buf, &p->known_len);
    return -2;
}
static int merchant_kv(const char *b, int n, const char *k, int kl, int v, Payload *p) {
    if (KEY_IS("id"))         return p_read_string(b, n, v, &p->merchant_id, &p->merchant_id_len);
    if (KEY_IS("mcc"))        return p_read_string(b, n, v, &p->merchant_mcc, &p->merchant_mcc_len);
    if (KEY_IS("avg_amount")) return p_read_f64(b, n, v, &p->merchant_avg);
    return -2;
}
static int terminal_kv(const char *b, int n, const char *k, int kl, int v, Payload *p) {
    if (KEY_IS("is_online"))    return p_read_bool(b, n, v, &p->is_online);
    if (KEY_IS("card_present")) return p_read_bool(b, n, v, &p->card_present);
    if (KEY_IS("km_from_home")) return p_read_f64(b, n, v, &p->km_from_home);
    return -2;
}
static int last_tx_kv(const char *b, int n, const char *k, int kl, int v, Payload *p) {
    if (KEY_IS("timestamp")) {
        const char *s; int sl;
        int e = p_read_string(b, n, v, &s, &sl);
        if (e < 0) return -1;
        if (!parse_iso8601(s, sl, &p->last_tx_stamp)) return -1;
        return e;
    }
    if (KEY_IS("km_from_current")) return p_read_f64(b, n, v, &p->last_tx_km);
    return -2;
}
static int top_kv(const char *b, int n, const char *k, int kl, int v, Payload *p) {
    if (KEY_IS("transaction"))  return for_each_kv(b, n, v, tx_kv, p);
    if (KEY_IS("customer"))     return for_each_kv(b, n, v, customer_kv, p);
    if (KEY_IS("merchant"))     return for_each_kv(b, n, v, merchant_kv, p);
    if (KEY_IS("terminal"))     return for_each_kv(b, n, v, terminal_kv, p);
    if (KEY_IS("last_transaction")) {
        if (p_is_null(b, n, v)) {
            p->has_last_tx = 0;
            return p_skip_value(b, n, v);
        }
        p->has_last_tx = 1;
        return for_each_kv(b, n, v, last_tx_kv, p);
    }
    return -2;
}

static int parse_payload(const char *b, int n, Payload *p) {
    memset(p, 0, sizeof(*p));
    return for_each_kv(b, n, 0, top_kv, p) >= 0;
}

static int merchant_in_known(const char *known, int klen, const char *mid, int mid_len) {
    if (mid_len <= 0) return 0;
    int i = 0;
    while (i < klen) {
        if (known[i] == '"') {
            int start = i + 1, j = start;
            while (j < klen && known[j] != '"') j++;
            if (j - start == mid_len && memcmp(known + start, mid, (size_t)mid_len) == 0)
                return 1;
            i = j + 1;
        } else i++;
    }
    return 0;
}

/* Vetorização (vectorize_q) ----------------------------------------------- */

static void vectorize(const Payload *p, int16_t *q) {
    q[0] = quantize_clamped(p->amount / MAX_AMOUNT);
    q[1] = quantize_clamped((double)p->installments / MAX_INSTALLMENTS);

    double ratio = p->customer_avg > 0.0 ? p->amount / p->customer_avg : INFINITY;
    q[2] = quantize_clamped(ratio / AMOUNT_VS_AVG_RATIO);

    q[3] = quantize((double)p->requested_at.hour / 23.0);
    q[4] = quantize((double)p->requested_at.weekday / 6.0);

    if (p->has_last_tx) {
        double minutes = (double)(p->requested_at.epoch_min - p->last_tx_stamp.epoch_min);
        q[5] = quantize_clamped(minutes / MAX_MINUTES);
        q[6] = quantize_clamped(p->last_tx_km / MAX_KM);
    } else {
        q[5] = -(int16_t)SCALE;
        q[6] = -(int16_t)SCALE;
    }

    q[7]  = quantize_clamped(p->km_from_home / MAX_KM);
    q[8]  = quantize_clamped((double)p->tx_count_24h / MAX_TX_COUNT_24H);
    q[9]  = p->is_online ? (int16_t)SCALE : 0;
    q[10] = p->card_present ? (int16_t)SCALE : 0;
    q[11] = merchant_in_known(p->known_buf, p->known_len, p->merchant_id, p->merchant_id_len)
                ? 0 : (int16_t)SCALE;
    q[12] = quantize(mcc_risk_lookup(p->merchant_mcc, p->merchant_mcc_len));
    q[13] = quantize_clamped(p->merchant_avg / MAX_MERCHANT_AVG_AMOUNT);
    q[14] = 0;
    q[15] = 0;
}

/* Busca KNN particionada (index.rs::fraud_count_pair_avx2) ----------------- */

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

static inline int64_t lower_bound_ptr(const int16_t *q, const int16_t *mn, const int16_t *mx) {
    __m256i qv = _mm256_loadu_si256((const __m256i *)q);
    __m256i miv = _mm256_loadu_si256((const __m256i *)mn);
    __m256i mxv = _mm256_loadu_si256((const __m256i *)mx);
    __m256i zero = _mm256_setzero_si256();
    __m256i below = _mm256_max_epi16(_mm256_sub_epi16(miv, qv), zero);
    __m256i above = _mm256_max_epi16(_mm256_sub_epi16(qv, mxv), zero);
    __m256i gap = _mm256_max_epi16(below, above);
    __m256i sq = _mm256_madd_epi16(gap, gap);
    int32_t v[LANES];
    _mm256_storeu_si256((__m256i *)v, sq);
    return (int64_t)v[0]+v[1]+v[2]+v[3]+v[4]+v[5]+v[6]+v[7];
}

static inline int64_t lower_bound_partition(uint32_t part, const int16_t *q) {
    const uint8_t *base = g_parts + (size_t)part * PART_SIZE;
    return lower_bound_ptr(q, (const int16_t *)(base + 12), (const int16_t *)(base + 44));
}
static inline int64_t lower_bound_node(uint32_t node, const int16_t *q) {
    const uint8_t *base = g_nodes + (size_t)node * NODE_SIZE;
    return lower_bound_ptr(q, (const int16_t *)(base + 16), (const int16_t *)(base + 48));
}

static inline void distance_pair_block8(int32_t block_idx, const __m256i *q_pairs, int64_t *out) {
    const int16_t *base = g_vectors + (size_t)block_idx * DIMS * LANES;
    __m256i acc = _mm256_setzero_si256();
    for (int p = 0; p < IVF_PAIRS; p++) {
        __m256i packed = _mm256_loadu_si256((const __m256i *)(base + (size_t)p * LANES * 2));
        __m256i diff = _mm256_sub_epi16(q_pairs[p], packed);
        acc = _mm256_add_epi32(acc, _mm256_madd_epi16(diff, diff));
    }
    uint32_t v[LANES];
    _mm256_storeu_si256((__m256i *)v, acc);
    for (int i = 0; i < LANES; i++) out[i] = (int64_t)v[i];
}

static inline void insert_best(int64_t dist, uint8_t label, int64_t *bd, uint8_t *bl) {
    if (dist >= bd[K-1]) return;
    int pos = K - 1;
    while (pos > 0 && dist < bd[pos-1]) { bd[pos] = bd[pos-1]; bl[pos] = bl[pos-1]; pos--; }
    bd[pos] = dist; bl[pos] = label;
}
static inline uint8_t sum_labels(const uint8_t *bl) {
    uint8_t n = 0;
    for (int i = 0; i < K; i++) n += bl[i];
    return n;
}
static inline int early_done(const int64_t *bd) { return bd[K-1] <= EARLY_DISTANCE_LIMIT; }

static inline void node_meta(uint32_t node, int32_t *left, int32_t *right,
                             int32_t *start, int32_t *len) {
    const uint8_t *base = g_nodes + (size_t)node * NODE_SIZE;
    *left = rd_i32(base); *right = rd_i32(base + 4);
    *start = rd_i32(base + 8); *len = rd_i32(base + 12);
}

static int scan_leaf(int32_t start_block, int32_t len, const __m256i *q_pairs,
                     int64_t *bd, uint8_t *bl) {
    int blocks = (len + LANES - 1) / LANES;
    for (int b = 0; b < blocks; b++) {
        int32_t block_idx = start_block + b;
        int64_t dists[LANES];
        distance_pair_block8(block_idx, q_pairs, dists);
        int lane_count = len - b * LANES;
        if (lane_count > LANES) lane_count = LANES;
        const uint8_t *lab = g_labels + (size_t)block_idx * LANES;
        for (int lane = 0; lane < lane_count; lane++) {
            if (dists[lane] < bd[K-1]) insert_best(dists[lane], lab[lane], bd, bl);
        }
        if (early_done(bd)) return 1;
    }
    return 0;
}

static int search_node(int32_t root, int64_t root_bound, const int16_t *q,
                       const __m256i *q_pairs, int64_t *bd, uint8_t *bl) {
    if (root < 0 || (uint32_t)root >= g_node_count) return 0;
    int32_t stack_node[128];
    int64_t stack_bound[128];
    int sp = 0;
    int32_t cur = root;
    int64_t cur_bound = root_bound;

    for (;;) {
        if (cur_bound < bd[K-1]) {
            int32_t left, right, start, len;
            node_meta((uint32_t)cur, &left, &right, &start, &len);
            if (left < 0) {
                if (scan_leaf(start, len, q_pairs, bd, bl)) return 1;
            } else {
                int64_t lb = lower_bound_node((uint32_t)left, q);
                int64_t rb = lower_bound_node((uint32_t)right, q);
                int32_t near, far; int64_t nb, fb;
                if (lb <= rb) { near = left; nb = lb; far = right; fb = rb; }
                else          { near = right; nb = rb; far = left; fb = lb; }
                if (fb < bd[K-1] && sp < 128) {
                    stack_node[sp] = far; stack_bound[sp] = fb; sp++;
                }
                cur = near; cur_bound = nb;
                continue;
            }
        }
        if (sp == 0) break;
        sp--;
        cur = stack_node[sp];
        cur_bound = stack_bound[sp];
    }
    return early_done(bd);
}

typedef struct { int32_t part; int64_t lb; } Probe;
static int cmp_probe(const void *a, const void *b) {
    int64_t la = ((const Probe *)a)->lb, lb = ((const Probe *)b)->lb;
    return (la > lb) - (la < lb);
}

static uint8_t fraud_count(const int16_t *q) {
    int64_t bd[K];
    uint8_t bl[K];
    for (int i = 0; i < K; i++) { bd[i] = INT64_MAX; bl[i] = 0; }

    __m256i q_pairs[IVF_PAIRS];
    for (int p = 0; p < IVF_PAIRS; p++) {
        uint32_t lo = (uint16_t)q[p*2];
        uint32_t hi = (uint16_t)q[p*2 + 1];
        q_pairs[p] = _mm256_set1_epi32((int)(lo | (hi << 16)));
    }

    uint32_t key = partition_key(q);
    int32_t primary = g_part_by_key[key & 0xff];
    if (primary >= 0) {
        int32_t root = rd_i32(g_parts + (size_t)primary * PART_SIZE + 4);
        if (search_node(root, 0, q, q_pairs, bd, bl))
            return sum_labels(bl);
    }

    Probe probes[256];
    int np = 0;
    for (int32_t p = 0; p < (int32_t)g_part_count; p++) {
        if (p == primary) continue;
        int64_t lb = lower_bound_partition((uint32_t)p, q);
        if (lb >= bd[K-1]) continue;
        probes[np].part = p; probes[np].lb = lb; np++;
    }
    qsort(probes, (size_t)np, sizeof(Probe), cmp_probe);

    for (int i = 0; i < np; i++) {
        if (probes[i].lb >= bd[K-1]) break;
        int32_t root = rd_i32(g_parts + (size_t)probes[i].part * PART_SIZE + 4);
        if (search_node(root, probes[i].lb, q, q_pairs, bd, bl)) break;
    }
    return sum_labels(bl);
}

/* Scoring de requisição --------------------------------------------------- */

static uint8_t process_fraud(const char *body, int len) {
    Payload px;
    if (!parse_payload(body, len, &px)) return RESP_FALLBACK_IDX;
    int16_t q[STORE_DIM];
    vectorize(&px, q);
    uint8_t fc = fraud_count(q);
    return fc < 6 ? fc : 5;
}

/* Estado de conexão / epoll ----------------------------------------------- */

typedef enum {
    EV_CTRL_LISTENER = 1,
    EV_CTRL_CONN     = 2,
    EV_CLIENT        = 3,
} EvKind;

typedef struct EventTag { int kind; } EventTag;

typedef struct Conn {
    int  kind;
    int  fd;
    int  head, tail;
    char buf[RX_BUF_SZ];
} Conn;

typedef struct CtrlConn { int kind; int fd; } CtrlConn;

#define MAX_CTRL_CONNS 16

static Conn      conn_pool[MAX_CONNS];
static int       conn_free_stk[MAX_CONNS];
static int       conn_free_top;
static CtrlConn  ctrl_pool[MAX_CTRL_CONNS];
static int       ctrl_free_stk[MAX_CTRL_CONNS];
static int       ctrl_free_top;
static EventTag  ctrl_listener_tag = { EV_CTRL_LISTENER };

static int set_fd_nonblock_cloexec(int fd) {
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl >= 0) fcntl(fd, F_SETFL, fl | O_NONBLOCK);
    int fdfl = fcntl(fd, F_GETFD, 0);
    if (fdfl >= 0) fcntl(fd, F_SETFD, fdfl | FD_CLOEXEC);
    return 0;
}

static void conn_pool_init(void) {
    conn_free_top = MAX_CONNS;
    for (int i = 0; i < MAX_CONNS; i++) {
        conn_pool[i].kind = EV_CLIENT;
        conn_pool[i].fd = -1;
        conn_free_stk[i] = i;
    }
}
static Conn *conn_alloc(void) {
    if (!conn_free_top) return NULL;
    Conn *c = &conn_pool[conn_free_stk[--conn_free_top]];
    c->kind = EV_CLIENT;
    return c;
}
static void conn_release(Conn *c) {
    c->fd = -1; c->head = c->tail = 0;
    conn_free_stk[conn_free_top++] = (int)(c - conn_pool);
}
static void conn_close(Conn *c, int efd) {
    if (c->fd >= 0) {
        epoll_ctl(efd, EPOLL_CTL_DEL, c->fd, NULL);
        close(c->fd);
    }
    conn_release(c);
}

static void ctrl_pool_init(void) {
    ctrl_free_top = MAX_CTRL_CONNS;
    for (int i = 0; i < MAX_CTRL_CONNS; i++) {
        ctrl_pool[i].kind = EV_CTRL_CONN;
        ctrl_pool[i].fd = -1;
        ctrl_free_stk[i] = i;
    }
}
static CtrlConn *ctrl_alloc(void) {
    if (!ctrl_free_top) return NULL;
    CtrlConn *c = &ctrl_pool[ctrl_free_stk[--ctrl_free_top]];
    c->kind = EV_CTRL_CONN;
    return c;
}
static void ctrl_close(CtrlConn *c, int efd) {
    if (c->fd >= 0) {
        epoll_ctl(efd, EPOLL_CTL_DEL, c->fd, NULL);
        close(c->fd);
    }
    c->fd = -1;
    ctrl_free_stk[ctrl_free_top++] = (int)(c - ctrl_pool);
}

/* HTTP ------------------------------------------------------------------- */

static int parse_content_length(const char *buf, int hlen) {
    const char *key = "content-length:";
    for (int i = 0; i <= hlen - 15; i++) {
        if ((buf[i] | 32) != 'c') continue;
        int ok = 1;
        for (int j = 1; j < 15; j++) if ((buf[i+j] | 32) != key[j]) { ok = 0; break; }
        if (!ok) continue;
        int p = i + 15;
        while (p < hlen && (buf[p]==' '||buf[p]=='\t')) p++;
        int v = 0;
        while (p < hlen && buf[p]>='0' && buf[p]<='9') { v = v*10 + (buf[p]-'0'); p++; }
        return v;
    }
    return -1;
}

static inline int path_eq(const char *rest, int rlen, const char *path, int plen) {
    if (rlen < plen + 1) return 0;
    if (memcmp(rest, path, (size_t)plen) != 0) return 0;
    char nx = rest[plen];
    return nx == ' ' || nx == '?';
}

/*
 * Sempre responde 200. Retorna nº de bytes consumidos do buffer e preenche
 * iov, ou 0 se precisa de mais dados.
 */
static int handle_req(const char *buf, int len, struct iovec *iov) {
    const char *he = (const char *)memmem(buf, (size_t)len, "\r\n\r\n", 4);
    if (!he) {
        if (len > MAX_REQ_HEAD) {   /* cabeçalho gigante -> fallback, descarta tudo */
            iov->iov_base = (void *)RESP_FRAUD[RESP_FALLBACK_IDX];
            iov->iov_len = RESP_FRAUD_LEN[RESP_FALLBACK_IDX];
            return len;
        }
        return 0;
    }
    int hlen = (int)(he - buf);
    int body_start = hlen + 4;

    if (memcmp(buf, "POST ", 5) == 0) {
        const char *rest = buf + 5; int rlen = hlen - 5;
        if (path_eq(rest, rlen, "/fraud-score", 12)) {
            int cl = parse_content_length(buf, hlen);
            if (cl < 0 || cl > MAX_BODY) {
                iov->iov_base = (void *)RESP_FRAUD[RESP_FALLBACK_IDX];
                iov->iov_len = RESP_FRAUD_LEN[RESP_FALLBACK_IDX];
                return len;
            }
            int body_end = body_start + cl;
            if (len < body_end) return 0;
            uint8_t fc = process_fraud(buf + body_start, cl);
            iov->iov_base = (void *)RESP_FRAUD[fc];
            iov->iov_len = RESP_FRAUD_LEN[fc];
            return body_end;
        }
        iov->iov_base = (void *)RESP_FRAUD[RESP_FALLBACK_IDX];
        iov->iov_len = RESP_FRAUD_LEN[RESP_FALLBACK_IDX];
        return body_start;
    }
    if (memcmp(buf, "GET ", 4) == 0) {
        const char *rest = buf + 4; int rlen = hlen - 4;
        if (path_eq(rest, rlen, "/ready", 6)) {
            iov->iov_base = (void *)RESP_READY;
            iov->iov_len = sizeof(RESP_READY) - 1;
            return body_start;
        }
        iov->iov_base = (void *)RESP_FRAUD[RESP_FALLBACK_IDX];
        iov->iov_len = RESP_FRAUD_LEN[RESP_FALLBACK_IDX];
        return body_start;
    }
    /* método desconhecido -> fallback, descarta o head */
    iov->iov_base = (void *)RESP_FRAUD[RESP_FALLBACK_IDX];
    iov->iov_len = RESP_FRAUD_LEN[RESP_FALLBACK_IDX];
    return body_start;
}

static int send_iov_all(int fd, struct iovec *iov, int niov) {
    while (niov > 0) {
        ssize_t n = writev(fd, iov, niov);
        if (n > 0) {
            while (niov > 0 && n >= (ssize_t)iov[0].iov_len) {
                n -= (ssize_t)iov[0].iov_len; iov++; niov--;
            }
            if (niov > 0 && n > 0) {
                iov[0].iov_base = (char *)iov[0].iov_base + n;
                iov[0].iov_len -= (size_t)n;
            }
            continue;
        }
        if (n < 0 && errno == EINTR) continue;
        return -1;
    }
    return 0;
}

static void handle_conn(Conn *c, int efd) {
    for (;;) {
        int space = RX_BUF_SZ - c->tail;
        if (space == 0) {
            if (c->head == 0) { conn_close(c, efd); return; }
            int keep = c->tail - c->head;
            if (keep > 0) memmove(c->buf, c->buf + c->head, (size_t)keep);
            c->tail = keep; c->head = 0; space = RX_BUF_SZ - c->tail;
        }
        int n = (int)recv(c->fd, c->buf + c->tail, (size_t)space, MSG_DONTWAIT);
        if (n < 0) { if (errno==EAGAIN||errno==EWOULDBLOCK) break; conn_close(c, efd); return; }
        if (n == 0) { conn_close(c, efd); return; }
        c->tail += n;
        if (n < space) break;
    }

    struct iovec iovs[MAX_IOVECS];
    int niov = 0;

    while (c->head < c->tail && niov < MAX_IOVECS) {
        struct iovec iv;
        int consumed = handle_req(c->buf + c->head, c->tail - c->head, &iv);
        if (consumed == 0) break;
        iovs[niov++] = iv;
        c->head += consumed;
    }

    if (niov > 0) {
        if (send_iov_all(c->fd, iovs, niov) < 0) { conn_close(c, efd); return; }
    }

    if (c->head == c->tail) { c->head = c->tail = 0; }
    else if (c->head > RX_BUF_SZ / 2) {
        int k = c->tail - c->head;
        memmove(c->buf, c->buf + c->head, (size_t)k);
        c->tail = k; c->head = 0;
    }
}

static Conn *register_client_fd(int fd, int efd) {
#ifndef RINHA_ASSUME_PASSED_FD_FLAGS
    set_fd_nonblock_cloexec(fd);
#endif
    Conn *nc = conn_alloc();
    if (!nc) { close(fd); return NULL; }
    nc->fd = fd; nc->head = nc->tail = 0;
    struct epoll_event ev = { .events = EPOLLIN | EPOLLRDHUP | EPOLLET, .data.ptr = nc };
    if (epoll_ctl(efd, EPOLL_CTL_ADD, fd, &ev) < 0) {
        close(fd); conn_release(nc); return NULL;
    }
    return nc;
}

/* Intake de FDs no socket de controle ------------------------------------- */

static int recv_one_passed_fd(int sock) {
    char byte;
    struct iovec iov = { .iov_base = &byte, .iov_len = 1 };
    union { char buf[CMSG_SPACE(sizeof(int))]; struct cmsghdr align; } control;
    memset(&control, 0, sizeof(control));

    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = &iov; msg.msg_iovlen = 1;
    msg.msg_control = control.buf; msg.msg_controllen = sizeof(control.buf);

    ssize_t n;
    for (;;) {
        n = recvmsg(sock, &msg, MSG_DONTWAIT | MSG_CMSG_CLOEXEC);
        if (n < 0 && errno == EINTR) continue;
        break;
    }
    if (n < 0) { if (errno==EAGAIN||errno==EWOULDBLOCK) return -2; return -1; }
    if (n == 0) return -1;

    for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
        if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {
            int fd = -1;
            memcpy(&fd, CMSG_DATA(cmsg), sizeof(fd));
            return fd;
        }
    }
    return -1;
}

static int drain_control_fds(CtrlConn *cc, int efd) {
    for (;;) {
        int fd = recv_one_passed_fd(cc->fd);
        if (fd == -2) return 0;
        if (fd < 0) return -1;
        Conn *nc = register_client_fd(fd, efd);
        if (!nc) continue;
        handle_conn(nc, efd);
    }
}

static void accept_control_loop(int ctrl_sfd, int efd) {
    for (;;) {
        int fd = accept4(ctrl_sfd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (fd < 0) {
            if (errno==EAGAIN||errno==EWOULDBLOCK) return;
            if (errno == EINTR) continue;
            return;
        }
        CtrlConn *cc = ctrl_alloc();
        if (!cc) { close(fd); continue; }
        cc->fd = fd;
        struct epoll_event ev = { .events = EPOLLIN | EPOLLRDHUP | EPOLLET, .data.ptr = cc };
        if (epoll_ctl(efd, EPOLL_CTL_ADD, fd, &ev) < 0) { ctrl_close(cc, efd); continue; }
    }
}

static int make_parent_dir(const char *path) {
    char tmp[256];
    strncpy(tmp, path, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';
    char *sl = strrchr(tmp, '/');
    if (sl && sl != tmp) { *sl = '\0'; mkdir(tmp, 0777); }
    return 0;
}

static int listen_unix_seqpacket(const char *path) {
    unlink(path);
    make_parent_dir(path);
    int fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) { perror("socket ctrl"); return -1; }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    size_t plen = strlen(path);
    if (plen >= sizeof(addr.sun_path)) {
        fprintf(stderr, "control socket path too long: %s\n", path);
        close(fd); return -1;
    }
    memcpy(addr.sun_path, path, plen + 1);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) { perror("bind ctrl"); close(fd); return -1; }
    chmod(path, 0666);
    if (listen(fd, 64) < 0) { perror("listen ctrl"); close(fd); return -1; }
    return fd;
}

static void event_loop(int ctrl_sfd, int efd) {
    struct epoll_event evs[128];
    for (;;) {
        int n = epoll_wait(efd, evs, 128, -1);
        if (n < 0) { if (errno == EINTR) continue; return; }
        for (int i = 0; i < n; i++) {
            EventTag *tag = (EventTag *)evs[i].data.ptr;
            if (!tag) continue;
            if (tag->kind == EV_CTRL_LISTENER) { accept_control_loop(ctrl_sfd, efd); continue; }
            if (tag->kind == EV_CTRL_CONN) {
                CtrlConn *cc = (CtrlConn *)tag;
                if (evs[i].events & EPOLLIN) {
                    if (drain_control_fds(cc, efd) < 0) { ctrl_close(cc, efd); continue; }
                }
                if (evs[i].events & (EPOLLRDHUP|EPOLLHUP|EPOLLERR)) { ctrl_close(cc, efd); continue; }
                continue;
            }
            Conn *c = (Conn *)tag;
            if (evs[i].events & (EPOLLRDHUP|EPOLLHUP|EPOLLERR)) { conn_close(c, efd); continue; }
            if (evs[i].events & EPOLLIN) handle_conn(c, efd);
        }
    }
}

static void warm_up_index(void) {
    const char *e = getenv("API_WARMUP_QUERIES");
    int count = (e && *e) ? atoi(e) : 2048;
    if (count <= 0) return;
    uint8_t sink = 0;
    for (int i = 0; i < count; i++) {
        int16_t q[STORE_DIM];
        for (int d = 0; d < STORE_DIM; d++) q[d] = 0;
        for (int d = 0; d < DIMS; d++)
            q[d] = (int16_t)(((size_t)i * 313 + (size_t)d * 1009) % (SCALE + 1));
        if ((i & 3) == 0) { q[5] = -(int16_t)SCALE; q[6] = -(int16_t)SCALE; }
        if (i & 1) q[9] = SCALE;
        if (i & 2) q[10] = SCALE;
        if (i & 4) q[11] = SCALE;
        sink ^= fraud_count(q);
    }
    __asm__ volatile("" :: "r"(sink));
}

#ifndef RINHA_API_NO_MAIN

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    for (int i = 0; i < 6; i++) RESP_FRAUD_LEN[i] = strlen(RESP_FRAUD[i]);

    const char *sock  = getenv("RINHA_SOCK");       if (!sock)  sock = "/run/sock/api.sock";
    const char *ipath = getenv("RINHA_INDEX_PATH"); if (!ipath) ipath = "/app/data/index.ivf";

    load_index(ipath);
    warm_up_index();
    fprintf(stderr, "[api] índice carregado: %u pontos, %u partições\n",
            g_n_points, g_part_count);

    char ctrl_sock[256];
    const char *ctrl_env = getenv("RINHA_CTRL_SOCK");
    if (ctrl_env && *ctrl_env) {
        strncpy(ctrl_sock, ctrl_env, sizeof(ctrl_sock) - 1);
        ctrl_sock[sizeof(ctrl_sock) - 1] = '\0';
    } else {
        snprintf(ctrl_sock, sizeof(ctrl_sock), "%s.ctrl", sock);
    }

    int ctrl_sfd = listen_unix_seqpacket(ctrl_sock);
    if (ctrl_sfd < 0) return 1;

    int efd = epoll_create1(EPOLL_CLOEXEC);
    if (efd < 0) { perror("epoll_create1"); return 1; }
    struct epoll_event ev = { .events = EPOLLIN, .data.ptr = &ctrl_listener_tag };
    epoll_ctl(efd, EPOLL_CTL_ADD, ctrl_sfd, &ev);

    conn_pool_init();
    ctrl_pool_init();
    event_loop(ctrl_sfd, efd);
    return 0;
}
#endif
