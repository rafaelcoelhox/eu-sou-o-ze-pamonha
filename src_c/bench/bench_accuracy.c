#define _GNU_SOURCE
#define RINHA_API_NO_MAIN
#include "../api.c"

#include <limits.h>
#include "bench_common.h"

typedef struct {
    BenchJsonSpan req;
    int expected_approved;
} TestEntry;

static int find_field_obj(const char *buf, int len, const char *key, int klen,
                          int *out_start, int *out_end)
{
    int kl_with_quotes = klen + 2;
    const char *p = memmem(buf, len, key-1, kl_with_quotes);
    while (p) {
        if (p > buf && p[-1] == '"' && p[klen] == '"') break;
        p = memmem(p+1, len-((p+1)-buf), key, klen);
    }
    if (!p) return 0;
    int pos = (int)((p - buf) + klen);
    while (pos < len && buf[pos] != ':') pos++;
    if (pos >= len) return 0;
    pos++;
    while (pos < len && (buf[pos] == ' ' || buf[pos] == '\t')) pos++;
    *out_start = pos;
    *out_end = pos;
    return 1;
}

static int extract_request_span(const char *entry, int elen,
                                const char **req_out, int *req_len_out,
                                int *expected_out)
{
    const char *rk = "\"request\"";
    const char *rp = memmem(entry, elen, rk, 9);
    if (!rp) return 0;
    int pos = (int)((rp - entry) + 9);
    while (pos < elen && (entry[pos] == ' ' || entry[pos] == ':' || entry[pos] == '\t')) pos++;
    if (pos >= elen || entry[pos] != '{') return 0;
    int start = pos;
    int depth = 0, in_str = 0, esc = 0;
    for (; pos < elen; pos++) {
        char c = entry[pos];
        if (in_str) {
            if (esc) esc = 0;
            else if (c == '\\') esc = 1;
            else if (c == '"') in_str = 0;
            continue;
        }
        if (c == '"') { in_str = 1; continue; }
        if (c == '{') depth++;
        else if (c == '}') {
            depth--;
            if (depth == 0) { pos++; break; }
        }
    }
    *req_out = entry + start;
    *req_len_out = pos - start;

    const char *ek = "\"expected_approved\"";
    const char *ep = memmem(entry, elen, ek, 19);
    if (!ep) return 0;
    int ePos = (int)((ep - entry) + 19);
    while (ePos < elen && (entry[ePos] == ' ' || entry[ePos] == ':')) ePos++;
    if (ePos >= elen) return 0;
    *expected_out = (entry[ePos] == 't');
    return 1;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <index.ivf> <test-data.json> [iterations]\n", argv[0]);
        return 1;
    }
    long iters = bench_arg_long(argv, argc, 3, 1);
    load_index(argv[1]);

    BenchFile file = bench_read_file(argv[2]);

    const char *entries_marker = "\"entries\"";
    const char *em = memmem(file.data, file.len, entries_marker, 9);
    if (!em) { fputs("no entries\n", stderr); return 1; }
    size_t start = (size_t)(em - file.data) + 9;
    while (start < file.len && file.data[start] != '[') start++;
    if (start >= file.len) { fputs("no entries array\n", stderr); return 1; }
    start++;

    size_t cap = 60000;
    TestEntry *entries = malloc(cap * sizeof(TestEntry));
    size_t n = 0;
    size_t pos = start;
    BenchJsonSpan span;
    while (bench_next_json_object(file.data, file.len, &pos, &span)) {
        const char *rp; int rl, ea;
        if (!extract_request_span(span.ptr, (int)span.len, &rp, &rl, &ea)) continue;
        if (n >= cap) { cap *= 2; entries = realloc(entries, cap * sizeof(TestEntry)); }
        entries[n].req.ptr = rp;
        entries[n].req.len = (size_t)rl;
        entries[n].expected_approved = ea;
        n++;
    }
    fprintf(stderr, "loaded %zu test entries\n", n);

    int tp = 0, tn = 0, fp = 0, fn = 0, parse_fail = 0;
    int fc_dist[7] = {0};
    int dump_errors = getenv("DUMP_ERRORS") != NULL;

    uint64_t t0 = bench_now_ns();
    for (long it = 0; it < iters; it++) {
        tp = tn = fp = fn = parse_fail = 0;
        for (int i = 0; i < 7; i++) fc_dist[i] = 0;
        for (size_t i = 0; i < n; i++) {
            Payload px;
            if (!parse_payload(entries[i].req.ptr, (int)entries[i].req.len, &px)) {
                parse_fail++;
                continue;
            }
            int16_t q[STORE_DIM];
            vectorize(&px, q);
            uint8_t fc = fraud_count(q);
            if (fc <= 6) fc_dist[fc]++;
            int approved = (fc < 3);
            int expected = entries[i].expected_approved;
            if (approved == expected) {
                if (approved) tn++; else tp++;
            } else {
                if (approved) fn++; else fp++;
                if (dump_errors && it == iters-1) {
                    fprintf(stderr, "ERR i=%zu fc=%u approved=%d expected=%d  vec=[",
                            i, fc, approved, expected);
                    for (int d=0; d<DIMS; d++)
                        fprintf(stderr, "%.4f%s", (double)q[d]/(double)SCALE, d==DIMS-1?"":",");
                    fprintf(stderr, "]\n");
                }
            }
        }
    }
    uint64_t elapsed = bench_now_ns() - t0;

    printf("entries=%zu iters=%ld TP=%d TN=%d FP=%d FN=%d parse_fail=%d total_errs=%d\n",
           n, iters, tp, tn, fp, fn, parse_fail, fp+fn);
    printf("fc distribution: ");
    for (int i = 0; i <= 6; i++) printf("%d=%d ", i, fc_dist[i]);
    printf("\n");
    printf("elapsed_ms=%.3f ns_per_query=%.2f\n",
           (double)elapsed/1e6,
           (double)elapsed/(double)(iters*n));

    free(entries);
    free(file.data);
    return 0;
}
