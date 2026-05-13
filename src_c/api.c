#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#include <float.h>
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

#define DIMS         14
#define BLOCK_VECS   16
#define VECTOR_SCALE 0.0001f   
#define FAST_NPROBE  8
#define FULL_NPROBE  24       

#define MAX_CONNS   512
#define RX_BUF_SZ  8192
#define MAX_IOVECS   16

#define R_HDR "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
static const char *RESP_FRAUD[6] = {
    R_HDR "35\r\n\r\n{\"approved\":true,\"fraud_score\":0.0}",
    R_HDR "35\r\n\r\n{\"approved\":true,\"fraud_score\":0.2}",
    R_HDR "35\r\n\r\n{\"approved\":true,\"fraud_score\":0.4}",
    R_HDR "36\r\n\r\n{\"approved\":false,\"fraud_score\":0.6}",
    R_HDR "36\r\n\r\n{\"approved\":false,\"fraud_score\":0.8}",
    R_HDR "36\r\n\r\n{\"approved\":false,\"fraud_score\":1.0}",
};
static size_t RESP_FRAUD_LEN[6]; 
static const char RESP_READY[]    = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
static const char RESP_NOT_FOUND[]= "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
static const char RESP_BAD_REQ[]  = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

static float mcc_risk(uint32_t mcc) {
    switch (mcc) {
        case 5411: return 0.15f;
        case 5812: return 0.30f;
        case 5912: return 0.20f;
        case 5944: return 0.45f;
        case 7801: return 0.80f;
        case 7802: return 0.75f;
        case 7995: return 0.85f;
        case 4511: return 0.35f;
        case 5311: return 0.25f;
        case 5999: return 0.50f;
        default:   return 0.50f;
    }
}

typedef struct __attribute__((packed)) {
    char     magic[8];
    uint32_t n, k, d, total_blocks, padded_n;
} IvfHeader;

static const float    *g_ct;
static const uint32_t *g_offsets;
static const uint8_t  *g_labels;
static const int16_t  *g_blocks;
static int             g_k;

static float g_dists[4096];

static void load_index(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) { perror(path); exit(1); }
    struct stat st;
    fstat(fd, &st);
    size_t sz = (size_t)st.st_size;

    char *base = mmap(NULL, sz, PROT_READ|PROT_WRITE,
                      MAP_PRIVATE|MAP_ANONYMOUS|MAP_POPULATE, -1, 0);
    if (base == MAP_FAILED) { perror("mmap index"); exit(1); }
    madvise(base, sz, MADV_HUGEPAGE);

    size_t rem = sz;
    char *wp = base;
    while (rem > 0) {
        ssize_t n = read(fd, wp, rem < (1u<<20) ? rem : (1u<<20));
        if (n <= 0) { perror("read index"); exit(1); }
        wp += n; rem -= (size_t)n;
    }
    close(fd);

    mlock(base, sz);

    IvfHeader *hdr = (IvfHeader*)base;
    if (memcmp(hdr->magic, "CIVF2\0\0\0", 8)) {
        fputs("Invalid index magic\n", stderr); exit(1);
    }
    g_k = (int)hdr->k;

    const char *p = base + sizeof(IvfHeader);
    g_ct      = (const float*)p;    p += (size_t)DIMS * g_k * sizeof(float);
    g_offsets = (const uint32_t*)p; p += (size_t)(g_k+1) * sizeof(uint32_t);
    g_labels  = (const uint8_t*)p;  p += hdr->padded_n;
    g_blocks  = (const int16_t*)p;

}

static uint8_t day_of_week(uint16_t y, uint8_t m, uint8_t d) {
    static const uint8_t T[12] = {0,3,2,5,0,3,5,1,4,6,2,4};
    uint32_t ya = (m < 3) ? (uint32_t)(y-1) : (uint32_t)y;
    uint32_t dow = (ya + ya/4 - ya/100 + ya/400 + T[m-1] + d) % 7;
    return (uint8_t)((dow + 6) % 7);  /* Mon=0 conforme as regras */
}

static int64_t days_epoch(int y, uint32_t m, uint32_t d) {
    if (m <= 2) y--;
    int era = (y >= 0) ? y/400 : (y-399)/400;
    uint32_t yoe = (uint32_t)(y - era*400);
    uint32_t mm  = (m > 2) ? m-3 : m+9;
    uint32_t doy = (153*mm+2)/5 + d - 1;
    uint32_t doe = yoe*365 + yoe/4 - yoe/100 + doy;
    return (int64_t)era*146097 + (int64_t)doe - 719468;
}

static uint32_t minutes_between(
    uint16_t y1, uint8_t m1, uint8_t d1, uint8_t h1, uint8_t mi1,
    uint16_t y2, uint8_t m2, uint8_t d2, uint8_t h2, uint8_t mi2)
{
    int64_t a = days_epoch(y1,m1,d1)*1440 + h1*60 + mi1;
    int64_t b = days_epoch(y2,m2,d2)*1440 + h2*60 + mi2;
    int64_t diff = b - a;
    return (uint32_t)(diff < 0 ? 0 : diff);
}

typedef struct {
    float    amount, customer_avg, merchant_avg, km_home, km_current;
    uint32_t tx_count_24h, mcc, minutes_since_last;
    uint8_t  installments, hour, dow;
    int      is_online, card_present, is_unknown, has_last_tx;
} Payload;

static int next_val(const char *b, int n, int *p) {
    while (*p < n) {
        char c = b[*p];
        if (c == ':') { (*p)++; while (*p<n && (b[*p]==' '||b[*p]=='\t'||b[*p]=='\n'||b[*p]=='\r')) (*p)++; return 1; }
        if (c == '"') {
            (*p)++;
            const char *e = memchr(b+*p, '"', n-*p);
            if (!e) return 0;
            *p = (int)(e-b)+1;
        } else (*p)++;
    }
    return 0;
}

static int skip_str(const char *b, int n, int *p) {
    if (*p<n && b[*p]=='"') (*p)++;
    const char *e = memchr(b+*p, '"', n-*p);
    if (!e) return 0;
    *p = (int)(e-b)+1; return 1;
}

static float scan_f32(const char *b, int n, int *p) {
    int neg=0;
    if (*p<n && b[*p]=='-') { neg=1; (*p)++; }
    double v=0;
    while (*p<n && b[*p]>='0' && b[*p]<='9') { v=v*10+(b[*p]-'0'); (*p)++; }
    if (*p<n && b[*p]=='.') {
        (*p)++; double f=0.1;
        while (*p<n && b[*p]>='0' && b[*p]<='9') { v+=(b[*p]-'0')*f; f*=0.1; (*p)++; }
    }
    if (*p<n && (b[*p]|32)=='e') {
        (*p)++; int es=1;
        if (*p<n && b[*p]=='-'){es=-1;(*p)++;} else if(*p<n&&b[*p]=='+')(*p)++;
        int e=0; while(*p<n&&b[*p]>='0'&&b[*p]<='9'){e=e*10+(b[*p]-'0');(*p)++;}
        v*=pow(10.0,es*e);
    }
    return (float)(neg?-v:v);
}

static uint32_t scan_u32(const char *b, int n, int *p) {
    uint32_t v=0;
    while (*p<n && b[*p]>='0' && b[*p]<='9') { v=v*10+(b[*p]-'0'); (*p)++; }
    return v;
}

static int scan_bool(const char *b, int n, int *p) {
    int r = (*p<n && b[*p]=='t'); *p += r ? 4 : 5; return r;
}

static uint32_t scan_mcc(const char *b, int n, int *p) {
    if (*p<n && b[*p]=='"') (*p)++;
    uint32_t v = scan_u32(b,n,p);
    if (*p<n && b[*p]=='"') (*p)++;
    return v;
}

static const char *scan_str(const char *b, int n, int *p, int *slen) {
    if (*p>=n||b[*p]!='"'){*slen=0;return NULL;}
    (*p)++;
    int s=*p;
    const char *e=memchr(b+*p,'"',n-*p);
    if(!e){*slen=0;return NULL;}
    *slen=(int)(e-(b+s)); *p=(int)(e-b)+1;
    return b+s;
}

static int scan_iso(const char *b, int n, int *p,
    uint16_t *y, uint8_t *mo, uint8_t *d, uint8_t *h, uint8_t *mi)
{
    if (*p<n && b[*p]=='"') (*p)++;
    if (n-*p < 16) return 0;
    const char *s=b+*p;
    *y  = (uint16_t)((s[0]-'0')*1000+(s[1]-'0')*100+(s[2]-'0')*10+(s[3]-'0'));
    *mo = (s[5]-'0')*10+(s[6]-'0');
    *d  = (s[8]-'0')*10+(s[9]-'0');
    *h  = (s[11]-'0')*10+(s[12]-'0');
    *mi = (s[14]-'0')*10+(s[15]-'0');
    *p += 16;
    const char *e=memchr(b+*p,'"',n-*p);
    if (e) *p=(int)(e-b)+1;
    return 1;
}

static int parse_json(const char *buf, int len, Payload *px) {
    int p = 0;
    if (!next_val(buf,len,&p)) return 0;
    if (!skip_str(buf,len,&p)) return 0;
    if (!next_val(buf,len,&p)) return 0;
    if (!next_val(buf,len,&p)) return 0;
    px->amount = scan_f32(buf,len,&p);
    if (!next_val(buf,len,&p)) return 0;
    px->installments = (uint8_t)scan_u32(buf,len,&p);
    if (!next_val(buf,len,&p)) return 0;
    uint16_t ry; uint8_t rmo,rd,rh,rmi;
    if (!scan_iso(buf,len,&p,&ry,&rmo,&rd,&rh,&rmi)) return 0;
    px->hour = rh;
    px->dow  = day_of_week(ry,rmo,rd);
    if (!next_val(buf,len,&p)) return 0;
    if (!next_val(buf,len,&p)) return 0;
    px->customer_avg = scan_f32(buf,len,&p);
    if (!next_val(buf,len,&p)) return 0;
    px->tx_count_24h = scan_u32(buf,len,&p);
    if (!next_val(buf,len,&p)) return 0;
    while (p<len && buf[p]!='[') p++;
    if (p>=len) return 0;
    p++;
    const char *merchant_sl[16]; int merchant_ln[16]; int mc=0;
    while (p<len && buf[p]!=']') {
        if (buf[p]=='"') {
            p++;
            const char *e=memchr(buf+p,'"',len-p);
            if (!e) break;
            if (mc<16){merchant_sl[mc]=buf+p; merchant_ln[mc]=(int)(e-(buf+p)); mc++;}
            p=(int)(e-buf)+1;
        } else p++;
    }
    if (p<len) p++;
    if (!next_val(buf,len,&p)) return 0;
    if (!next_val(buf,len,&p)) return 0;
    int mid_len;
    const char *mid = scan_str(buf,len,&p,&mid_len);
    if (!next_val(buf,len,&p)) return 0;
    px->mcc = scan_mcc(buf,len,&p);
    if (!next_val(buf,len,&p)) return 0;
    px->merchant_avg = scan_f32(buf,len,&p);
    if (!next_val(buf,len,&p)) return 0;
    if (!next_val(buf,len,&p)) return 0;
    px->is_online   = scan_bool(buf,len,&p);
    if (!next_val(buf,len,&p)) return 0;
    px->card_present = scan_bool(buf,len,&p);
    if (!next_val(buf,len,&p)) return 0;
    px->km_home = scan_f32(buf,len,&p);
    if (!next_val(buf,len,&p)) return 0;
    px->has_last_tx = (p<len && buf[p]!='n');
    if (px->has_last_tx) {
        if (!next_val(buf,len,&p)) return 0;
        uint16_t ly; uint8_t lmo,ld,lh,lmi;
        if (!scan_iso(buf,len,&p,&ly,&lmo,&ld,&lh,&lmi)) return 0;
        if (!next_val(buf,len,&p)) return 0;
        px->km_current = scan_f32(buf,len,&p);
        px->minutes_since_last = minutes_between(ly,lmo,ld,lh,lmi, ry,rmo,rd,rh,rmi);
    } else {
        px->km_current = 0; px->minutes_since_last = 0;
    }
    px->is_unknown = 1;
    if (mid) {
        for (int i=0; i<mc; i++) {
            if (merchant_ln[i]==mid_len && memcmp(merchant_sl[i],mid,mid_len)==0) {
                px->is_unknown=0; break;
            }
        }
    }
    return 1;
}

static inline float round4(float x) { return roundf(x*10000.f)*0.0001f; }
static inline float clamp01(float x) {
    if (x<0.f) x=0.f; else if (x>1.f) x=1.f;
    return round4(x);
}

static void vectorize(const Payload *px, float *v) {
    v[0]  = clamp01(px->amount / 10000.f);
    v[1]  = clamp01((float)px->installments / 12.f);
    float ratio = px->customer_avg > 0.f
        ? (px->amount / px->customer_avg) / 10.f : 1.f;
    v[2]  = clamp01(ratio);
    v[3]  = round4((float)px->hour / 23.f);
    v[4]  = round4((float)px->dow  / 6.f);
    if (px->has_last_tx) {
        v[5] = clamp01((float)px->minutes_since_last / 1440.f);
        v[6] = clamp01(px->km_current / 1000.f);
    } else {
        v[5] = -1.f; v[6] = -1.f;  /* sentinela: sem transação anterior */
    }
    v[7]  = clamp01(px->km_home / 1000.f);
    v[8]  = clamp01((float)px->tx_count_24h / 20.f);
    v[9]  = px->is_online   ? 1.f : 0.f;
    v[10] = px->card_present? 1.f : 0.f;
    v[11] = px->is_unknown  ? 1.f : 0.f;
    v[12] = mcc_risk(px->mcc);
    v[13] = clamp01(px->merchant_avg / 10000.f);
}

static void compute_centroid_dists(const float *q, const float *ct, int k, float *dists) {
    {
        const float *cp = ct;
        __m256 qd = _mm256_set1_ps(q[0]);
        int ci;
        for (ci=0; ci+16<=k; ci+=16) {
            __m256 d0=_mm256_sub_ps(_mm256_loadu_ps(cp+ci),   qd);
            __m256 d1=_mm256_sub_ps(_mm256_loadu_ps(cp+ci+8), qd);
            _mm256_storeu_ps(dists+ci,   _mm256_mul_ps(d0,d0));
            _mm256_storeu_ps(dists+ci+8, _mm256_mul_ps(d1,d1));
        }
        for (; ci<k; ci++) { float d=cp[ci]-q[0]; dists[ci]=d*d; }
    }
    for (int d=1; d<DIMS; d++) {
        const float *cp = ct + d*k;
        __m256 qd = _mm256_set1_ps(q[d]);
        int ci;
        for (ci=0; ci+16<=k; ci+=16) {
            __m256 cv0=_mm256_loadu_ps(cp+ci);   __m256 cv1=_mm256_loadu_ps(cp+ci+8);
            __m256 d0 =_mm256_sub_ps(cv0,qd);    __m256 d1 =_mm256_sub_ps(cv1,qd);
            __m256 a0 =_mm256_loadu_ps(dists+ci);__m256 a1 =_mm256_loadu_ps(dists+ci+8);
            _mm256_storeu_ps(dists+ci,   _mm256_fmadd_ps(d0,d0,a0));
            _mm256_storeu_ps(dists+ci+8, _mm256_fmadd_ps(d1,d1,a1));
        }
        for (; ci<k; ci++) { float dd=cp[ci]-q[d]; dists[ci]+=dd*dd; }
    }
}

static void top_n(const float *dists, int k, int n, int *out) {
    float td[FULL_NPROBE]; int ti[FULL_NPROBE];
    for (int i=0;i<n;i++){td[i]=FLT_MAX;ti[i]=0;}
    for (int ci=0;ci<k;ci++) {
        float di=dists[ci];
        if (di>=td[n-1]) continue;
        int pos=n-1;
        while (pos>0 && di<td[pos-1]) pos--;
        for (int j=n-1;j>pos;j--){td[j]=td[j-1];ti[j]=ti[j-1];}
        td[pos]=di; ti[pos]=ci;
    }
    memcpy(out, ti, n*sizeof(int));
}

static void scan_cluster(
    const __m256 *qv,          
    uint32_t bs, uint32_t be,  
    float top5d[5], uint8_t top5l[5], int *wi)
{
    __m256 scale = _mm256_set1_ps(VECTOR_SCALE);

#define DIM_PAIR(D) { \
    const int16_t *row0=block+(D)*BLOCK_VECS; \
    const int16_t *row1=block+((D)+1)*BLOCK_VECS; \
    __m128i r0lo=_mm_loadu_si128((__m128i*)row0); \
    __m128i r0hi=_mm_loadu_si128((__m128i*)(row0+8)); \
    __m128i r1lo=_mm_loadu_si128((__m128i*)row1); \
    __m128i r1hi=_mm_loadu_si128((__m128i*)(row1+8)); \
    __m256 v0lo=_mm256_mul_ps(_mm256_cvtepi32_ps(_mm256_cvtepi16_epi32(r0lo)),scale); \
    __m256 v0hi=_mm256_mul_ps(_mm256_cvtepi32_ps(_mm256_cvtepi16_epi32(r0hi)),scale); \
    __m256 v1lo=_mm256_mul_ps(_mm256_cvtepi32_ps(_mm256_cvtepi16_epi32(r1lo)),scale); \
    __m256 v1hi=_mm256_mul_ps(_mm256_cvtepi32_ps(_mm256_cvtepi16_epi32(r1hi)),scale); \
    __m256 d0lo=_mm256_sub_ps(v0lo,qv[D]);     \
    __m256 d1lo=_mm256_sub_ps(v1lo,qv[(D)+1]); \
    __m256 d0hi=_mm256_sub_ps(v0hi,qv[D]);     \
    __m256 d1hi=_mm256_sub_ps(v1hi,qv[(D)+1]); \
    alo=_mm256_fmadd_ps(d0lo,d0lo,alo); \
    blo=_mm256_fmadd_ps(d1lo,d1lo,blo); \
    ahi=_mm256_fmadd_ps(d0hi,d0hi,ahi); \
    bhi=_mm256_fmadd_ps(d1hi,d1hi,bhi); \
}

    for (uint32_t bi=bs; bi<be; bi++) {
        if (bi+8<be) {
            const char *nxt=(const char*)(g_blocks+(bi+8)*(size_t)DIMS*BLOCK_VECS);
            __builtin_prefetch(nxt,     0, 0);
            __builtin_prefetch(nxt+ 64, 0, 0);
            __builtin_prefetch(nxt+128, 0, 0);
            __builtin_prefetch(nxt+192, 0, 0);
            __builtin_prefetch(nxt+256, 0, 0);
            __builtin_prefetch(nxt+320, 0, 0);
            __builtin_prefetch(nxt+384, 0, 0);
        }

        const int16_t *block=g_blocks+bi*(size_t)DIMS*BLOCK_VECS;
        __m256 thresh=_mm256_set1_ps(top5d[*wi]);

        __m256 alo=_mm256_setzero_ps(), blo=_mm256_setzero_ps();
        __m256 ahi=_mm256_setzero_ps(), bhi=_mm256_setzero_ps();

        DIM_PAIR(0); DIM_PAIR(2); DIM_PAIR(4); DIM_PAIR(6);

        __m256 plo=_mm256_add_ps(alo,blo);
        __m256 phi=_mm256_add_ps(ahi,bhi);
        if (!_mm256_movemask_ps(_mm256_cmp_ps(plo,thresh,_CMP_LT_OQ)) &&
            !_mm256_movemask_ps(_mm256_cmp_ps(phi,thresh,_CMP_LT_OQ))) continue;

        DIM_PAIR(8); DIM_PAIR(10); DIM_PAIR(12);

        __m256 acclo=_mm256_add_ps(alo,blo);
        __m256 acchi=_mm256_add_ps(ahi,bhi);
        int masklo=_mm256_movemask_ps(_mm256_cmp_ps(acclo,thresh,_CMP_LT_OQ));
        int maskhi=_mm256_movemask_ps(_mm256_cmp_ps(acchi,thresh,_CMP_LT_OQ));
        if (!masklo && !maskhi) continue;

        float dlo[8]; _mm256_storeu_ps(dlo,acclo);
        float dhi[8]; _mm256_storeu_ps(dhi,acchi);
        uint32_t lb=bi*BLOCK_VECS;

        while (masklo) {
            int s=__builtin_ctz(masklo); masklo&=masklo-1;
            float di=dlo[s];
            if (di<top5d[*wi]) {
                top5d[*wi]=di; top5l[*wi]=g_labels[lb+s];
                int nwi=0; float nwv=top5d[0];
                for (int j=1;j<5;j++) if(top5d[j]>nwv){nwv=top5d[j];nwi=j;}
                *wi=nwi;
            }
        }
        while (maskhi) {
            int s=__builtin_ctz(maskhi); maskhi&=maskhi-1;
            float di=dhi[s];
            if (di<top5d[*wi]) {
                top5d[*wi]=di; top5l[*wi]=g_labels[lb+8+s];
                int nwi=0; float nwv=top5d[0];
                for (int j=1;j<5;j++) if(top5d[j]>nwv){nwv=top5d[j];nwi=j;}
                *wi=nwi;
            }
        }
    }
#undef DIM_PAIR
}

static uint8_t knn5_search(const float *q) {
    compute_centroid_dists(q, g_ct, g_k, g_dists);

    int probes[FULL_NPROBE];
    top_n(g_dists, g_k, FULL_NPROBE, probes);

    __m256 qv[DIMS];
    for (int d=0;d<DIMS;d++) qv[d]=_mm256_set1_ps(q[d]);

    float top5d[5]={FLT_MAX,FLT_MAX,FLT_MAX,FLT_MAX,FLT_MAX};
    uint8_t top5l[5]={0};
    int wi=0;

    for (int pi=0; pi<FAST_NPROBE; pi++) {
        int ci=probes[pi];
        scan_cluster(qv, g_offsets[ci], g_offsets[ci+1], top5d, top5l, &wi);
    }
    uint8_t fc=0;
    for (int i=0;i<5;i++) fc+=top5l[i];

        if (fc>=1 && fc<=4) {
        for (int pi=FAST_NPROBE; pi<FULL_NPROBE; pi++) {
            int ci=probes[pi];
            scan_cluster(qv, g_offsets[ci], g_offsets[ci+1], top5d, top5l, &wi);
        }
        fc=0;
        for (int i=0;i<5;i++) fc+=top5l[i];
    }
    return fc;
}

static const char *process_fraud(const char *body, int len) {
    Payload px;
    if (!parse_json(body, len, &px)) return RESP_FRAUD[0];
    float q[DIMS];
    vectorize(&px, q);
    uint8_t fc = knn5_search(q);
    return RESP_FRAUD[fc < 6 ? fc : 5];
}

typedef enum {
    EV_CTRL_LISTENER = 1,
    EV_CTRL_CONN     = 2,
    EV_CLIENT        = 3,
} EvKind;

typedef struct EventTag {
    int kind;
} EventTag;

typedef struct Conn {
    int  kind;
    int  fd;
    int  head, tail;
    char buf[RX_BUF_SZ];
} Conn;

typedef struct CtrlConn {
    int kind;
    int fd;
} CtrlConn;

#define MAX_CTRL_CONNS 16

static Conn      conn_pool[MAX_CONNS];
static int       free_stk[MAX_CONNS];
static int       free_top;
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
    free_top = MAX_CONNS;
    for (int i=0;i<MAX_CONNS;i++){
        conn_pool[i].kind=EV_CLIENT;
        conn_pool[i].fd=-1;
        free_stk[i]=i;
    }
}
static Conn *conn_alloc(void) {
    if (!free_top) return NULL;
    Conn *c = &conn_pool[free_stk[--free_top]];
    c->kind = EV_CLIENT;
    return c;
}
static void conn_release(Conn *c) {
    c->fd=-1; c->head=c->tail=0;
    free_stk[free_top++]=(int)(c-conn_pool);
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
    for (int i=0;i<MAX_CTRL_CONNS;i++){
        ctrl_pool[i].kind=EV_CTRL_CONN;
        ctrl_pool[i].fd=-1;
        ctrl_free_stk[i]=i;
    }
}
static CtrlConn *ctrl_alloc(void) {
    if (!ctrl_free_top) return NULL;
    CtrlConn *c=&ctrl_pool[ctrl_free_stk[--ctrl_free_top]];
    c->kind=EV_CTRL_CONN;
    return c;
}
static void ctrl_close(CtrlConn *c, int efd) {
    if (c->fd >= 0) {
        epoll_ctl(efd, EPOLL_CTL_DEL, c->fd, NULL);
        close(c->fd);
    }
    c->fd=-1;
    ctrl_free_stk[ctrl_free_top++]=(int)(c-ctrl_pool);
}

static int parse_content_length(const char *buf, int hlen) {
    const char *key="content-length:";
    for (int i=0; i<=hlen-15; i++) {
        if ((buf[i]|32)!='c') continue;
        int ok=1;
        for (int j=1;j<15;j++) if ((buf[i+j]|32)!=key[j]){ok=0;break;}
        if (!ok) continue;
        int p=i+15;
        while (p<hlen&&(buf[p]==' '||buf[p]=='\t')) p++;
        int v=0;
        while (p<hlen&&buf[p]>='0'&&buf[p]<='9'){v=v*10+(buf[p]-'0');p++;}
        return v;
    }
    return 0;
}

static inline int path_eq(const char *rest, int rlen, const char *path, int plen) {
    if (rlen < plen+1) return 0;
    if (memcmp(rest,path,plen)!=0) return 0;
    char nx=rest[plen];
    return nx==' '||nx=='?';
}

static int handle_req(const char *buf, int len, struct iovec *iov) {
    if (len<16) return 0;
    const char *he=(const char*)memmem(buf,len,"\r\n\r\n",4);
    if (!he) return 0;
    int hlen=(int)(he-buf);

    if (memcmp(buf,"POST ",5)==0) {
        const char *rest=buf+5; int rlen=hlen-5;
        if (path_eq(rest,rlen,"/fraud-score",12)) {
            int cl=parse_content_length(buf,hlen);
            int body_start=hlen+4, body_end=body_start+cl;
            if (len<body_end) return 0;
            const char *resp=process_fraud(buf+body_start,cl);
            iov->iov_base=(void*)resp;
            iov->iov_len=RESP_FRAUD_LEN[0];
            for (int i=0;i<6;i++) if (resp==RESP_FRAUD[i]){iov->iov_len=RESP_FRAUD_LEN[i];break;}
            return body_end;
        }
        iov->iov_base=(void*)RESP_NOT_FOUND;
        iov->iov_len=sizeof(RESP_NOT_FOUND)-1;
        return hlen+4;
    }
    if (memcmp(buf,"GET ",4)==0) {
        const char *rest=buf+4; int rlen=hlen-4;
        if (path_eq(rest,rlen,"/ready",6)) {
            iov->iov_base=(void*)RESP_READY;
            iov->iov_len=sizeof(RESP_READY)-1;
            return hlen+4;
        }
        iov->iov_base=(void*)RESP_NOT_FOUND;
        iov->iov_len=sizeof(RESP_NOT_FOUND)-1;
        return hlen+4;
    }
    return -1;
}


static int send_iov_all(int fd, struct iovec *iov, int niov) {
    while (niov > 0) {
        ssize_t n = writev(fd, iov, niov);

        if (n > 0) {
            while (niov > 0 && n >= (ssize_t)iov[0].iov_len) {
                n -= (ssize_t)iov[0].iov_len;
                iov++;
                niov--;
            }
            if (niov > 0 && n > 0) {
                iov[0].iov_base = (char *)iov[0].iov_base + n;
                iov[0].iov_len -= (size_t)n;
            }
            continue;
        }

        if (n < 0 && errno == EINTR) continue;

        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return -1;

        return -1;
    }
    return 0;
}

static void handle_conn(Conn *c, int efd) {
    for (;;) {
        int space=RX_BUF_SZ-c->tail;
        if (space==0) {
            if (c->head==0){conn_close(c,efd);return;}
            int keep=c->tail-c->head;
            if(keep>0) memmove(c->buf,c->buf+c->head,keep);
            c->tail=keep; c->head=0; space=RX_BUF_SZ-c->tail;
        }
        int n=(int)recv(c->fd,c->buf+c->tail,space,MSG_DONTWAIT);
        if (n<0){if(errno==EAGAIN||errno==EWOULDBLOCK)break;conn_close(c,efd);return;}
        if (n==0){conn_close(c,efd);return;}
        c->tail+=n;
        if (n<space) break;
    }

    struct iovec iovs[MAX_IOVECS];
    int niov=0, bad=0;

    while (c->head<c->tail && niov<MAX_IOVECS) {
        struct iovec iv;
        int consumed=handle_req(c->buf+c->head, c->tail-c->head, &iv);
        if (consumed==0) break;
        if (consumed<0) {
            iovs[niov].iov_base=(void*)RESP_BAD_REQ;
            iovs[niov].iov_len=sizeof(RESP_BAD_REQ)-1;
            niov++; bad=1; break;
        }
        if (iv.iov_base == (void*)RESP_NOT_FOUND) bad=1;
        iovs[niov++]=iv;
        c->head+=consumed;
    }

    if (niov>0) {
        if (send_iov_all(c->fd, iovs, niov) < 0) {
            conn_close(c,efd);
            return;
        }
    }
    if (bad){conn_close(c,efd);return;}

    if (c->head==c->tail){c->head=c->tail=0;}
    else if (c->head>RX_BUF_SZ/2){
        int k=c->tail-c->head;
        memmove(c->buf,c->buf+c->head,k);
        c->tail=k; c->head=0;
    }
}

static Conn *register_client_fd(int fd, int efd) {
#ifndef RINHA_ASSUME_PASSED_FD_FLAGS
    set_fd_nonblock_cloexec(fd);
#endif

    Conn *nc = conn_alloc();
    if (!nc) {
        close(fd);
        return NULL;
    }

    nc->fd = fd;
    nc->head = nc->tail = 0;

    struct epoll_event ev = {
        .events = EPOLLIN | EPOLLRDHUP | EPOLLET,
        .data.ptr = nc
    };

    if (epoll_ctl(efd, EPOLL_CTL_ADD, fd, &ev) < 0) {
        close(fd);
        conn_release(nc);
        return NULL;
    }

    return nc;
}
static int recv_one_passed_fd(int sock) {
    char byte;
    struct iovec iov={.iov_base=&byte,.iov_len=1};
    union {
        char buf[CMSG_SPACE(sizeof(int))];
        struct cmsghdr align;
    } control;
    memset(&control,0,sizeof(control));

    struct msghdr msg;
    memset(&msg,0,sizeof(msg));
    msg.msg_iov=&iov;
    msg.msg_iovlen=1;
    msg.msg_control=control.buf;
    msg.msg_controllen=sizeof(control.buf);

    ssize_t n;
    for (;;) {
        n=recvmsg(sock,&msg,MSG_DONTWAIT|MSG_CMSG_CLOEXEC);
        if (n < 0 && errno == EINTR) continue;
        break;
    }
    if (n < 0) {
        if (errno==EAGAIN||errno==EWOULDBLOCK) return -2;
        return -1;
    }
    if (n == 0) return -1;

    for (struct cmsghdr *cmsg=CMSG_FIRSTHDR(&msg); cmsg; cmsg=CMSG_NXTHDR(&msg,cmsg)) {
        if (cmsg->cmsg_level==SOL_SOCKET && cmsg->cmsg_type==SCM_RIGHTS) {
            int fd=-1;
            memcpy(&fd,CMSG_DATA(cmsg),sizeof(fd));
            return fd;
        }
    }
    return -1;
}

static int drain_control_fds(CtrlConn *cc, int efd) {
    for (;;) {
        int fd = recv_one_passed_fd(cc->fd);

        if (fd == -2) {
            return 0;
        }

        if (fd < 0) {
            return -1;
        }

        Conn *nc = register_client_fd(fd, efd);

        if (!nc) {
            /*
             * register_client_fd already closes fd on failure.
             */
            continue;
        }

        /*
         * Não processa imediatamente.
         * Deixa o epoll acordar quando o socket do cliente estiver pronto.
         */
    }
}static void accept_control_loop(int ctrl_sfd, int efd) {
    for (;;) {
        int fd=accept4(ctrl_sfd,NULL,NULL,SOCK_NONBLOCK|SOCK_CLOEXEC);
        if (fd<0) {
            if (errno==EAGAIN||errno==EWOULDBLOCK) return;
            if (errno==EINTR) continue;
            return;
        }

        CtrlConn *cc=ctrl_alloc();
        if (!cc){close(fd);continue;}
        cc->fd=fd;
        struct epoll_event ev={
            .events=EPOLLIN|EPOLLRDHUP|EPOLLET,
            .data.ptr=cc
        };
        if (epoll_ctl(efd,EPOLL_CTL_ADD,fd,&ev)<0) {
            ctrl_close(cc,efd);
            continue;
        }
    }
}

static int make_parent_dir(const char *path) {
    char tmp[256];
    strncpy(tmp,path,sizeof(tmp)-1);
    tmp[sizeof(tmp)-1]='\0';
    char *sl=strrchr(tmp,'/');
    if (sl&&sl!=tmp){*sl='\0';mkdir(tmp,0777);}
    return 0;
}

static int listen_unix_seqpacket(const char *path) {
    unlink(path);
    make_parent_dir(path);

    int fd=socket(AF_UNIX,SOCK_SEQPACKET|SOCK_NONBLOCK|SOCK_CLOEXEC,0);
    if (fd<0){perror("socket ctrl");return -1;}

    struct sockaddr_un addr;
    memset(&addr,0,sizeof(addr));
    addr.sun_family=AF_UNIX;
    size_t plen = strlen(path);
    if (plen >= sizeof(addr.sun_path)) {
        fprintf(stderr, "control socket path too long: %s\n", path);
        close(fd);
        return -1;
    }
    memcpy(addr.sun_path,path,plen+1);

    if (bind(fd,(struct sockaddr*)&addr,sizeof(addr))<0){perror("bind ctrl");close(fd);return -1;}
    chmod(path,0666);
    if (listen(fd,64)<0){perror("listen ctrl");close(fd);return -1;}
    return fd;
}

static void event_loop(int ctrl_sfd, int efd) {
    struct epoll_event evs[128];
    for (;;) {
        int n=epoll_wait(efd,evs,128,-1);
        if (n<0) {
            if (errno==EINTR) continue;
            return;
        }
        for (int i=0;i<n;i++) {
            EventTag *tag=(EventTag*)evs[i].data.ptr;
            if (!tag) continue;

            if (tag->kind==EV_CTRL_LISTENER) {
                accept_control_loop(ctrl_sfd,efd);
                continue;
            }

            if (tag->kind==EV_CTRL_CONN) {
                CtrlConn *cc=(CtrlConn*)tag;
                if (evs[i].events&EPOLLIN) {
                    if (drain_control_fds(cc,efd)<0){ctrl_close(cc,efd);continue;}
                }
                if (evs[i].events&(EPOLLRDHUP|EPOLLHUP|EPOLLERR)){
                    ctrl_close(cc,efd);
                    continue;
                }
                continue;
            }

            Conn *c=(Conn*)tag;
            if (evs[i].events&(EPOLLRDHUP|EPOLLHUP|EPOLLERR)){conn_close(c,efd);continue;}
            if (evs[i].events&EPOLLIN) handle_conn(c,efd);
        }
    }
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    for (int i=0;i<6;i++) RESP_FRAUD_LEN[i]=strlen(RESP_FRAUD[i]);

    const char *sock  = getenv("RINHA_SOCK");       if(!sock)  sock="/run/sock/api.sock";
    const char *ipath = getenv("RINHA_INDEX_PATH"); if(!ipath) ipath="/app/data/index.ivf";

    load_index(ipath);

        {
        float dq[DIMS]={0};
        compute_centroid_dists(dq, g_ct, g_k, g_dists);
        uint32_t s = 0x9E3779B9u;
        for (int i=0;i<2000;i++) {
            float q[DIMS];
            for (int d=0;d<DIMS;d++) {
                s = s*1664525u + 1013904223u;
                q[d] = (float)(s & 0xFFFFu) * (1.0f/65535.0f);
            }
            knn5_search(q);
        }
    }

    char ctrl_sock[256];
    const char *ctrl_env = getenv("RINHA_CTRL_SOCK");
    if (ctrl_env && *ctrl_env) {
        strncpy(ctrl_sock, ctrl_env, sizeof(ctrl_sock)-1);
        ctrl_sock[sizeof(ctrl_sock)-1] = '\0';
    } else {
        snprintf(ctrl_sock, sizeof(ctrl_sock), "%s.ctrl", sock);
    }

    int ctrl_sfd=listen_unix_seqpacket(ctrl_sock);
    if (ctrl_sfd<0)return 1;

    int efd=epoll_create1(EPOLL_CLOEXEC);
    if (efd<0){perror("epoll_create1");return 1;}
    struct epoll_event ev={.events=EPOLLIN,.data.ptr=&ctrl_listener_tag};
    epoll_ctl(efd,EPOLL_CTL_ADD,ctrl_sfd,&ev);

    conn_pool_init();
    ctrl_pool_init();
    event_loop(ctrl_sfd,efd);
    return 0;
}
