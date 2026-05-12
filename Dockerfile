FROM --platform=linux/amd64 debian:bookworm-slim AS builder
WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libc-dev zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

COPY src_c ./src_c
COPY resources ./resources

RUN gcc -O3 -march=haswell -mavx2 -mfma -pthread \
    -o build_ivf src_c/build_ivf.c -lz -lm -lpthread

RUN gcc -O3 -march=haswell -mavx2 -mfma \
    -o canjica src_c/api.c -lm

RUN gcc -O3 -march=haswell \
    -o carro-da-pamonha src_c/lb.c

RUN mkdir -p /out && \
    ./build_ivf resources/references.json.gz /out/index.ivf 4096

FROM debian:bookworm-slim AS runtime
WORKDIR /app

COPY --from=builder /build/canjica /usr/local/bin/canjica
COPY --from=builder /build/canjica /usr/local/bin/pamonha
COPY --from=builder /build/carro-da-pamonha  /usr/local/bin/carro-da-pamonha
COPY --from=builder /out/index.ivf   /app/data/index.ivf
COPY resources/mcc_risk.json         /app/resources/mcc_risk.json

ENV RINHA_SOCK=/run/sock/api.sock
ENV RINHA_INDEX_PATH=/app/data/index.ivf

EXPOSE 8080
CMD ["/usr/local/bin/canjica"]
