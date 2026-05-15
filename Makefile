CC = gcc
BUILD_DIR ?= build

HASWELL_FLAGS ?= -O3 -march=haswell
AVX_FLAGS ?= $(HASWELL_FLAGS) -mavx2 -mfma
API_DEFS ?= -DRINHA_ASSUME_PASSED_FD_FLAGS

.PHONY: all bench bench-json-parser bench-index-search bench-index-builder bench-lb bench-smoke clean

all: $(BUILD_DIR)/canjica $(BUILD_DIR)/carro-da-pamonha $(BUILD_DIR)/build_ivf

bench: \
	$(BUILD_DIR)/bench-json-parser \
	$(BUILD_DIR)/bench-index-search \
	$(BUILD_DIR)/bench-index-builder \
	$(BUILD_DIR)/bench-lb

bench-json-parser: $(BUILD_DIR)/bench-json-parser

bench-index-search: $(BUILD_DIR)/bench-index-search

bench-index-builder: $(BUILD_DIR)/bench-index-builder

bench-lb: $(BUILD_DIR)/bench-lb

$(BUILD_DIR):
	mkdir -p $@

$(BUILD_DIR)/canjica: src_c/api.c | $(BUILD_DIR)
	$(CC) $(AVX_FLAGS) $(API_DEFS) -o $@ $< -lm

$(BUILD_DIR)/carro-da-pamonha: src_c/lb.c | $(BUILD_DIR)
	$(CC) $(HASWELL_FLAGS) -o $@ $<

$(BUILD_DIR)/build_ivf: src_c/build_ivf.c | $(BUILD_DIR)
	$(CC) $(AVX_FLAGS) -pthread -o $@ $< -lz -lm -lpthread

$(BUILD_DIR)/bench-json-parser: src_c/bench/bench_json_parser.c src_c/bench/bench_common.h src_c/api.c | $(BUILD_DIR)
	$(CC) $(AVX_FLAGS) $(API_DEFS) -o $@ $< -lm

$(BUILD_DIR)/bench-index-search: src_c/bench/bench_index_search.c src_c/bench/bench_common.h src_c/api.c | $(BUILD_DIR)
	$(CC) $(AVX_FLAGS) $(API_DEFS) -o $@ $< -lm

$(BUILD_DIR)/bench-index-builder: src_c/bench/bench_index_builder.c src_c/bench/bench_common.h src_c/build_ivf.c | $(BUILD_DIR)
	$(CC) $(AVX_FLAGS) -pthread -o $@ $< -lz -lm -lpthread

$(BUILD_DIR)/bench-lb: src_c/bench/bench_lb.c src_c/bench/bench_common.h src_c/lb.c | $(BUILD_DIR)
	$(CC) $(HASWELL_FLAGS) -o $@ $<

$(BUILD_DIR)/example-index.ivf: $(BUILD_DIR)/bench-index-builder resources/example-references.json | $(BUILD_DIR)
	$(BUILD_DIR)/bench-index-builder resources/example-references.json 16 1 $@

bench-smoke: bench $(BUILD_DIR)/example-index.ivf
	$(BUILD_DIR)/bench-json-parser resources/example-payloads.json 100 1
	$(BUILD_DIR)/bench-lb 1000000 2
	$(BUILD_DIR)/bench-index-search $(BUILD_DIR)/example-index.ivf resources/example-payloads.json 10

clean:
	rm -rf $(BUILD_DIR)
