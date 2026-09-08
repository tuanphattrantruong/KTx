# KTx prototype build (DESIGN §11).
# Package 1 owns this file; the bench rules below are for package 2's
# sources (src/bench/*.c) and need no edits at integration time.

CC      = clang
CFLAGS  = -O2 -std=c11 -Wall -Wextra -pthread -Isrc/include
LDFLAGS = -pthread

CORE_OBJS = build/decode.o build/vm.o build/loader.o \
            build/map.o build/log.o build/commit.o build/helpers.o \
            build/twopl.o build/jit.o

HDRS = src/include/ktx.h src/include/ktx_format.h src/ktx/ktx_internal.h

.PHONY: core bench all test semantic-check clean

core: bin/ktxmicro bin/ktxser bin/test_vm bin/test_ktx bin/test_jit

bench: bin/ktxbench bin/ktxtorn bin/ktxpolicy bin/ktxengine bin/ktxobserver

all: core bench

test: core
	./bin/test_vm && ./bin/test_ktx && ./bin/test_jit

semantic-check:
	python3 experiments/run_e22_semantic_checker.py

clean:
	rm -rf bin build

# --- objects ---

build/decode.o: src/vm/decode.c $(HDRS)
	@mkdir -p build
	$(CC) $(CFLAGS) -c src/vm/decode.c -o $@

build/vm.o: src/vm/vm.c src/vm/vm_core.inc $(HDRS)
	@mkdir -p build
	$(CC) $(CFLAGS) -c src/vm/vm.c -o $@

build/loader.o: src/vm/loader.c $(HDRS)
	@mkdir -p build
	$(CC) $(CFLAGS) -c src/vm/loader.c -o $@

build/map.o: src/ktx/map.c $(HDRS)
	@mkdir -p build
	$(CC) $(CFLAGS) -c src/ktx/map.c -o $@

build/log.o: src/ktx/log.c $(HDRS)
	@mkdir -p build
	$(CC) $(CFLAGS) -c src/ktx/log.c -o $@

build/commit.o: src/ktx/commit.c $(HDRS)
	@mkdir -p build
	$(CC) $(CFLAGS) -c src/ktx/commit.c -o $@

build/helpers.o: src/ktx/helpers.c $(HDRS)
	@mkdir -p build
	$(CC) $(CFLAGS) -c src/ktx/helpers.c -o $@

build/twopl.o: src/ktx/twopl.c $(HDRS)
	@mkdir -p build
	$(CC) $(CFLAGS) -c src/ktx/twopl.c -o $@

build/jit.o: src/jit/jit_arm64.c src/jit/jit.h $(HDRS)
	@mkdir -p build
	$(CC) $(CFLAGS) -Isrc/ktx -c src/jit/jit_arm64.c -o $@

# --- package-1 binaries ---

bin/ktxmicro: src/ktx/micro.c $(CORE_OBJS) $(HDRS)
	@mkdir -p bin
	$(CC) $(CFLAGS) src/ktx/micro.c $(CORE_OBJS) $(LDFLAGS) -o $@

bin/ktxser: src/ktx/ser.c $(CORE_OBJS) $(HDRS)
	@mkdir -p bin
	$(CC) $(CFLAGS) -Isrc/ktx src/ktx/ser.c $(CORE_OBJS) $(LDFLAGS) -lm -o $@

bin/test_jit: src/tests/test_jit.c $(CORE_OBJS) $(HDRS) src/jit/jit.h
	@mkdir -p bin
	$(CC) $(CFLAGS) -Isrc/ktx -Isrc/jit src/tests/test_jit.c $(CORE_OBJS) $(LDFLAGS) -o $@

bin/test_vm: src/tests/test_vm.c $(CORE_OBJS) $(HDRS)
	@mkdir -p bin
	$(CC) $(CFLAGS) src/tests/test_vm.c $(CORE_OBJS) $(LDFLAGS) -o $@

bin/test_ktx: src/tests/test_ktx.c $(CORE_OBJS) $(HDRS)
	@mkdir -p bin
	$(CC) $(CFLAGS) src/tests/test_ktx.c $(CORE_OBJS) $(LDFLAGS) -o $@

# --- package-2 binaries (sources owned by package 2) ---

bin/ktxbench: src/bench/bench.c src/bench/trace.h $(CORE_OBJS) $(HDRS)
	@mkdir -p bin
	$(CC) $(CFLAGS) src/bench/bench.c $(CORE_OBJS) $(LDFLAGS) -o $@

# UBPF_DIR/UBPF_LIB, when set, add an external-runtime arm to E13.
UBPF_FLAGS =
ifdef UBPF_DIR
UBPF_FLAGS = -DKTX_WITH_UBPF -I$(UBPF_DIR)/vm/inc -I$(UBPF_DIR)/vm $(UBPF_LIB)
endif

bin/ktxengine: src/bench/engine.c src/bench/trace.h $(CORE_OBJS) $(HDRS)
	@mkdir -p bin
	$(CC) $(CFLAGS) $(UBPF_FLAGS) src/bench/engine.c $(CORE_OBJS) $(LDFLAGS) -o $@

bin/ktxpolicy: src/bench/policy.c src/bench/trace.h $(CORE_OBJS) $(HDRS)
	@mkdir -p bin
	$(CC) $(CFLAGS) src/bench/policy.c $(CORE_OBJS) $(LDFLAGS) -o $@

bin/ktxtorn: src/bench/torn.c src/bench/trace.h $(CORE_OBJS) $(HDRS)
	@mkdir -p bin
	$(CC) $(CFLAGS) src/bench/torn.c $(CORE_OBJS) $(LDFLAGS) -o $@

bin/ktxobserver: src/bench/observer.c $(CORE_OBJS) $(HDRS)
	@mkdir -p bin
	$(CC) $(CFLAGS) -Isrc/ktx src/bench/observer.c $(CORE_OBJS) $(LDFLAGS) -o $@
