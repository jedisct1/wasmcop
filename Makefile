# Built one at a time, otherwise the compilers end up in the runner and it gets slow to start.

LLVM_PREFIX := $(shell llvm-config-22 --prefix 2>/dev/null)
export LLVM_SYS_221_PREFIX ?= $(LLVM_PREFIX)

.PHONY: all test clean

all:
	cargo build --release -p wasmcop-runner
	cargo build --release -p wasmcop

test: all
	cargo test --release -p wasmcop-job -p wasmcop-spec
	cargo test --release -p wasmcop

clean:
	cargo clean
