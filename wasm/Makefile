CC = cc
CLANG = clang-18

# Default target
all: wasm-load prog.wasm prog-test.wasm

# Compile WASM bytecode
prog.wasm: prog.c
	$(CLANG) -target wasm32 -nostdlib -Wl,--no-entry -Wl,--export-all $< -o $@

prog-test.wasm: prog-test.c
	$(CLANG) -target wasm32 -nostdlib -Wl,--no-entry -Wl,--export-all $< -o $@

# Compile loader executable
wasm-load: wasm-load.c
	$(CC) $< -o $@

# Load rule
load: wasm-load prog.wasm
	./wasm-load prog.wasm

test: wasm-load prog-test.wasm
	./wasm-load prog-test.wasm

# Clean up compiled files
clean:
	rm -f wasm-load prog.wasm

.PHONY: all load clean test