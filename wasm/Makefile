CC = cc
CLANG = clang

# Default target
all: wasm-load prog.wasm

# Compile WASM bytecode
prog.wasm: prog.c
	$(CLANG) -target wasm32 -nostdlib -Wl,--no-entry -Wl,--export-all $< -o $@

# Compile loader executable
wasm-load: wasm-load.c
	$(CC) $< -o $@

# Load rule
load: wasm-load prog.wasm
	./wasm-load prog.wasm

# Clean up compiled files
clean:
	rm -f wasm-load prog.wasm

.PHONY: all load clean