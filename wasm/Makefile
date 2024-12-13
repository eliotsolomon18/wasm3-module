CC = cc
CLANG = clang-18

# Default target
all: wasm-load prog.wasm

# Compile WASM bytecode
prog.wasm: prog.c walloc.c
	$(CLANG) -target wasm32 -nostdlib -Wl,--no-entry -Wl,--export-all $< walloc.c -o $@

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