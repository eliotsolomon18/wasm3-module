# wasm/Makefile

# Compiler and flags
CC = clang
CFLAGS = -target wasm32 -O3 -nostdlib -nodefaultlibs
LDFLAGS = -Wl,--no-entry \
          -Wl,--export-all \
          -Wl,--allow-undefined \
          -Wl,--export=__heap_base \
          -Wl,--initial-memory=131072

# Files
SRC = prog.c
WASM = prog.wasm
WASM_C = prog.wasm.c

# Default target
all: $(WASM_C)

# Compile WebAssembly file
$(WASM): $(SRC)
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@

# Generate C representation of the WebAssembly file
$(WASM_C): $(WASM)
	xxd -i $< > $@
	sed -i -E 's/unsigned char [a-z_]+\[\]/const uint8_t wasm_code[]/' $@
	sed -i -E 's/unsigned int [a-z_]+_len/const uint32_t wasm_size/' $@

# Clean up generated files
clean:
	rm -f $(WASM) $(WASM_C) prog.o

.PHONY: all clean
