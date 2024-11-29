# Compiler and flags
CC = clang-18
CFLAGS = -target wasm32 -nostdlib
LDFLAGS = -Wl,--no-entry -Wl,--export-all

# Files
SRC = two.c
WASM = two.wasm
WASM_C = $(WASM).c

# Default target
all: $(WASM_C)

# Compile WebAssembly file
$(WASM): $(SRC)
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@

# Generate C representation of the WebAssembly file
$(WASM_C): $(WASM)
	xxd -i $< > $@

# Clean up generated files
clean:
	rm -f $(WASM) $(WASM_C)

.PHONY: all clean