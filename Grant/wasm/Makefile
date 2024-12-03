# wasm/Makefile

# Compiler and flags
CC = clang
CFLAGS = -target wasm32 -O3 -nostdlib \
         -Wl,--no-entry -Wl,--export-all -Wl,--allow-undefined \
         -Wl,--import-memory \
         -Wl,--initial-memory=131072 -Wl,--max-memory=131072

# Source files
SRCS = print_prog.c sum_prog.c

# Output WASM files
WASMS = print_prog.wasm sum_prog.wasm

# Default target
all: $(WASMS)

# Compile print_prog.wasm
print_prog.wasm: print_prog.c
	$(CC) $(CFLAGS) $< -o $@

# Compile sum_prog.wasm
sum_prog.wasm: sum_prog.c
	$(CC) $(CFLAGS) $< -o $@

# Clean target
clean:
	rm -f $(WASMS)

.PHONY: all clean
