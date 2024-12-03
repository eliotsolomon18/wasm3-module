// sum_prog.c

#include <stdint.h>

// Import the print_int function from module "custom"
__attribute__((import_module("custom"), import_name("print_int")))
extern void print_int(int32_t x);

// Declare the __heap_base symbol provided by the linker
extern uint32_t __heap_base;

// Heap management variables
uint32_t heap_base = 0;
uint32_t heap_top = 0;

// Exported alloc function
__attribute__((export_name("alloc")))
uint32_t alloc(uint32_t n) {
    // Initialize heap_base if it's not set
    if (heap_base == 0) {
        heap_base = __heap_base;
        // Align heap_base to 8 bytes
        heap_base = (heap_base + 7) & ~7;
        heap_top = heap_base;
    }

    uint32_t addr = heap_top;
    heap_top += n;

    // Note: Memory growth is not handled here for simplicity

    return addr;
}

// Exported sum function
__attribute__((export_name("sum")))
uint32_t sum(uint32_t array_ptr, uint32_t size) {
    uint32_t total = 0;

    // Access the array in WASM memory using the array_ptr
    for (uint32_t i = 0; i < size; i++) {
        // Calculate the memory offset
        uint32_t offset = array_ptr + i * sizeof(int32_t);
        // Read the integer value from memory
        int32_t value = *((int32_t*)offset);
        // Call the imported print_int function
        print_int(value);
        // Accumulate the total
        total += value;
    }

    return total;
}
