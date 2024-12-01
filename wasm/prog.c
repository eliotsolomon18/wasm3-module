#include <stdint.h>

#define DROP_PORT 20080

// Convert between WASM pages and bytes
#define PAGE_SIZE (64 * 1024)
#define PAGES_TO_BYTES(p) (p * PAGE_SIZE)
#define BYTES_TO_PAGES(b) ((b + PAGE_SIZE - 1) / PAGE_SIZE * PAGE_SIZE)

// Linker-provided symbol that represents the base of the heap.
extern unsigned char __heap_base;

// Prototype for print_int() function exposed by the runtime.
int32_t print_int(int32_t i) __attribute__((
    __import_module__("custom"),
    __import_name__("print_int")
));

// Stores the size of the requested allocation.
uint64_t data_size = 0;

/*
 * Called by the runtime to dynamically allocate a single piece of memory.
 */
void *
alloc(uint64_t size)
{
    // Store the allocation size.
    data_size = size;

    // Grow the WASM program's linear memory if it is not big enough to fit the allocation.
    if ((uint64_t)&__heap_base + size >= PAGES_TO_BYTES(__builtin_wasm_memory_size(0))) {
        __builtin_wasm_memory_grow(0, BYTES_TO_PAGES(PAGES_TO_BYTES(__builtin_wasm_memory_size(0)) - ((uint64_t)&__heap_base + size)));
    }

    // Return a pointer to the base of the heap.
    return &__heap_base;
}

/*
 * Called by the runtime to sum up an array of integers.
 */
int32_t
sum(void)
{
    // Form a pointer to the array.
    int32_t *data = (int32_t *)&__heap_base;

    // Compute the sum.
    int32_t sum = 0;
    for (int i = 0; i < data_size / sizeof(int32_t); i++) {
        print_int(i);
        sum += data[i];
    }

    // Return the sum.
    return sum;
}

/**
 * Dummy function that does nothing but return NF_DROP.
 */
uint64_t nf_filter(void) {
    return 0;
}
