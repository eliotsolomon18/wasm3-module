#include <stdint.h>

#define PAGE_SIZE (64 * 1024)
#define PAGES_TO_BYTES(p) (p * PAGE_SIZE)
#define BYTES_TO_PAGES(b) ((b + PAGE_SIZE - 1) / PAGE_SIZE * PAGE_SIZE)

extern unsigned char __heap_base;

int32_t print_int(int32_t i) __attribute__((
    __import_module__("custom"),
    __import_name__("print_int")
));

uint64_t data_size = 0;

void *
alloc(uint64_t size)
{
    data_size = size;
    if ((uint64_t)&__heap_base + size >= PAGES_TO_BYTES(__builtin_wasm_memory_size(0))) {
        __builtin_wasm_memory_grow(0, BYTES_TO_PAGES(PAGES_TO_BYTES(__builtin_wasm_memory_size(0)) - ((uint64_t)&__heap_base + size)));
    }
    return &__heap_base;
}

int32_t
sum(void)
{
    int32_t *data = (int32_t *)&__heap_base;

    int32_t sum = 0;
    for (int i = 0; i < data_size / sizeof(int32_t); i++) {
        print_int(i);
        sum += data[i];
    }

    return sum;
}