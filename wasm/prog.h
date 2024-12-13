#ifndef PROG_H
#define PROG_H

#include <stdint.h>
#include <stddef.h>

#include "../packet.h"

// Prototype for print_int() function exposed by the runtime.
int32_t print_int(int32_t i) __attribute__((
    __import_module__("custom"),
    __import_name__("print_int")
));

void *malloc(size_t size);
void free(void *p);

// Stores a pointer to the requested allocation.
struct packet_header *header = NULL;

// Stores the size of the requested allocation.
uint64_t header_size = 0;

/*
 * Called by the runtime to dynamically allocate a single piece of memory.
 */
void *
alloc(uint64_t size)
{
    if (header) {
        if (size > header_size) {
            free(header);
            header = malloc(size);
            header_size = size;
        }
    } else {
        header = malloc(size);
        header_size = size;
    }
    return header;
}

#endif