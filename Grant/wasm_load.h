// wasm_load.h
#ifndef WASM_LOAD_H
#define WASM_LOAD_H

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stddef.h>
#endif

long wasm_load(const char *buffer, size_t size);

#endif // WASM_LOAD_H
