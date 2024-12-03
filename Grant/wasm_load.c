// wasm_load.c
#include <unistd.h>
#include <sys/syscall.h>
#include "wasm_load.h"

#ifndef __NR_wasm_load
#define __NR_wasm_load 333
#endif

long wasm_load(const char *buffer, size_t size) {
    return syscall(__NR_wasm_load, buffer, size);
}
