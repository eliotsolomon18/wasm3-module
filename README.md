# Wasm3 Kernel Module

This repository contains a kernel module that sets up the wasm runtime in the kernel space. A userspace wasm program can then be loaded into the wasm runtime. The runtime will look for a function called `nf_filter` in the userspace program and attempt to hook into netfilter.

The `wasm/` directory contains an example program which simply drops all packets.

## Structure

- `main.c`
    - This is the kernel module itself.
- `Makefile`
    - This is a `Makefile` that can be used to build the kernel module.
- `wasm3-kernel/`
    - This is a submodule that points to a [fork](https://github.com/eliotsolomon18/wasm3-kernel) of the `wasm3` repository that has been modified to run in kernel space.
    - All the heavy lifting was done by [this fork](https://github.com/bonifaido/wasm3/tree/linux-kernel), but I merged in the latest changes from the [upstream repository](https://github.com/wasm3/wasm3).
- `wasm/`
    - This directory contains the WASM program as well as a `Makefile` to compile it and convert its binary form to a C array suitable for inclusion in the kernel module.

## Build

```
$ make
```
## Load module and create dev file
```
$ make load
```

## Compile userspace wasm loader
```
$ gcc -o loader wasm/loader.c
```

## Verify that the module has been loaded successfully
```
$ sudo dmesg
```

## Load the userspace program
```
$ ./loader
```

## Unload the kernel and remove the filter
```
$ make unload
```


## Resources

- https://sysprog21.github.io/lkmpg/
- https://danielmangum.com/posts/wasm-wasi-clang-17/
- https://radu-matei.com/blog/practical-guide-to-wasm-memory/
- https://www.reddit.com/r/cpp_questions/comments/1dlps19/wasm_memory_allocation/
- https://surma.dev/things/c-to-webassembly/
- https://developer.mozilla.org/en-US/docs/WebAssembly/Reference/Memory
- https://github.com/cisco-open/camblet-driver
- https://www.apriorit.com/dev-blog/195-simple-driver-for-linux-os