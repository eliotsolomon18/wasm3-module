# Wasm3 Kernel Module

This repository contains a kernel module that runs a small WASM program in kernel space. It illustrates how to expose functions from the kernel module to the WASM program as well as how to pass a variable-length data structure from the module to the program. It also hooks into `netfilter` to invoke the WASM program in response to every IPv4 packet.

## Structure

- `main.c`
    - This is the kernel module itself.
- `Makefile`
    - This is a `Makefile` that can be used to build the kernel module.
- `wasm3-kernel/`
    - This is a submodule that points to a [fork](https://github.com/eliotsolomon18/wasm3-kernel) of the `wasm3` repository that has been modified to run in kernel space.
    - All the heavy lifting was done by [this fork](https://github.com/bonifaido/wasm3/tree/linux-kernel), but I merged in the latest changes from the [upstream repository](https://github.com/wasm3/wasm3).
- `wasm/`
    - This directory contains the WASM program as well as a program that can be used to load it into the kernel. A `Makefile` is provided to automate the process of building and loading the program.

## Build

```
$ make
```

## Install

```
$ sudo make install
```

## (Optional) Test the module
```
$ python3 test/run_test.py
```

## Load WASM program

```
$ sudo make load
```

## Uninstall

```
$ sudo make remove
```

## Check Output

```
$ sudo journalctl --since "1 hour ago" | grep kernel
```

## Clean up

```
$ make clean
```

## Resources

- https://sysprog21.github.io/lkmpg/
- https://danielmangum.com/posts/wasm-wasi-clang-17/
- https://radu-matei.com/blog/practical-guide-to-wasm-memory/
- https://www.reddit.com/r/cpp_questions/comments/1dlps19/wasm_memory_allocation/
- https://surma.dev/things/c-to-webassembly/
- https://developer.mozilla.org/en-US/docs/WebAssembly/Reference/Memory
- https://github.com/cisco-open/camblet-driver
- https://docs.kernel.org/locking/spinlocks.html
- https://olegkutkov.me/2018/03/14/simple-linux-character-device-driver/
- https://unix.stackexchange.com/questions/724686/what-is-the-modern-way-of-creating-devices-files-in-dev
- https://embetronicx.com/tutorials/linux/device-drivers/device-file-creation-for-character-drivers/
- https://kel.bz/post/netfilter/
- https://wiki.linuxfoundation.org/networking/sk_buff
- https://utcc.utoronto.ca/~cks/space/blog/linux/CPUNumbersNotContiguous
- https://lwn.net/Articles/2220/
- https://stackoverflow.com/questions/57983653/nr-cpu-ids-vs-nr-cpus-in-linux-kernel