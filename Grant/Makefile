# Makefile

# Kernel module name
obj-m += wasm.o

# Paths to Wasm3 kernel source files (update as necessary)
WASM3_KERNEL_PATH := ../wasm3-kernel/source

# Object files for the kernel module
wasm-objs := main.o \
             $(WASM3_KERNEL_PATH)/m3_api_libc.o \
             $(WASM3_KERNEL_PATH)/m3_compile.o \
             $(WASM3_KERNEL_PATH)/m3_api_tracer.o \
             $(WASM3_KERNEL_PATH)/m3_bind.o \
             $(WASM3_KERNEL_PATH)/m3_code.o \
             $(WASM3_KERNEL_PATH)/m3_core.o \
             $(WASM3_KERNEL_PATH)/m3_env.o \
             $(WASM3_KERNEL_PATH)/m3_exec.o \
             $(WASM3_KERNEL_PATH)/m3_function.o \
             $(WASM3_KERNEL_PATH)/m3_info.o \
             $(WASM3_KERNEL_PATH)/m3_module.o \
             $(WASM3_KERNEL_PATH)/m3_parse.o

# Include paths
ccflags-y += -I$(PWD)/../wasm3-kernel/source/

# Save the current working directory
PWD := $(shell pwd)

# Kernel build directory
KDIR := /lib/modules/$(shell uname -r)/build

# Default target
all:
	$(MAKE) -C wasm
	$(MAKE) -C $(KDIR) M=$(PWD) modules
	clang -o test_print_loader test_print_loader.c
	clang -o test_sum_loader test_sum_loader.c

# Clean up generated files
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	$(MAKE) -C wasm clean
	rm -f test_print_loader test_sum_loader

.PHONY: all clean
