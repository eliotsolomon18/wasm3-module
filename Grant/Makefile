# Kernel module name
obj-m += wasm.o

# Update the paths to the wasm3-kernel source files
WASM3_KERNEL_PATH := ../wasm3-kernel/source

wasm-objs := main.o \
              $(WASM3_KERNEL_PATH)/m3_api_libc.o \
              $(WASM3_KERNEL_PATH)/m3_compile.o \
              $(WASM3_KERNEL_PATH)/m3_api_meta_wasi.o \
              $(WASM3_KERNEL_PATH)/m3_api_tracer.o \
              $(WASM3_KERNEL_PATH)/m3_api_uvwasi.o \
              $(WASM3_KERNEL_PATH)/m3_api_wasi.o \
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
	clang -o test_loader test_loader.c

# Clean up generated files
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	$(MAKE) -C wasm clean
	rm -f test_loader
	rm -f wasm/prog.wasm
	rm -f wasm/prog.wasm.c

.PHONY: all clean
