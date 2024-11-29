# Specify the object files that comprise the kernel module.
obj-m += wasm.o
wasm-objs :=  main.o \
			  wasm3-kernel/source/m3_api_libc.o \
			  wasm3-kernel/source/m3_compile.o \
			  wasm3-kernel/source/m3_api_meta_wasi.o \
			  wasm3-kernel/source/m3_api_tracer.o \
			  wasm3-kernel/source/m3_api_uvwasi.o \
			  wasm3-kernel/source/m3_api_wasi.o \
			  wasm3-kernel/source/m3_bind.o \
			  wasm3-kernel/source/m3_code.o \
			  wasm3-kernel/source/m3_core.o \
			  wasm3-kernel/source/m3_env.o \
			  wasm3-kernel/source/m3_exec.o \
			  wasm3-kernel/source/m3_function.o \
			  wasm3-kernel/source/m3_info.o \
			  wasm3-kernel/source/m3_module.o \
			  wasm3-kernel/source/m3_parse.o

# Add wasm3-kernel to the compiler's include path.
ccflags-y += -I$(src)/wasm3-kernel/source/

# Save the current working directory.
PWD := $(CURDIR)

# Build the kernel module.
all: 
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules 

# Remove all files produced by the build process.
clean: 
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -f wasm3-kernel/source/*.o wasm3-kernel/source/.*.cmd