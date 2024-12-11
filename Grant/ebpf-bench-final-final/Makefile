CC = clang
CLANG = clang
CFLAGS = -O2 -g -pthread -Wall -Werror
BPF_CFLAGS = -target bpf -D__TARGET_ARCH_x86 -O2 -g -Wall -Werror
LIBS = -lbpf -lelf

all: filter.o single

filter.o: filter.c
	$(CLANG) $(BPF_CFLAGS) -c -o $@ $<

single: single.c filter.o
	$(CC) $(CFLAGS) -o $@ single.c $(LIBS)

clean:
	rm -f filter.o single *.o

.PHONY: all clean
