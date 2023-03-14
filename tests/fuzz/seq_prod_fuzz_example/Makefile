CC = clang
CFLAGS = -g -fno-omit-frame-pointer -fsanitize=undefined,address,fuzzer -I../ -I../../../lib/

.PHONY: default
default: example_seq_prod.o

example_seq_prod.o: example_seq_prod.c
	$(CC) -c $(CFLAGS) $^ -o $@
