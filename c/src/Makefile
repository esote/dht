PROG = dht

SRCS = test/dht.c
SRCS += dht.c
SRCS += io.c crypto.c proto.c util.c bytes.c kbucket.c rtable.c storer.c listen.c crypto_sha3.c dht_internal.c crypto_stream.c

FLAGS = -pedantic #-D_POSIX_C_SOURCE=1 -std=c99
FLAGS += -pthread -lsodium
FLAGS += -Wall \
	-Wshadow -Wpointer-arith -Wcast-qual -Wcast-align \
	-Wstrict-prototypes -Wmissing-prototypes -Wconversion

build: $(SRCS)
	$(CC) -g $(FLAGS) -o $(PROG).out $(SRCS)

valgrind: $(PROG).out
	valgrind --child-silent-after-fork=yes ./$(PROG).out $(ARGS)

clean:
	rm -f $(PROG).out
	rm -f vgcore.*
