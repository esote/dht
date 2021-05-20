PROG = dht

SRCS = test/main2.c
SRCS += dht.c
SRCS += io.c crypto.c proto.c util.c bytes.c kbucket.c rtable.c storer.c listen.c crypto_sha3.c

FLAGS = -D_POSIX_C_SOURCE=1
FLAGS += -pthread -lsodium
FLAGS += -Wall -pedantic -std=c99 \
	-Wshadow -Wpointer-arith -Wcast-qual -Wcast-align \
	-Wstrict-prototypes -Wmissing-prototypes -Wconversion

build: $(SRCS)
	$(CC) -g $(FLAGS) -o $(PROG).out $(SRCS)

clean:
	rm -f $(PROG).out
