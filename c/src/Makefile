PROG = dht
SRCS = test/dht.c
SRCS += bucket.c bytes.c crypto.c crypto_sha3.c crypto_stream.c dht.c \
	dht_internal.c io.c listen.c proto.c rtable.c session.c storer.c util.c
FLAGS = -pthread -lsodium \
	-pedantic -Wall -Wshadow -Wpointer-arith -Wcast-qual -Wcast-align \
	-Wstrict-prototypes -Wmissing-prototypes -Wconversion
BUILD_FLAGS = -O2
DEBUG_FLAGS = -fsanitize=thread -fPIE -pie -g

build: $(SRCS)
	$(CC) $(FLAGS) $(BUILD_FLAGS) -o $(PROG).out $(SRCS)

debug: $(SRCS)
	$(CC) $(FLAGS) $(DEBUG_FLAGS) -DC1=2 -DC2=3 -o $(PROG).out $(SRCS)

clean:
	rm -f $(PROG).out
	rm -f vgcore.*
