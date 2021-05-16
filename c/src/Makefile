PROG = dht
SRCS = test/main2.c io.c crypto.c proto.c util.c bytes.c dht.c kbucket.c rtable.c
FLAGS = -D_POSIX_C_SOURCE=1
FLAGS += -pthread -lsodium
FLAGS += -Wall -pedantic -std=c99 \
	-Wshadow -Wpointer-arith -Wcast-qual -Wcast-align \
	-Wstrict-prototypes -Wmissing-prototypes -Wconversion

build: $(SRCS)
	$(CC) -g $(FLAGS) -o $(PROG).out $(SRCS)

clean:
	rm -f $(PROG).out
