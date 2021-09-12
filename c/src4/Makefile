PROG = dhtd
SRCS = crypto.c crypto_sha3.c listen.c monitor.c proto.c util.c
FLAGS = -pthread -lsodium -pedantic -Wall -Wshadow -Wpointer-arith -Wcast-qual \
	-Wcast-align -Wstrict-prototypes -Wmissing-prototypes -Wconversion

build: $(PROG).c $(SRCS)
	$(CC) $(FLAGS) -o $(PROG).out $(PROG).c $(SRCS)

DEBUG_FLAGS = $(FLAGS) -g3 -gdwarf

debug: $(PROG).c $(SRCS)
	$(CC) $(DEBUG_FLAGS) -o $(PROG).out $(PROG).c $(SRCS)

TEST_PROG = dhtd_test
TEST_SRCS = $(SRCS) monitor_test.c
TEST_FLAGS = $(DEBUG_FLAGS) -D C1=2 -D C2=2 -lcheck

.PHONY: test
test: $(TEST_PROG).c $(TEST_SRCS)
	$(CC) $(TEST_FLAGS) -o $(TEST_PROG).out $(TEST_PROG).c $(TEST_SRCS)

clean:
	rm -f $(PROG).out $(TEST_PROG).out
	rm -f vgcore.*
