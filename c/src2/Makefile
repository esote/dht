PROG = dhtd
SRCS = bytes.c io.c ipc.c
FLAGS = -pthread -lsodium \
	-std=c99 -D _POSIX_C_SOURCE=200809L -pedantic -Wall -Wshadow \
	-Wpointer-arith -Wcast-qual -Wcast-align -Wstrict-prototypes \
	-Wmissing-prototypes -Wconversion

build: $(SRCS)
	$(CC) $(FLAGS) -o $(PROG).out $(SRCS)

DEBUG_FLAGS = $(FLAGS) -g

debug: $(SRCS)
	$(CC) $(DEBUG_FLAGS) -o $(PROG).out $(SRCS)

TEST_PROG = test
TEST_SRCS = $(SRCS) test/test.c test/ipc.c
TEST_FLAGS = $(DEBUG_FLAGS) -lcheck

.PHONY: test
test: $(TEST_SRCS)
	$(CC) $(TEST_FLAGS) -o $(TEST_PROG).out $(TEST_SRCS)

clean:
	rm -f $(PROG).out $(TEST_PROG).out
	rm -f vgcore.*
