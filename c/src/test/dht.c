#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../dht.h"
#include "../dht_internal.h"
#include "../storer.h"

static void
print_hex(uint8_t *b, size_t n)
{
	size_t i;
	for (i = 0; i < n; i++) {
		printf("%02X", b[i]);
	}
	printf("\n");
}

static void
from_hex(uint8_t *dst, const char *src, size_t n)
{
	size_t i;
	for (i = 0; i < n; i++) {
		sscanf(src, "%2hhx", &dst[i]);
		src += 2;
	}
}

int
main(int argc, char *argv[])
{
	if (argc < 3) {
		return 1;
	}

	struct dht_config config = {
		.network_id = {1},
	};

	config.addr = "localhost";
	config.port = (uint16_t)strtol(argv[2], NULL, 10);

	if ((config.storer = storer_new(argv[1], 1600, 1600)) == NULL) {
		return 2;
	}

	struct dht *dht = dht_new(&config);
	assert(dht != NULL);
	print_hex(dht->id, NODE_ID_SIZE);

	if (argc < 5) {
		for (;;) { pause(); }
	}

	uint16_t port = (uint16_t)strtol(argv[3], NULL, 10);

	uint8_t id[NODE_ID_SIZE];
	from_hex(id, argv[4], NODE_ID_SIZE);
	int ret = dht_bootstrap(dht, id, dht->dyn_x, dht->addr, port);
	assert(ret != -1);
	assert(dht_close(dht) != -1);
	assert(storer_free(config.storer) != -1);
	return 0;
}
