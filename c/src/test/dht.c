#include <assert.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../dht.h"
#include "../dht_internal.h"
#include "../storer.h"
#include "../util.h"

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

	if (argc < 5) {
		sleep(60);
		assert(dht_close(dht) != -1);
		assert(storer_free(config.storer) != -1);
		return 0;
	}

	uint16_t port = (uint16_t)strtol(argv[3], NULL, 10);

	uint8_t id[NODE_ID_SIZE];
	assert(hex2bin(id, NODE_ID_SIZE, argv[4], strlen(argv[4])) != -1);
	int ret = dht_bootstrap(dht, id, dht->dyn_x, dht->addr, port);
	assert(ret != -1);
	assert(dht_close(dht) != -1);
	assert(storer_free(config.storer) != -1);
	return 0;
}
