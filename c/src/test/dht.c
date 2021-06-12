#include <assert.h>
#include <string.h>
#include "../dht.h"
#include "../dht_internal.h"
#include "../storer.h"
#include <unistd.h>

int
main(int argc, char *argv[])
{
	struct dht_config config = {
		.network_id = {1},
		.port = 8080,
		.timeout = 3600
	};
	struct in6_addr ip;
	(void)memcpy(ip.s6_addr, in6addr_loopback.s6_addr, sizeof(ip.s6_addr));
	config.ip = &ip;
	if ((config.storer = storer_new("/tmp/dht", 1600, 1600)) == NULL) {
		return 1;
	}
	struct dht *dht = dht_new(&config);
	assert(dht != NULL);
	int ret = dht_bootstrap(dht, dht->id, &dht->ip, dht->port);
	sleep(100000);
}
