#ifndef DHT_H
#define DHT_H

#define K 20

struct dht;

struct dht_config {
	/* TODO */
	void *x;
};

struct dht *dht_new(const struct dht_config *config);

#endif /* DHT_H */
