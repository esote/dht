#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "dht.h"
#include "dht_internal.h"
#include "listen.h"
#include "proto.h"
#include "session.h"
#include "util.h"

static int copy_config(struct dht *dht, const struct dht_config *config);
static int ignore_sigpipe(void);
static int spawn_listeners(struct dht *dht);
static int join_listeners(struct dht *dht, size_t i);
static void log_identity(const struct dht *dht);
static int bootstrap_response_update(struct dht *dht, const struct message *m);

struct dht *
dht_new(const struct dht_config *config)
{
	struct dht *dht;

	if ((dht = malloc(sizeof(*dht))) == NULL) {
		dht_log(LOG_CRIT, "%s", strerror(errno));
		return NULL;
	}

	if (copy_config(dht, config) == -1) {
		dht_log(LOG_CRIT, "%s", strerror(errno));
		free(dht);
		return NULL;
	}

	/* Create node identity */
	if (new_keypair(dht->id, dht->priv, dht->dyn_x) == -1) {
		dht_log(LOG_CRIT, "%s", strerror(errno));
		free(dht->addr);
		free(dht);
		return NULL;
	}

	if (ignore_sigpipe() == -1) {
		dht_log(LOG_CRIT, "%s", strerror(errno));
		free(dht->addr);
		free(dht);
		return NULL;
	}

	/* Initialize routing table */
	if (rtable_init(&dht->rtable, dht->id, ping_node, dht) == -1) {
		dht_log(LOG_CRIT, "%s", strerror(errno));
		free(dht->addr);
		free(dht);
		return NULL;
	}

	/* Begin listening for incoming requests */
	if (spawn_listeners(dht) == -1) {
		dht_log(LOG_CRIT, "%s", strerror(errno));
		(void)rtable_close(&dht->rtable);
		free(dht->addr);
		free(dht);
		return NULL;
	}

	log_identity(dht);

	return dht;
}

static int
copy_config(struct dht *dht, const struct dht_config *config)
{
	(void)memcpy(dht->network_id, config->network_id, NETWORK_ID_SIZE);

	if ((dht->addr = strdup(config->addr)) == NULL) {
		return -1;
	}

	dht->port = config->port;
	dht->storer = config->storer;

	return 0;
}

static int
ignore_sigpipe(void)
{
	struct sigaction act;

	(void)memset(&act, 0, sizeof(act));
	if (sigemptyset(&act.sa_mask) == -1) {
		return -1;
	}

	act.sa_handler = SIG_IGN;
	if (sigaction(SIGPIPE, &act, NULL) == -1) {
		return -1;
	}

	return 0;
}

static int
spawn_listeners(struct dht *dht)
{
	size_t i;

	if (sem_init(&dht->listen_exit, 0, 0) == -1) {
		return -1;
	}

	for (i = 0; i < LISTENER_COUNT; i++) {
		errno = pthread_create(&dht->listeners[i], NULL, listener_start,
			dht);
		if (errno != 0) {
			dht_log(LOG_ERR, "listen[%zu] %s", i, strerror(errno));
			(void)join_listeners(dht, i);
			(void)sem_destroy(&dht->listen_exit);
			return -1;
		}
	}

	return 0;
}

static int
join_listeners(struct dht *dht, size_t i)
{
	int ret;
	void *listen_ret;
	size_t j;

	ret = 0;

	for (j = 0; j < i; j++) {
		assert(sem_post(&dht->listen_exit) == 0);
	}

	for (j = 0; j < i; j++) {
		if ((errno = pthread_join(dht->listeners[j], &listen_ret)) != 0) {
			dht_log(LOG_ERR, "join[%zu] %s", j, strerror(errno));
			ret = -1;
		}

		if (listen_ret == NULL) {
			dht_log(LOG_ERR, "join[%zu] returned NULL", j);
			ret = -1;
		} else if (*(int *)listen_ret != 0) {
			dht_log(LOG_ERR, "join[%zu] returned %d", j, *(int *)listen_ret);
			ret = -1;
		}
	}

	return ret;
}

static void
log_identity(const struct dht *dht)
{
	char id[NODE_ID_SIZE*2 + 1];

	bin2hex(id, sizeof(id), dht->id, NODE_ID_SIZE);
	dht_log(LOG_INFO, "ID %s PORT %" PRIu16 " ADDR %s", id, dht->port,
		dht->addr);
}

int
dht_close(struct dht *dht)
{
	int ret = 0;

	if (join_listeners(dht, LISTENER_COUNT) == -1) {
		dht_log(LOG_CRIT, "%s", strerror(errno));
		ret = -1;
	}

	if (sem_destroy(&dht->listen_exit) == -1) {
		dht_log(LOG_CRIT, "%s", strerror(errno));
		ret = -1;
	}

	if (rtable_close(&dht->rtable) == -1) {
		dht_log(LOG_CRIT, "%s", strerror(errno));
		ret = -1;
	}

	free(dht->addr);
	free(dht);
	return ret;
}

int
dht_bootstrap(struct dht *dht, const uint8_t id[NODE_ID_SIZE],
	const uint8_t dyn_x[DYN_X_SIZE], const char *addr, uint16_t port)
{
	int afd;
	struct session s;
	union payload p;
	struct message *msg;

	if ((afd = connect_remote(addr, port)) == -1) {
		dht_log(LOG_ERR, "%s", strerror(errno));
		return -1;
	}

	session_init(&s, dht, id, afd);

	/* Find node request payload */
	p.fnode.count = K;
	(void)memcpy(p.fnode.target_id, dht->id, NODE_ID_SIZE);
	(void)memcpy(p.fnode.target_dyn_x, dht->dyn_x, DYN_X_SIZE);

	/* Send fnode request */
	if (session_send(&s, TYPE_FNODE, &p) == -1) {
		dht_log(LOG_ERR, "%s", strerror(errno));
		(void)close(afd);
		return -1;
	}

	if ((msg = session_recv(&s)) == NULL) {
		dht_log(LOG_ERR, "%s", strerror(errno));
		(void)close(afd);
		return -1;
	}
	if (msg->hdr.msg_type != TYPE_FNODE_RESP) {
		dht_log(LOG_ERR, "unexpected msg_type %"PRIu8, msg->hdr.msg_type);
		(void)message_close(msg);
		(void)close(afd);
		return -1;
	}

	if (bootstrap_response_update(dht, msg) == -1) {
		dht_log(LOG_ERR, "%s", strerror(errno));
		(void)message_close(msg);
		(void)close(afd);
		return -1;
	}

	if (message_close(msg) == -1) {
		dht_log(LOG_ERR, "%s", strerror(errno));
		(void)close(afd);
		return -1;
	}
	if (close(afd) == -1) {
		dht_log(LOG_ERR, "%s", strerror(errno));
		return -1;
	}

	return 0;
}

static int
bootstrap_response_update(struct dht *dht, const struct message *m)
{
	size_t i;

	if (dht_update(dht, &m->hdr.self) == -1) {
		return -1;
	}

	for (i = 0; i < m->payload.fnode_resp.count && i < K; i++) {
		if (dht_update(dht, &m->payload.fnode_resp.nodes[i]) == -1) {
			dht_log(LOG_ERR, "update[%zu] %s", i, strerror(errno));
			return -1;
		}
	}

	return 0;
}
