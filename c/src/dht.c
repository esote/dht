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
#include "util.h"

static int dht_join_listeners(struct dht *dht, size_t i);

struct dht *
dht_new(const struct dht_config *config)
{
	struct dht *dht;
	struct sigaction act;
	size_t i;

	if ((dht = malloc(sizeof(*dht))) == NULL) {
		dht_log(LOG_CRIT, "%s", strerror(errno));
		return NULL;
	}

	/* Copy config */
	(void)memcpy(dht->network_id, config->network_id, NETWORK_ID_SIZE);
	if ((dht->addr = strdup(config->addr)) == NULL) {
		dht_log(LOG_CRIT, "%s", strerror(errno));
		free(dht);
		return NULL;
	}
	dht->port = config->port;
	dht->timeout = config->timeout;
	dht->storer = config->storer;

	/* Create node identity */
	if (new_keypair(dht->id, dht->priv, dht->dyn_x) == -1) {
		dht_log(LOG_CRIT, "%s", strerror(errno));
		free(dht->addr);
		free(dht);
		return NULL;
	}
	/* TODO: LOG_DEBUG id */

	/* Ignore SIGPIPE */
	(void)memset(&act, 0, sizeof(act));
	if (sigemptyset(&act.sa_mask) == -1) {
		dht_log(LOG_CRIT, "%s", strerror(errno));
		free(dht->addr);
		free(dht);
		return NULL;
	}
	act.sa_handler = SIG_IGN;
	if (sigaction(SIGPIPE, &act, NULL) == -1) {
		dht_log(LOG_CRIT, "%s", strerror(errno));
		free(dht->addr);
		free(dht);
		return NULL;
	}

	/* Initialize routing table */
	if ((dht->rtable = rtable_new(dht->id, K)) == NULL) {
		dht_log(LOG_CRIT, "%s", strerror(errno));
		free(dht->addr);
		free(dht);
		return NULL;
	}

	if (sem_init(&dht->listen_exit, 0, 0) == -1) {
		dht_log(LOG_CRIT, "%s", strerror(errno));
		(void)rtable_close(dht->rtable);
		free(dht->addr);
		free(dht);
		return NULL;
	}
	/* Begin listening for incoming requests */
	for (i = 0; i < LISTENER_COUNT; i++) {
		errno = pthread_create(&dht->listeners[i], NULL, listener_start,
			dht);
		if (errno != 0) {
			dht_log(LOG_CRIT, "listener[%zu] %s", i, strerror(errno));
			(void)dht_join_listeners(dht, i);
			(void)sem_destroy(&dht->listen_exit);
			(void)rtable_close(dht->rtable);
			free(dht->addr);
			free(dht);
			return NULL;
		}
	}

	return dht;
}

static int
dht_join_listeners(struct dht *dht, size_t i)
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

int
dht_bootstrap(struct dht *dht, const uint8_t id[NODE_ID_SIZE],
	const uint8_t dyn_x[DYN_X_SIZE], const char *addr, uint16_t port)
{
	uint8_t session_id[SESSION_ID_SIZE];
	struct node target;
	union payload p;
	struct message *msg;
	size_t i;
	int afd;

	/* Target node */
	(void)memcpy(target.id, id, NODE_ID_SIZE);
	(void)memcpy(target.dyn_x, dyn_x, DYN_X_SIZE);
	if ((target.addr = strdup(addr)) == NULL) {
		dht_log(LOG_ERR, "%s", strerror(errno));
		return -1;
	}
	target.port = port;

	/* Find node request payload */
	p.fnode.count = K;
	(void)memcpy(p.fnode.target_id, dht->id, NODE_ID_SIZE);
	(void)memcpy(p.fnode.target_dyn_x, dht->dyn_x, DYN_X_SIZE);

	if ((afd = connect_remote(addr, port)) == -1) {
		dht_log(LOG_ERR, "%s", strerror(errno));
		free(target.addr);
		return -1;
	}

	/* Send fnode request */
	crypto_rand(session_id, SESSION_ID_SIZE);
	if (send_message(dht, afd, TYPE_FNODE, session_id, &p, id) == -1) {
		dht_log(LOG_ERR, "%s", strerror(errno));
		(void)close(afd);
		free(target.addr);
		return -1;
	}

	/* Recv fnode_resp response */
	if ((msg = message_decode(afd, dht->id, dht->priv)) == NULL) {
		dht_log(LOG_ERR, "%s", strerror(errno));
		(void)close(afd);
		free(target.addr);
		return -1;
	}
	if (msg->hdr.msg_type != TYPE_FNODE_RESP) {
		dht_log(LOG_ERR, "unexpected msg_type %"PRIu8, msg->hdr.msg_type);
		(void)message_close(msg);
		(void)close(afd);
		free(target.addr);
		return -1;
	}
	if (memcmp(msg->hdr.session_id, session_id, SESSION_ID_SIZE) != 0) {
		dht_log(LOG_ERR, "unexpected session ID");
		(void)message_close(msg);
		(void)close(afd);
		free(target.addr);
		return -1;
	}

	/* Target node is alive, update rtable */
	if (dht_update(dht, &target) == -1) {
		dht_log(LOG_ERR, "%s", strerror(errno));
		(void)message_close(msg);
		(void)close(afd);
		free(target.addr);
		return -1;
	}

	/* Update rtable with nodes returned by target */
	for (i = 0; i < msg->payload.fnode_resp.count && i < K; i++) {
		if (dht_update(dht, &msg->payload.fnode_resp.nodes[i]) == -1) {
			dht_log(LOG_ERR, "update[%zu] %s", i, strerror(errno));
			(void)message_close(msg);
			(void)close(afd);
			free(target.addr);
			return -1;
		}
	}

	if (message_close(msg) == -1) {
		dht_log(LOG_ERR, "%s", strerror(errno));
		(void)close(afd);
		free(target.addr);
		return -1;
	}
	if (close(afd) == -1) {
		dht_log(LOG_ERR, "%s", strerror(errno));
		free(target.addr);
		return -1;
	}

	free(target.addr);
	return 0;
}

int
dht_close(struct dht *dht)
{
	int ret = 0;
	if (dht_join_listeners(dht, LISTENER_COUNT) == -1) {
		dht_log(LOG_CRIT, "%s", strerror(errno));
		ret = -1;
	}
	if (sem_destroy(&dht->listen_exit) == -1) {
		dht_log(LOG_CRIT, "%s", strerror(errno));
		ret = -1;
	}
	if (rtable_close(dht->rtable) == -1) {
		dht_log(LOG_CRIT, "%s", strerror(errno));
		ret = -1;
	}
	free(dht->addr);
	free(dht);
	return ret;
}
