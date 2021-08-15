#include "proto.h"

int
encode_message(struct dht *dht, int out, const struct message *msg)
{
	
}

static int
encode_header(int out, const struct header *hdr)
{
	uint8_t buf[HEADER_SIZE(UINT8_MAX)];
}
