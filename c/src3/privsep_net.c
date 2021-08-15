#include "privsep_net.h"

// Child: request parent to sign hdr.
int
privsep_net_child_encode(const struct network_child *child, const struct header *hdr)
{
	if (write_header_no_
}

static int
encode_request(const struct network_child *child, const struct header *hdr)
{
	uint8_t buf[HEADER_SIZE(UINT8_MAX) - sizeof(hdr->sig)];
	uint8_t *b;
	ssize_t n;

	b = buf;

	// Version
	*b = hdr->ver;
	b += sizeof(hdr->ver);

	// Session ID
	memcpy(b, hdr->session_id, sizeof(hdr->session_id));
	b += sizeof(hdr->session_id);

	// Exp
	hton_64(b, hdr->exp);
	b += sizeof(hdr->exp);

	// Net ID
	memcpy(b, hdr->net_id, sizeof(hdr->net_id));
	b += sizeof(hdr->net_id);

	// Type
	*b = hdr->type;
	b += sizeof(hdr->type);

	// Node
	if ((n = encode_node(b, sizeof(buf) - (b - buf))) == -1) {
		return -1;
	}
	b += n;

	assert(b - buf == HEADER_SIZE(hdr->addrlen) - sizeof(hdr->sig));
	if (write(child->pipe, buf, b - buf) != b - buf) {
		return -1;
	}

	return 0;
}

static int
decode_response(const struct network_child *child, uint8_t sig[SIG_SIZE], )
{

}
