#include <arpa/inet.h>
#include <ifs.h>
#include <json-c/json.h>
#include <json-c-parser.h>
#include <linux/if_ether.h>
#include <netinet/in.h>
#include <safer_json.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

#include "log.h"

#include "brdcst.h"

#define BROADCAST_ADDR "ff02::2"
#define BRDCST_PORT 38388
#define BROADCAST_PACK_LEN 32

static struct {
	int s;
	struct event_base *evbase;

	msg_cb_t cb;
	void *ctx;

	struct event *read_ev;
} udp;
static unsigned char pack[BROADCAST_PACK_LEN];
static const char *brdcst_ip;


static void read_cb(int s, short flags, void *arg)
{
	(void) flags;
	(void) arg;

	log_info("recved broadcast");

	struct sockaddr_storage from_info;
	socklen_t info_size = sizeof(from_info);

	memset(pack, '\0', BROADCAST_PACK_LEN);
	ssize_t r_len = recvfrom(s, pack, BROADCAST_PACK_LEN, 0, (struct sockaddr *) &from_info, &info_size);
	if (r_len == -1) {
		log_error("recv error %s", strerror(errno));
		return;
	} else if (r_len == 0) {
		log_error("socket was closed");
		return;
	}
	if ((size_t) r_len < BROADCAST_PACK_LEN) {
		log_error("short read (%zd/%u)", r_len, BROADCAST_PACK_LEN);
		return;
	}

	pack[r_len-1] = '\0';
	log_info("receved secret %s", pack);

	char ip[INET6_ADDRSTRLEN + 1];
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) &from_info;
	if (!inet_ntop(from_info.ss_family, &sin6->sin6_addr, ip, sizeof(ip))) {
		log_error("inet_ntop %s", strerror(errno));
		return;
	}

	uint32_t scope_id = ((struct sockaddr_in6 *) &from_info)->sin6_scope_id;
	if_t *i = get_if_by_index(scope_id);
	if(!i) {
		log_error("unknown interface");
		return;
	}

	udp.cb((const char *) pack, ip, i, udp.ctx);
}

static void send_on_if(if_t *i, void *ctx)
{
	(void) ctx;

	struct sockaddr_in6 saddr;
	memset(&saddr, 0, sizeof(struct sockaddr_in6));
	saddr.sin6_family = AF_INET6;
	saddr.sin6_port = htons(BRDCST_PORT);
	saddr.sin6_scope_id = i->index;
	inet_pton(AF_INET6, brdcst_ip, &saddr.sin6_addr);
	ssize_t wlen = sendto(udp.s, pack, BROADCAST_PACK_LEN, 0, (struct sockaddr *) &saddr, sizeof(saddr));
	if (wlen == -1) {
		log_error("sendto ouch: %s", strerror(errno));
		return;
	}
	if ((size_t) wlen < BROADCAST_PACK_LEN) {
		log_error("short write (%zd/%u)", wlen, BROADCAST_PACK_LEN);
		return;
	}

	log_info("sent broadcast %zd", wlen);
}

bool brdcst_send(const char *payload, uint16_t len)
{
	if (len >= BROADCAST_PACK_LEN) {
		log_error("payload oversized");
		return false;
	}

	memset(pack, '\0', BROADCAST_PACK_LEN);
	memcpy(pack, payload, len);

	ifs_enum(send_on_if, NULL);
	return true;
}

static void join_group(if_t *i, void *ctx)
{
	int *s = (int *) ctx;

	struct sockaddr_in6 mc_addr;
	memset(&mc_addr, 0, sizeof(mc_addr));
	inet_pton(AF_INET6, brdcst_ip, &mc_addr.sin6_addr);

	struct ipv6_mreq mc_req;
	memcpy(&mc_req.ipv6mr_multiaddr, &mc_addr.sin6_addr, sizeof(mc_req.ipv6mr_multiaddr));
	mc_req.ipv6mr_interface = i->index;

	if (setsockopt(*s, IPPROTO_IPV6, IPV6_JOIN_GROUP, (char *) &mc_req, sizeof(mc_req))) {
		log_error("setsockopt group error %s", strerror(errno));
	}
}

bool brdcst_init(struct event_base *evbase, msg_cb_t cb, void *ctx)
{
	brdcst_ip = getenv("ADDRESS") || BROADCAST_ADDR;

	int s = socket(AF_INET6, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP);
	if (s < 0) {
		log_error("socket error %s", strerror(errno));
		return false;
	}

	int so_reuse = 1;
	if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &so_reuse, sizeof(so_reuse)) != 0) {
		log_error("setsockopt reuse error %s", strerror(errno));
		goto cleanup_sock;
	}

	int loop = 0;
	if (setsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &loop, sizeof(loop)) != 0) {
		log_error("setsockopt loop error %s", strerror(errno));
		goto cleanup_sock;
	}

	struct sockaddr_in6 s_info;
	memset(&s_info, 0, sizeof(struct sockaddr_in6));
	s_info.sin6_family = AF_INET6;
	s_info.sin6_port = htons(BRDCST_PORT);
	s_info.sin6_addr = in6addr_any;

	if (bind(s, (struct sockaddr *) &s_info, sizeof(s_info)) < 0) {
		log_error("bind failed %s", strerror(errno));
		goto cleanup_sock;
	}

	ifs_enum(join_group, &s);

	int hops = 5;
	if (setsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &hops, sizeof(hops))) {
		log_error("setsockopt group error %s", strerror(errno));
		goto cleanup_sock;
	}

	udp.s = s;
	udp.evbase = evbase;

	udp.read_ev = event_new(evbase, s, EV_READ | EV_PERSIST, read_cb, NULL);
	event_add(udp.read_ev, NULL);

	udp.cb = cb;
	udp.ctx = ctx;

	return true;

cleanup_sock:
	close(s);

	return false;
}

void brdcst_cleanup(void)
{
	close(udp.s);
	event_free(udp.read_ev);
}
