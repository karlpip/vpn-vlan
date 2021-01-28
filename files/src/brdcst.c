#include <arpa/inet.h>
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


#define BRDCST_PORT 38388
#define BROADCAST_ADDR "ff02::2"

static struct {
	int s;
	struct event_base *evbase;

	msg_cb_t cb;
	void *ctx;

	struct event *read_ev;
} udp;


static void read_cb(int s, short flags, void *arg)
{
	(void) flags;
	(void) arg;


	struct sockaddr_storage from_info;
	socklen_t info_size = sizeof(from_info);

	uint16_t netlen;
	ssize_t r_len = recvfrom(s, (void *) &netlen, sizeof(uint16_t), 0, (struct sockaddr *) &from_info, &info_size);
	if (r_len == -1) {
		log_error("len recv error %s", strerror(errno));
		return;
	} else if (r_len == 0) {
		log_error("len socket was closed");
		return;
	}
	if ((size_t) r_len < sizeof(uint16_t)) {
		log_error("len short read %zd", r_len);
		return;
	}

	uint16_t paylen = ntohs(netlen);

	char *msg = alloca(paylen+1);
	r_len = recvfrom(s, msg, paylen, 0, (struct sockaddr *) &from_info, &info_size);
	if (r_len == -1) {
		log_error("payload recv error %s", strerror(errno));
		return;
	} else if (r_len == 0) {
		log_error("payload socket was closed");
		return;
	}
	if ((size_t) r_len < paylen) {
		log_error("payload short read %zd/%" PRIx16, r_len, paylen);
		return;
	}

	msg[r_len]  = '\0';

	char ip[INET6_ADDRSTRLEN + 1];
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) &from_info;
	if (!inet_ntop(from_info.ss_family, &sin6->sin6_addr, ip, sizeof(ip))) {
		log_error("inet_ntop %s", strerror(errno));
		return;
	}

	udp.cb(msg, ip, udp.ctx);
}

bool brdcst_send(const char *payload, uint16_t len)
{
	struct sockaddr_in6 saddr;
	memset(&saddr, 0, sizeof(struct sockaddr_in6));
	saddr.sin6_family = AF_INET6;
	saddr.sin6_port = htons(BRDCST_PORT);
	inet_pton(AF_INET6, BROADCAST_ADDR, &saddr.sin6_addr);

	uint16_t net_len = htons(len);
	ssize_t wlen = sendto(udp.s, &net_len, sizeof(uint16_t), 0, (struct sockaddr *) &saddr, sizeof(saddr));
	if (wlen == -1) {
		log_error("sendto ouch: %s", strerror(errno));
		return false;
	}

	if ((size_t) wlen < sizeof(uint16_t)) {
		log_error("short write (%zd/%zu)", wlen, sizeof(uint16_t));
		return false;
	}

	wlen = sendto(udp.s, payload, len, 0, (struct sockaddr *) &saddr, sizeof(saddr));
	if (wlen == -1) {
		log_error("sendto ouch: %s", strerror(errno));
		return false;
	}

	if ((size_t) wlen < len) {
		log_error("short write (%zd/%zu)", wlen, len);
		return false;
	}

	return true;
}

bool brdcst_init(struct event_base *evbase, msg_cb_t cb, void *ctx)
{
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

	struct sockaddr_in6 mc_addr;
	memset(&mc_addr, 0, sizeof(mc_addr));
	inet_pton(AF_INET6, BROADCAST_ADDR, &mc_addr.sin6_addr);

	struct ipv6_mreq mc_req;
	memcpy(&mc_req.ipv6mr_multiaddr, &mc_addr.sin6_addr, sizeof(mc_req.ipv6mr_multiaddr));
	mc_req.ipv6mr_interface = 0;

	if (setsockopt(s, IPPROTO_IPV6, IPV6_JOIN_GROUP, (char *) &mc_req, sizeof(mc_req))) {
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
