#include <arpa/inet.h>
#include <event2/bufferevent.h>
#include <event2/event.h>
#include <event2/util.h>
#include <uthash.h>

#include "crypto_aes.h"
#include "log.h"

#include "info_client.h"


#define INFO_SERVER_PORT 39393

typedef enum {
	STATE_CONNECTED,
	STATE_SENT_INTRO,
	STATE_GOT_INTRO_LEN,
} client_state_t;

typedef struct {
	char *ip;

	struct bufferevent *bev;

	struct event *client_to;

	client_state_t state;

	uint16_t msg_len;

	UT_hash_handle hh;
} client_t;

static struct event_base *evbase;

static client_t *clients;

const char *my_intro;

static server_intro_cb_t cb;
static void *ctx;


static void cleanup_c(client_t *c)
{
	event_free(c->client_to);
	bufferevent_free(c->bev);
	free(c->ip);
	free(c);
}

static void to_cb(evutil_socket_t fd, short what, void *arg)
{
	(void) fd;
	(void) what;
	(void) arg;


	client_t *c = (client_t *) ctx;
	log_info("timeout %s", c->ip);
	cleanup_c(c);
	HASH_DEL(clients, c);
}

static void handle_msg(client_t *c, const char *msg)
{
	int cipher_len = c->msg_len;
	unsigned char *dec_server_intro = crypto_aes_decrypt((unsigned char *) msg, &cipher_len);
	cb(c->ip, (char *) dec_server_intro, ctx);
	free(dec_server_intro);
}

static void readcb(struct bufferevent *bev, void *ctx)
{
	client_t *c = (client_t *) ctx;

	if (c->state == STATE_SENT_INTRO) {
		uint16_t netlen;
		bufferevent_read(bev, &netlen, sizeof(uint16_t));
		uint16_t paylen = ntohs(netlen);
		c->msg_len = paylen;
		bufferevent_setwatermark(bev, EV_READ, paylen, 0);

		c->state = STATE_GOT_INTRO_LEN;
		return;
	}
	else if (c->state == STATE_GOT_INTRO_LEN) {
		unsigned char *enc_msg = alloca(c->msg_len);
		size_t r_len =  bufferevent_read(bev, enc_msg, c->msg_len);
		if (r_len < c->msg_len)
			log_error("payload short read %zd/%" PRIx16, r_len, c->msg_len);
		else
			handle_msg(c, (const char *) enc_msg);
	}
	else {
		log_info("server doesnt wait for us :/");
	}

	cleanup_c(c);
	HASH_DEL(clients, c);
}

static void send_msg(client_t *c, const char *msg)
{
	int len = strlen(msg);
	unsigned char *cipher = crypto_aes_encrypt((unsigned char *) msg, &len);

	uint16_t netlen = htons(len);
	bufferevent_write(c->bev, &netlen, sizeof(netlen));
	bufferevent_write(c->bev, cipher, len);
	free(cipher);
}

static void eventcb(struct bufferevent *bev, short events, void *ctx)
{
	(void) bev;

	client_t *c = (client_t *) ctx;

	if (events & BEV_EVENT_CONNECTED) {
		send_msg(c, my_intro);
		c->state = STATE_SENT_INTRO;
	} else if (events & BEV_EVENT_ERROR) {
		cleanup_c(c);
		HASH_DEL(clients, c);
	}

	// TODO: cases
}

void info_client_start(const char *msg, const char *ip, void *ctx)
{
	const char *secret = (const char *) ctx;

	if (strcmp(msg, secret) != 0) {
		log_error("secrets not matching %s", msg);
		return;
	}

	client_t *c;
	HASH_FIND_STR(clients, ip, c);
	if (c) {
		log_info("already exchanging peer infos with %s", ip);
		return;
	}

	c = malloc(sizeof(client_t));
	c->ip = strdup(ip);
	c->client_to = evtimer_new(evbase, to_cb, c);

	struct sockaddr_in6 sin;
	sin.sin6_family = AF_INET6;
	inet_pton(AF_INET6, ip, &sin.sin6_addr);
	sin.sin6_port = htons(INFO_SERVER_PORT);
	struct bufferevent *bev = bufferevent_socket_new(evbase, -1, BEV_OPT_CLOSE_ON_FREE);
	bufferevent_setcb(bev, readcb, NULL, eventcb, c);
	bufferevent_enable(bev, EV_READ|EV_WRITE);
	c->bev = bev;

	if (bufferevent_socket_connect(bev, (struct sockaddr *) &sin,  sizeof(sin)) < 0) {
		log_info("cant connect to %s", ip);
		cleanup_c(c);
		return;
	}
	c->state = STATE_CONNECTED;

	struct timeval t;
	t.tv_sec = 10;
	t.tv_usec = 0;
    evtimer_add(c->client_to, &t);

	HASH_ADD_STR(clients, ip, c);
}

void info_client_init(struct event_base *_evbase, const char *_my_intro, server_intro_cb_t _cb, void *_ctx)
{
	evbase = _evbase;
	my_intro = _my_intro;
	cb = _cb;
	ctx = _ctx;
}
