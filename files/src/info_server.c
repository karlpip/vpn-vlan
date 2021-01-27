#include "log.h"

#include "info_server.h"


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

#define INFO_SERVER_PORT 39393

static struct evconnlistener *listener;
static client_t *clients;

const char *my_intro;

static client_intro_cb_t cb;
static void *ctx;


static void cleanup_c(client_t *c)
{
	event_free(c->client_to)
	bufferevent_free(c->bev);
	free(c->ip);
	free(c);
}

static void to_cb(evutil_socket_t fd, short what, void *arg)
{
	client_t *c = (client_t *) ctx;
	log_info("server client timeout %s", c->ip);
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

static void handle_msg(client_t *c, const char *msg)
{
	int cipher_len = c->msg_len;
	unsigned char *dec_server_intro = crypto_aes_decrypt(msg, &cipher_len);
	cb(c->ip, dec_server_intro, ctx);
	free(dec_server_intro);
}

static void readcb(struct bufferevent *bev, void *ctx)
{
	client_t *c = (client_t *) ctx;

	if (c->state == STATE_CONNECTED) {
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
			handle_msg(c, enc_msg);

		send_msg(c, my_intro);

		cleanup_c(c);
		HASH_DEL(clients, c);

	}
	else {
		log_info("state???");
	}
}

static void eventcb(struct bufferevent *bev, short events, void *ctx)
{
	client_t *c = (client_t *) ctx;

	if (events & BEV_EVENT_CONNECTED) {
		c->state = STATE_SENT_INTRO;
	} else if (events & BEV_EVENT_ERROR) {
		cleanup_c(c);
		HASH_DEL(clients, c);
	}

	// TODO: cases
}

static void accept_conn_cb(struct evconnlistener *listener,
			   evutil_socket_t fd, struct sockaddr *address,
			   int socklen, void *ctx)
{
	char ip[INET6_ADDRSTRLEN + 1];
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) address;
	if (!inet_ntop(sin6->sin6_family, &sin6->sin6_addr, ip, sizeof(ip))) {
		log_error("inet_ntop %s", strerror(errno));
		return;
	}

	client_t *c;
	HASH_FIND_STR(clients, ip, c);
	if(c) {
		log_info("%s already connected", ip);
		close(fd);
		return;
	}

	c = malloc(sizeof(client_t));
	c->ip = strdup(ip);
	struct event_base *base = evconnlistener_get_base(listener);
	struct bufferevent *bev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);
	bufferevent_setcb(bev, readcb, NULL, eventcb, c);
	bufferevent_enable(bev, EV_READ|EV_WRITE);
	c->bev = bev;
	c->client_to = evtimer_new(evbase, to_cb, c);

	struct timeval t;
	t.tv_sec = 10;
	t.tv_usec = 0;
	evtimer_add(c->client_to, &t);

	HASH_ADD_STR(clients, ip, c);
}

bool info_server_init(struct event_base *evbase, const char *_my_intro, client_intro_cb_t _cb, void *_ctx)
{
	my_intro = _my_intro;
	cb = _cb;
	ctx = _ctx;

	struct sockaddr_in6 sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin6_family = AF_INET6;
	sin.sin6_port = htons(INFO_SERVER_PORT);

	listener = evconnlistener_new_bind(evbase, accept_conn_cb, NULL, LEV_OPT_CLOSE_ON_FREE|LEV_OPT_REUSEABLE, -1, (struct sockaddr*) &sin, sizeof(sin));
	if (!listener) {
		log_error("Couldn't create listener");
		return false;
	}
	// evconnlistener_set_error_cb(listener, accept_error_cb);

	return true;
}
