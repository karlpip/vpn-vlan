#include "info_server.h"


#define INFO_SERVER_PORT 39393

https://github.com/jonglezb/tcpscaler/blob/master/tcpserver.c
bool info_server_init(struct event_base *evbase, client_intro_cb_t _cb, void *_ctx)
{
	struct sockaddr_in6 sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin6_family = AF_INET6;
	sin.sin6_port = htons(INFO_SERVER_PORT);

	listener = evconnlistener_new_bind(evbase, accept_conn_cb, NULL,    LEV_OPT_CLOSE_ON_FREE|LEV_OPT_REUSEABLE, -1, (struct sockaddr*) &sin, sizeof(sin));
	if (!listener) {
		log_error("Couldn't create listener");
		return false;
	}
	evconnlistener_set_error_cb(listener, accept_error_cb);

	return true;
}
