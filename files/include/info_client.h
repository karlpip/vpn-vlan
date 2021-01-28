#ifndef INFO_CLIENT_H
#define INFO_CLIENT_H

typedef void (*server_intro_cb_t)(const char *ip, const char *intro, void *ctx);
void info_client_init(struct event_base *_evbase, const char *_my_intro, server_intro_cb_t _cb, void *_ctx);

void info_client_start(const char *secret, const char *ip, void *ctx);

#endif
