#ifndef INFO_SERVER_H
#define INFO_SERVER_H


typedef void (*client_intro_cb_t)(const char *ip, const char *intro, void *ctx);
bool info_server_init(struct event_base *_evbase, const char *_my_intro, client_intro_cb_t _cb, void *_ctx);
void info_server_cleanup(void);

#endif
