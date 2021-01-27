#ifndef INFO_SERVER_H
#define INFO_SERVER_H


typedef void (*client_intro_cb_t)(const char *ip, const char *intro, void *ctx);
void info_server_init(client_intro_cb_t _cb, void *_ctx);

#endif
