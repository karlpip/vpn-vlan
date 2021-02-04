#ifndef INFO_CLIENT_H
#define INFO_CLIENT_H

#include "ifs.h"

typedef void (*server_intro_cb_t)(const char *ip, const char *intro, const char *if_name, void *ctx);
bool info_client_init(struct event_base *_evbase, const char *_my_intro, server_intro_cb_t _cb, void *_ctx);

void info_client_start(const char *secret, const char *ip, if_t *i, void *ctx);

#endif
