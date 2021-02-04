#ifndef BRDCST_H
#define BRDCST_H

#include <event2/event.h>
#include <stdbool.h>

#include "ifs.h"

typedef void (*msg_cb_t)(const char *msg, const char *ip, if_t *i, void *ctx);
bool brdcst_init(struct event_base *evbase, msg_cb_t cb, void *ctx);
void brdcst_cleanup(void);

bool brdcst_send(const char *payload, uint16_t len);

#endif
