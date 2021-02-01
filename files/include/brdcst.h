#ifndef BRDCST_H
#define BRDCST_H

#include <event2/event.h>
#include <stdbool.h>

typedef void (*msg_cb_t)(const char *msg, const char *ip, void *ctx);
bool brdcst_init(struct event_base *evbase, unsigned int _if_index, msg_cb_t cb, void *ctx);
void brdcst_cleanup(void);

bool brdcst_send(const char *payload, uint16_t len);

#endif
