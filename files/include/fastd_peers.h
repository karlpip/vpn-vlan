#ifndef FASTD_PEERS_H
#define FASTD_PEERS_H

typedef void (*reload_peers_cb_t)(void);
void fastd_peers_init(const char *_peers_dir, reload_peers_cb_t _cb);
void fastd_peers_cleanup(void);

void fastd_peers_handle_intro(const char *ip, const char *intro, void *ctx);

#endif
