#ifndef FASTD_H
#define FASTD_H

#include <stdbool.h>

bool fastd_prepare(void);
void fastd_start(void);
void fastd_kill(void);

void fastd_reload_peers(void);

const char *fastd_intro(void);


#endif
