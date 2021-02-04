#ifndef IFS_H
#define IFS_H

#include <uthash.h>

typedef struct {
	char *name;
	unsigned int index;

	UT_hash_handle hh;
} if_t;

unsigned int ifs_init(const char **ifs, size_t num);
void ifs_cleanup(void);

typedef void (*if_cb)(if_t *i, void *ctx);
void ifs_enum(if_cb cb, void *ctx);

if_t *get_if_by_index(unsigned int index);

#endif
