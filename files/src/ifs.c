#include <net/if.h>

#include "log.h"

#include "ifs.h"


static if_t *ifs;


static void add_if(const char *name, unsigned int index)
{
	if_t *i = malloc(sizeof(if_t));
	i->name = name;
	i->index = index;
	HASH_ADD_STR(ifs, name, i);
}

unsigned int ifs_init(const char **ifs, size_t num)
{
	unsigned int res = 0;

	for(size_t i  = 0; i < num; i++) {
		unsigned int index = if_nametoindex(ifs[i]);
		if(index == 0) {
			log_error("ouch if_nametoindex %s", ifs[i]);
			continue;
		}
		add_if(ifs[i], index);
		res++;
	}

	return res;
}

void ifs_enum(if_cb cb, void *ctx)
{
	if_t *i, *tmp;
	HASH_ITER(hh, ifs, i, tmp) {
		cb(i, ctx);
	}
}

void ifs_cleanup(void)
{
	if_t *i, *tmp;
	HASH_ITER(hh, ifs, i, tmp) {
		free(i);
		HASH_DEL(ifs, i);
	}
}

if_t *get_if_by_index(unsigned int index)
{
	if_t *i, *tmp;
	HASH_ITER(hh, ifs, i, tmp) {
		if(i->index == index) {
			return i;
		}
	}

	return NULL;
}
