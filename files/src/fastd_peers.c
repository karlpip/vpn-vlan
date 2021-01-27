#include <uthash.h>
#include <json-c/json.h>

#include "log.h"

#include "fastd_peers.h"


#define PEERS_FILE "/tmp/config/fastd/peers"

typedef struct {
	char *ip;
	uint16_t port;

	char *key;

	UT_hash_handle hh;
} peer_t;

static peer_t peers;
static reload_peers_cb_t cb;

bool fastd_peers_init(reload_peers_cb_t _cb)
{
	cb = _cb;
	peers = NULL;
}

static bool parse_intro(const char *intro, const char **key, uint16_t *port)
{
	struct json_object *jintro = json_tokener_parse(intro);
	if(!jintro)
		return false;

	struct json_object *jkey;
	if(!json_object_object_get_ex(jintro, "key", &jkey))
		return false;

	struct json_object *jport;
	if(!json_object_object_get_ex(jintro, "port", &jport))
		return false;

	int p = json_object_get_int(jport);
	*port = (uint16_t) p;
	*key = strdup(json_object_get_string(jkey));

	json_object_safer_put(jintro);

	return true;
}

static void write_peers(bool changed)
{
	if(!changed)
		return;

	char cmd[1024];
	snprintf(cmd, sizeof(cmd), "rm -rf %s", PEERS_FILE);
	system(cmd);

	FILE *f = fopen(PEERS_FILE, "w+");
	peer_t *p, *tmp;
	HASH_ITER(hh, peers, p, tmp) {
		fprintf(f, "key \"%s\";\nremote ipv6 \"%s\" port %hu;\n", p->key, p->ip, p->port);
	}
	fclose(f);

	cb();
}

void fastd_peers_handle_intro(const char *ip, const char *intro, void *ctx)
{
	bool changed = false;

	uint16_t port;
	const char *key;
	if (!parse_intro(intro, &key, &port)) {
		log_error("intro malformed");
		return;
	}

	peer_t *p;
	HASH_FIND_STR(peers, ip, p);
	if (p) {
		if (strcmp(p->key, key) != 0) {
			free(p->key);
			p->key = key;
			changed = true;
		}
		else {
			free(key);
		}

		goto out;
	}

	p = malloc(sizeof(peer_t));
	p->ip = strdup(ip);
	p->key = key;

	HASH_ADD_STR(peers, ip, p);

	changed = true;
out:
	write_peers(changed);
}
