#include <json-c/json.h>
#include <safer_json.h>
#include <stdbool.h>
#include <uthash.h>

#include "log.h"

#include "fastd_peers.h"


typedef struct {
	char *ip;
	uint16_t port;

	char *key;

	UT_hash_handle hh;
} peer_t;

static peer_t *peers;
static reload_peers_cb_t cb;
static char peers_dir[512];


void fastd_peers_init(const char *_peers_dir, reload_peers_cb_t _cb)
{
	cb = _cb;
	peers = NULL;

	strncpy(peers_dir, _peers_dir, sizeof(peers_dir));

	char cmd[1024];
	snprintf(cmd, sizeof(cmd), "rm -rf %s; mkdir -p %s", peers_dir, peers_dir);
	system(cmd);
}

void fastd_peers_cleanup(void)
{
	peer_t *p, *tmp;
	HASH_ITER(hh, peers, p, tmp) {
		free(p->ip);
		free(p->key);
		free(p);
	}
}

static bool parse_intro(const char *intro, char **key, uint16_t *port)
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

static void write_peer(peer_t *p)
{
	char peer_file[1024];
	snprintf(peer_file, sizeof(peer_file), "%s%s", peers_dir, p->key);

	FILE *f = fopen(peer_file, "w+");
	fprintf(f, "key \"%s\";\nremote ipv6 \"%s\" port %hu;\n", p->key, p->ip, p->port);
	fclose(f);

	cb();
}

void fastd_peers_handle_intro(const char *ip, const char *intro, void *ctx)
{
	(void) ctx;

	uint16_t port;
	char *key;
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
			write_peer(p);
		}
		else {
			free(key);
		}
	}
	else {
		p = malloc(sizeof(peer_t));
		p->ip = strdup(ip);
		p->key = key;
		HASH_ADD_STR(peers, ip, p);
		write_peer(p);
	}
}
