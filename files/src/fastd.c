#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "log.h"

#include "fastd.h"


enum {
	KEY_PUB = 0,
	KEY_PRIV,
	KEY_MAX
};
#define MAX_KEY_LEN 128

typedef struct {
	char keys[KEY_MAX][MAX_KEY_LEN];
} keys_t;

#define FASTD_CONF_DIR "/tmp/config/fastd/"
#define FASTD_CONF	"log level warn;\n" \
					"bind any port %s default;\n" \
					"mode multitap;\n" \
					"interface \"p%%k\";\n" \
					"forward yes;\n" \
					"method \"salsa2012+gmac\";\n" \
					"secret \"%s\";\n" \
					"mtu 1426;\n" \
					"on up \"batctl meshif \\\"$IFACE\\\" if add \\\"$INTERFACE\\\"; ip l set up $INTERFACE\";\n" \
					"include peers from \"%speers/\";\n"

static keys_t keys;
static pid_t proc;
static char port[6];
static char intro[512];


static bool get_port()
{
	bool res = true;
	FILE *f = popen("nc -vluw 1 2>&1 | sed -En 's/.*:(\\d+).*/\\1/p'", "r");
	if (!f) {
		log_error("ouch popen: %s", strerror(errno));
		return false;
	}
	if (feof(f)) {
		log_error("neigh insta close");
		res = false;
		goto cleanup;
	}
	if(!fgets(port, 6, f)) {
		log_error("fgets failed somehow");
		res = false;
		goto cleanup;
	}
	port[strlen(port)-1] = '\0';
cleanup:
	fclose(f);

	return res;
}

static char *conf_dir()
{
	static char dir[256];
	if(dir[0])
		return dir;
	snprintf(dir, sizeof(dir), "%s/%s/", FASTD_CONF_DIR, "env.iface"); // TODO: ???
	return dir;
}

static bool gen_keys(void)
{
	bool res = true;
	FILE *f = popen("fastd --generate-key 2>/dev/null | sed 's/^.\\{8\\}//g'", "r");
	if (!f) {
		log_error("ouch popen: %s", strerror(errno));
		return false;
	}

	if (feof(f)) {
		log_error("neigh insta close");
		res = false;
		goto cleanup;
	}

	if(!fgets(keys.keys[KEY_PRIV], MAX_KEY_LEN, f) || !fgets(keys.keys[KEY_PUB], MAX_KEY_LEN, f)) {
		log_error("fgets failed somehow");
		res = false;
	}

	keys.keys[KEY_PRIV][strlen(keys.keys[KEY_PRIV])-1] = '\0';
	keys.keys[KEY_PUB][strlen(keys.keys[KEY_PUB])-1] = '\0';

cleanup:
	fclose(f);

	return res;
}

static void write_conf(void)
{
	char filename[1024];
	snprintf(filename, sizeof(filename), "%s/fastd_conf", conf_dir());
	FILE *f = fopen(filename, "w+");
	fprintf(f, FASTD_CONF, port, keys.keys[KEY_PRIV], conf_dir());
	fclose(f);
}

bool fastd_prepare(void)
{
	if(!gen_keys())
		return false;

	if(!get_port())
		return false;

	char cmd[1024];
	snprintf(cmd, sizeof(cmd), "rm -rf %s; mkdir -p %speers", conf_dir(), conf_dir());
	system(cmd);

	write_conf();

	snprintf(intro, sizeof(intro), "{\"port\": \"%s\", \"key\": \"%s\"}", port, keys.keys[KEY_PUB]);

	return true;
}

void fastd_start(void)
{
	pid_t p = fork();

	if(p == 0) {
		// TODO: whatsup with the comm socket ????
		char filename[1024];
		snprintf(filename, sizeof(filename), "%sfastd_conf", conf_dir());
		execlp ("fastd", "fastd", "-c", filename, NULL);
	}
	else {
		proc = p;
	}
}

void fastd_kill(void)
{
	if(proc)
		kill(proc, SIGTERM);
}

void fastd_reload_peers(void)
{
	if(proc)
		kill(proc, SIGHUP);
}

void fastd_add_peer(const char *pub_key, const char *host, int64_t port)
{
	// TODO: check if peer already exist? add folder first fastd_peers.c???
	char filename[1024];
	snprintf(filename, sizeof(filename), "%speers/%.16s", conf_dir(), pub_key);
	FILE *f = fopen(filename, "w+");
	fprintf(f, "key \"%s\";\nremote ipv4 \"%s\" port %lld;\n", pub_key, host, port);
	fclose(f);

	if(proc == 0) {
		start();
	}
	else {

	}
}

const char *fastd_intro(void)
{
	return &intro;
}
