#include <event2/event.h>
#include <json-c/json.h>
#include <net/if.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

#include "brdcst.h"
#include "crypto_aes.h"
#include "fastd.h"
#include "fastd_peers.h"
#include "info_client.h"
#include "info_server.h"
#include "log.h"


static struct event_base *evbase;

static char *secret = "lmao";


static void handle_interrupt(int fd, short events, void *arg)
{
	(void) fd;
	(void) events;
	(void) arg;

	event_base_loopbreak(evbase);
}

int main(int argc, char **argv)
{
	if (argc != 2) {
		log_info("usage: ./bin/vpn-vlan [ifname]");
		return 0;
	}

	unsigned int if_index = if_nametoindex(argv[1]);
	if(if_index == 0) {
		log_error("ouch if_nametoindex");
		return 0;
	}

	crypto_aes_init((unsigned char *) "passpasspasspass", 16);

	evbase = event_base_new();

	if (!fastd_prepare()) {
		log_error("ouch fastd_prepare");
		goto cleanup_ev;
	}
	fastd_start();

	if(!info_client_init(evbase, if_index, fastd_intro(), fastd_peers_handle_intro, NULL)) {
		log_info("ouch info_client_init");
		goto cleanup_fastd;
	}

	if(!info_server_init(evbase, if_index, fastd_intro(), fastd_peers_handle_intro, NULL)) {
		log_info("ouch info_server_init");
		goto cleanup_fastd;
	}

	if (!brdcst_init(evbase, if_index, info_client_start, secret)) {
		log_error("ouch brdcst_init");
		goto cleanup_info_server;
	}

	while (!brdcst_send(secret, strlen(secret))) {
		log_info("retrying...");
		sleep(5);
	}
	struct event *sigint_event = evsignal_new(evbase, SIGINT, handle_interrupt, NULL);
	event_add(sigint_event, NULL);

	event_base_dispatch(evbase);

	log_error("past loop..");
	event_free(sigint_event);

cleanup_info_server:
	info_server_cleanup();
cleanup_fastd:
	fastd_cleanup();
cleanup_ev:
	event_base_free(evbase);

	return 0;
}
