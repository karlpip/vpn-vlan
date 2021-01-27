#include <event2/event.h>
#include <json-c/json.h>

#include "brdcst.h"
#include "fastd.h"
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

int main(void)
{
	evbase = event_base_new();

	if (!fastd_prepare()) {
		log_error("ouch fastd_prepare");
		goto cleanup_ev;
	}
	fastd_start();

	fastd_peers_init(fastd_reload_peers);

	info_client_init(fastd_intro(), fastd_peers_handle_intro, NULL);



	if (!brdcst_init(evbase, info_client_start, secret)) {
		log_error("ouch brdcst_init");
		goto cleanup_fastd_peers;
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

cleanup_fastd_peers:
	fastd_peers_cleanup();

	fastd_kill();
cleanup_ev:
	event_base_free(evbase);

	return 0;
}
