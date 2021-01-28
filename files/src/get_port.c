#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

#include "log.h"

#include "get_port.h"


uint16_t get_port(void)
{
	uint16_t port = 0;
	int s;
	int reuseaddr = 1;
	struct sockaddr_in6 addr;

	s = socket(AF_INET6, SOCK_STREAM, 0);
	setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof(reuseaddr));

	addr.sin6_family = AF_INET6;
	addr.sin6_port = 0;
	addr.sin6_addr = in6addr_any;

	bind(s, (struct sockaddr *) &addr, sizeof(addr));

	socklen_t len = sizeof(addr);
	if (getsockname(s, (struct sockaddr *)&addr, &len) == -1) {
	    log_error("getsockname ouch");
		goto out;
	}
	port = ntohs(addr.sin6_port);
out:
	close(s);
	return port;
}
