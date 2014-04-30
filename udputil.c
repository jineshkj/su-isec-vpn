
#include <errno.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>

#include "log.h"
#include "udputil.h"

//---- creates a udp socket bound to a free port ---

int
create_udp_socket()
{
  int s;
  struct sockaddr_in addr;

  if ((s = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
    lerr("Socket creation error : %s", strerror(errno));
    return -1;
  }

  memset(&addr, 0, sizeof(addr));

  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  addr.sin_port = 0; // let system choose a free port

  if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
    lerr("Could not bind UDP socket : %s", strerror(errno));
    close(s);
    return -1;
  }

  return s;
}

int
get_udp_port(int sock)
{
  struct sockaddr_in addr;
  socklen_t len = sizeof(addr);

  if (getsockname(sock, (struct sockaddr*) &addr, &len) == -1) {
    lerr("Unable to get port number : %s", strerror(errno));
    return 0;
  }

  return ntohs(addr.sin_port);
}
