
#include <ctype.h>
#include <netdb.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "log.h"
#include "tcputil.h"

static int
is_ip(const char *str)
{
  while (*str != '\0') {
    // valid ip contains only digits or a dot
    if (isdigit(*str) || *str == '.')
      str++;
    else
      return 0;
  }
  
  return 1;
}

static const char *
get_ip_from_name(const char *name)
{
  struct   hostent *h;
  
  if ((h = gethostbyname(name)) == 0 || h->h_addr_list[0] == 0) {
    lerr ("Unable to get IP address of %s", name);
    return 0;
  }
  
  return inet_ntoa(*(struct in_addr *)(h->h_addr_list[0]));
}

int
tcputil_connect(const char *server, int port)
{
  int sock;
  struct sockaddr_in servaddr;
  
  /* we do not accept IP address for server because we need to later
   * validate the common name obtained from the certificate */
  if (is_ip(server)) {
    lerr ("IPv4 address expected but host name provided instead");
    return -1;
  }

  /* covert domain name to ip address */
  if ((server = get_ip_from_name(server)) == 0)
    return -1;
  
  if ((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
    lerr ("Could not create socket : %s", strerror(errno));
    return -1;
  }
  
  memset(&servaddr, 0, sizeof(servaddr));
  servaddr.sin_family      = AF_INET;
  servaddr.sin_addr.s_addr = inet_addr(server);
  servaddr.sin_port        = htons(port);

  if (connect(sock, (struct sockaddr *) &servaddr, sizeof(servaddr)) < 0) {
    lerr ("Could not connect to %s:%u : %s", server, port, strerror(errno));
    close(sock);
    return -1;
  }

  return sock;
}

/* Creates a listening TCP socket
 *   port : port number on which to listen for incoming connections
 *   backlog : see MAN listen (2)
 *
 * returns : listening socket descriptor on success, -1 on failure
 */
int
tcputil_create_listener(int port, int backlog)
{
  int opt;
  int listenfd = -1;
  struct sockaddr_in servaddr;

  listenfd = socket(AF_INET, SOCK_STREAM, 0);
  if (listenfd == -1) {
    lerr ("Could not create socket : %s", strerror(errno));
    return -1;
  }

  opt = 1;
  if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1) {
    /* just a warning would be sufficient */
    lwarn ("Could not set REUSEADDR socket option : %s", strerror(errno));
  }

  memset(&servaddr, 0, sizeof(servaddr));
  servaddr.sin_family = AF_INET;
  servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
  servaddr.sin_port = htons(port);
  if (bind(listenfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) == -1) {
    lerr ("Could not bind to port %u: %s", port, strerror(errno));
    close(listenfd);
    return -1;
  }

  if (listen(listenfd, backlog) == -1) {
    lerr ("Could not listen on port %u (backlog=%d): %s", port, backlog,
          strerror(errno));
    close(listenfd);
    return -1;
  }

  return listenfd;
}

int
tcputil_accept(int listenfd, char *ip, int buflen, int *port)
{
  int connfd;
  struct sockaddr_in cliaddr;
  socklen_t clilen = sizeof(cliaddr);

  connfd = accept(listenfd, (struct sockaddr *)&cliaddr, &clilen);
  if (connfd == -1) {
    lerr ("Could not accept on listener socket: %s", strerror(errno));
    return -1;
  }

  snprintf(ip, buflen, "%s", inet_ntoa(cliaddr.sin_addr));
  *port = ntohs(cliaddr.sin_port);

  return connfd;
}
