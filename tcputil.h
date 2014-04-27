#ifndef ISEC_TCPUTIL_H
#define ISEC_TCPUTIL_H

int
tcputil_connect(const char *server, int port);

int
tcputil_create_listener(int port, int backlog);

int
tcputil_accept(int listenfd, char *ip, int buflen, int *port);

#endif // ISEC_TCPUTIL_H
