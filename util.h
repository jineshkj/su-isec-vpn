#ifndef ISEC_UTIL_H
#define ISEC_UTIL_H

#include "control.h"
#include "sslutil.h"

const char *
get_password(const char *prompt);

const char *
get_current_user();

cm_header_t *
recv_control_message(sslutil_connection_t ssl_conn);

int
send_control_message(sslutil_connection_t ssl_conn, cm_header_t *cm);

int
ivpn_protocol_handshake(sslutil_connection_t ssl_conn);

int
ivpn_protocol_authenticate(sslutil_connection_t ssl_conn, const char *user,
                           const char *pass);

// int
// create_udp_socket(uint16_t port);
// 
// int
// create_tun_iface(const char *name);
// 
// int
// set_ifip(const char *ifname, const char *ip);
// 
// int
// send_message(int sock, uint32_t ip, uint16_t port, const char *str);
// 
// int
// recv_data(int sock, void * buf, int bufsz, struct in_addr *remote_ip);
// 
// int
// link_fds(int tun_fd, int udp_sock, uint32_t ip, uint16_t port);

#endif // ISEC_UTIL_H
