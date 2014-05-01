#ifndef ISEC_UTIL_H
#define ISEC_UTIL_H

#include "control.h"
#include "sslutil.h"

char *
get_password(const char *prompt);

const char *
get_current_user();

int
authenticate_user(const char *user, const char *pass);

cm_header_t *
recv_control_message(sslutil_connection_t ssl_conn);

int
send_control_message(sslutil_connection_t ssl_conn, cm_header_t *cm);

int
ivpn_protocol_handshake(sslutil_connection_t ssl_conn);

int
ivpn_protocol_authenticate(sslutil_connection_t ssl_conn, const char *user,
                           const char *pass, int port);

int
generate_true_random(void *data, int datalen);

int
generate_pseudo_random(void *data, int datalen);

int
install_sigchld_handler();

int
relinquish_superuser();

#endif // ISEC_UTIL_H
