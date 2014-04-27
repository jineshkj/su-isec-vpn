#ifndef ISEC_CONTROL_H
#define ISEC_CONTROL_H

#include <stdint.h>

#define IVPN_PROTO_VERSION "1.0" // client need to match server's protocol version
#define IVPN_PROTO_HANDSHAKE "IVPN Protocol "IVPN_PROTO_VERSION

/* structures for control messages */

#define CM_TYPE_ECHO 0  // control message for echo messages (unused)
#define CM_TYPE_AUTH 1  // control message for authentication

#define CM_TYPE_OK   2  // ok response to previous message
#define CM_TYPE_FAIL 3  // failure response to previous message

typedef struct cm_header {
  uint16_t cm_len; // length include complete message
  uint16_t cm_type;
} __attribute__((packed)) cm_header_t;

/*
 * structures for client authentication control messages
 */

#define CM_AUTH_PASSWORD 0 // user/pass based authentication

typedef struct cm_auth {
  cm_header_t hdr;
  uint8_t     type;
} __attribute__((packed)) cm_auth_t;

#define MAX_USERNAME 64
#define MAX_PASSWORD 64

typedef struct cm_auth_password {
  cm_auth_t auth;
  char      username[MAX_USERNAME];
  char      password[MAX_PASSWORD];
}__attribute__((packed)) cm_auth_password_t;

const cm_auth_password_t *
ctl_create_cm_auth_password(const char *user, const char *pass);

#endif // ISEC_CONTROL_H
