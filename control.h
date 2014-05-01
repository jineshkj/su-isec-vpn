#ifndef ISEC_CONTROL_H
#define ISEC_CONTROL_H

#include "defaults.h"

#include <stdint.h>

#define IVPN_PROTO_VERSION "1.0" // client need to match server's protocol version
#define IVPN_PROTO_HEADER "IVPN Protocol "IVPN_PROTO_VERSION"\n"

#define MAX_CONTROL_MESSAGE_LEN 1024

/* structures for control messages */

#define CM_TYPE_ECHO    0  // control message for echo messages (unused)
#define CM_TYPE_AUTH    1  // control message for authentication
#define CM_TYPE_SETKEY  2  // control message for setting new key

#define CM_TYPE_OK   2  // ok response to previous message
#define CM_TYPE_FAIL 3  // failure response to previous message

typedef struct cm_header {
  uint16_t cm_len; // length include complete message
  uint16_t cm_type;
} __attribute__((packed)) cm_header_t;

void
cm_header_ntoh(cm_header_t *hdr);

void
cm_header_hton(cm_header_t *hdr);

/*
 * structures for client authentication control messages
 */

#define CM_AUTH_PASSWORD 0 // user/pass based authentication

typedef struct cm_auth {
  cm_header_t hdr;
  uint8_t     type; // change to 16 bits ??
  uint16_t    port;
} __attribute__((packed)) cm_auth_t;

#define CM_AUTH_OK   0
#define CM_AUTH_FAIL 1

typedef struct cm_auth_response {
  cm_header_t hdr;
  uint8_t     status;
  uint16_t    port;
} __attribute__((packed)) cm_auth_response_t;

void
cm_auth_response_ntoh(cm_auth_response_t *r);

void
cm_auth_response_hton(cm_auth_response_t *r);

typedef struct cm_auth_password {
  cm_auth_t auth;
  char      username[MAX_USERNAME];
  char      password[MAX_PASSWORD];
}__attribute__((packed)) cm_auth_password_t;

cm_auth_password_t *
create_cm_auth_password(const char *user, const char *pass, int port);

cm_auth_response_t *
create_cm_auth_response(int status, int port);

typedef struct cm_setkey {
  cm_header_t hdr;
  uint8_t     key[IVPN_KEY_LENGTH];
} __attribute__((packed)) cm_setkey_t;

cm_setkey_t *
create_cm_setkey(const char *key);

#endif // ISEC_CONTROL_H
