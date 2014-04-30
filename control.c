
#include "control.h"

#include <string.h>

#include <arpa/inet.h>

void
cm_header_ntoh(cm_header_t *hdr)
{
  hdr->cm_len = ntohs(hdr->cm_len);
  hdr->cm_type = ntohs(hdr->cm_type);
}

void
cm_header_hton(cm_header_t *hdr)
{
  hdr->cm_len = htons(hdr->cm_len);
  hdr->cm_type = htons(hdr->cm_type);
}

void
cm_auth_response_ntoh(cm_auth_response_t *r)
{
  r->port = ntohs(r->port);
}

void
cm_auth_response_hton(cm_auth_response_t *r)
{
  r->port = htons(r->port);
}


const cm_auth_password_t *
create_cm_auth_password(const char *user, const char *pass, int port)
{
  static cm_auth_password_t cm;
  
  memset(&cm, 0, sizeof(cm));
  
  cm.auth.hdr.cm_len = sizeof(cm);
  cm.auth.hdr.cm_type = CM_TYPE_AUTH;
  
  cm.auth.type = CM_AUTH_PASSWORD;
  cm.auth.port = htons(port);
  
  strncpy(cm.username, user, sizeof(cm.username));
  cm.username[sizeof(cm.username) - 1] = '\0';

  strncpy(cm.password, pass, sizeof(cm.password));
  cm.password[sizeof(cm.password) - 1] = '\0';
  
  cm_header_hton(&cm.auth.hdr);

  return &cm;
}

const cm_auth_response_t *
create_cm_auth_response(int status, int port)
{
  static cm_auth_response_t cm;

  memset(&cm, 0, sizeof(cm));

  cm.hdr.cm_len = sizeof(cm);
  cm.hdr.cm_type = CM_TYPE_AUTH;

  cm.status = status;
  cm.port = port;

  cm_header_hton(&cm.hdr);
  cm_auth_response_hton(&cm);

  return &cm;
}
