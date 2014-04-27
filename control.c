
#include "control.h"

#include <string.h>

#include <arpa/inet.h>

const cm_auth_password_t *
ctl_create_cm_auth_password(const char *user, const char *pass)
{
  static cm_auth_password_t cm;
  
  memset(&cm, 0, sizeof(cm));
  
  cm.auth.hdr.cm_len = htons(sizeof(cm));
  cm.auth.hdr.cm_type = htons(CM_TYPE_AUTH);
  
  cm.auth.type = CM_AUTH_PASSWORD;
  
  strncpy(cm.username, user, sizeof(cm.username));
  cm.username[sizeof(cm.username) - 1] = '\0';

  strncpy(cm.password, user, sizeof(cm.password));
  cm.password[sizeof(cm.password) - 1] = '\0';
  
  return &cm;
}
