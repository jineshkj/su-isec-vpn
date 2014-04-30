/*
 * utility functions ivpn software
 * 
 * Copyright (c) 2014 Jinesh J <jineshkj@gmail.com>
 */

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <termios.h>
#include <assert.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pwd.h>

#include <netinet/in.h>

#include "log.h"
#include "error.h"
#include "control.h"
#include "sslutil.h"

#include "util.h"

static inline void
remove_newline(char *s)
{
  while (*s != '\0') {
    if (*s == '\n')
      *s = '\0';
    s++;
  }
}

const char *
get_password(const char *prompt)
{
  struct termios oflags, nflags;
  static char password[128];

  /* save termios and disable echo */
  if (tcgetattr(fileno(stdin), &oflags) == -1) {
    lerr("Could not save current terminal attributes : %s", strerror(errno));
    return 0;
  }

  nflags = oflags;
  nflags.c_lflag &= ~ECHO;
  nflags.c_lflag |= ECHONL;

  if (tcsetattr(fileno(stdin), TCSANOW, &nflags) != 0) {
    lerr("Could not set new terminal attributes : %s", strerror(errno));
    return 0;
  }

  if (tcgetattr(fileno(stdin), &nflags) == -1) {
    lerr("Could not get new terminal attributes : %s", strerror(errno));
    return 0;
  }

  /* man page recommends verifying the set values. we do not want to take
   * any risk since it involves user inputting password */
  if ((nflags.c_lflag & ECHO) || !(nflags.c_lflag & ECHONL)) {
    lerr("New terminal attributes are not proper");
    (void) tcsetattr(fileno(stdin), TCSANOW, &oflags);
    return 0;
  }

  fprintf(stdout, "%s", prompt);
  fgets(password, sizeof(password), stdin);
  remove_newline(password);

  /* restore termios */
  if (tcsetattr(fileno(stdin), TCSANOW, &oflags) != 0) {
    lerr("Could not restore old terminal attributes : %s", strerror(errno));
    return 0;
  }

  return password;
}

const char *
get_current_user()
{
  struct passwd *pwd = getpwuid(getuid());
  if (pwd == 0) {
    lerr("Unable to get current user name");
    return 0;
  }

  return pwd->pw_name;
}

int
authenticate_user(const char *user, const char *pass)
{
  // TODO: use /etc/ivpn/users for allowed users
  // TODO: use PAM

  if (!strcmp(user, "seed") && !strcmp(pass, "seed"))
    return 1;

  return 0;
}


cm_header_t *
recv_control_message(sslutil_connection_t ssl_conn)
{
  int r, toread;
  static char buffer[MAX_CONTROL_MESSAGE_LEN];
  cm_header_t *hdr = (cm_header_t *) buffer;

  r = sslutil_read_all(ssl_conn, buffer, sizeof(cm_header_t));
  if (r < sizeof(cm_header_t))
    return 0;

  cm_header_ntoh(hdr);

  assert(sizeof(buffer) >= hdr->cm_len);

  toread = hdr->cm_len - r;

  r = sslutil_read_all(ssl_conn, buffer + r, toread);
  if (r < toread)
    return 0;

  return hdr;
}

int
send_control_message(sslutil_connection_t ssl_conn, cm_header_t *cm)
{
  int wlen = ntohs(cm->cm_len);
  if (sslutil_write_all(ssl_conn, cm, wlen) != wlen)
    return 0;

  return 1;
}

int
ivpn_protocol_handshake(sslutil_connection_t ssl_conn)
{
  char response[1024]; // big enough for holding handshake response

  assert(sizeof(response) >= sizeof(IVPN_PROTO_HEADER));

  if (sslutil_write_all(ssl_conn, IVPN_PROTO_HEADER, sizeof(IVPN_PROTO_HEADER))
      < sizeof(IVPN_PROTO_HEADER)) {
    lerr("Unable to write IVPN handshake message");
    return 0;
  }

  if (sslutil_read_all(ssl_conn, response, sizeof(IVPN_PROTO_HEADER))
      < sizeof(IVPN_PROTO_HEADER)) {
    lerr ("Unable to verify IVPN handshake message");
    return 0;
  }

  if (strncmp(response, IVPN_PROTO_HEADER, sizeof(response)) != 0) {
    lerr("IVPN Protocol handshake message incorrect");
    return 0;
  }

  return 1;
}

int
ivpn_protocol_authenticate(sslutil_connection_t ssl_conn, const char *user,
                           const char *pass, int port)
{
  if (send_control_message(
      ssl_conn, (cm_header_t *) create_cm_auth_password(user, pass, port))) {
    cm_header_t *h = recv_control_message(ssl_conn);
    if (h->cm_type == CM_TYPE_AUTH) {
      cm_auth_response_t *rsp = (cm_auth_response_t *) h;
      cm_auth_response_ntoh(rsp);

      if (rsp->status == CM_AUTH_OK)
        return rsp->port;
    }
  }

  return 0;
}

static int urandom_fd = -1; // never to close this fd. we need it till end or program

int
generate_true_random(void *data, int datalen)
{
  // don't use fopen() since it's going to buffer data from /dev/urandom
  if (urandom_fd == -1)
    urandom_fd = open("/dev/urandom", O_RDONLY);

  if (urandom_fd == -1) {
    lerr("Unable to open /dev/urandom : %s", strerror(errno));
    return 0;
  }
  
  if (read(urandom_fd, data, datalen) != datalen) {
    lerr("Unable to read required bytes from /dev/urandom : %s", strerror(errno));
    return 0;
  }

  return 1;
}

int
generate_pseudo_random(void *data, int datalen)
{
  unsigned char *buf = (unsigned char *)data;
  
  while (datalen--)
    buf[datalen] = (unsigned char) (rand() & 0xFF);

  return 1;
}
