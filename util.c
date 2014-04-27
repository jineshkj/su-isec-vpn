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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pwd.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>

#include "log.h"
#include "error.h"
#include "control.h"
#include "sslutil.h"

#include "util.h"

#define TUN_CTL_DEV "/dev/net/tun"
#define TUNNEL_MODE IFF_TUN

static void
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
                           const char *pass)
{
  if (send_control_message(
      ssl_conn, (cm_header_t *) create_cm_auth_password(user, pass))) {
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


//---- creates a udp socket bound to a given port ---

int
create_udp_socket(uint16_t port)
{
  int s;
  struct sockaddr_in sin;
  
  if ((s = socket(AF_INET, SOCK_DGRAM, 0)) != -1) {
    int optval = 1;
    
    /* avoid EADDRINUSE error on bind() */
    if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
      printf("Socket setsockopt error : %s\n", strerror(errno));
      close(s);
      return -1;
    }
    
    memset(&sin, 0, sizeof(sin));
    
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_ANY);
    sin.sin_port = port;
    
    if (bind(s,(struct sockaddr *)&sin, sizeof(sin)) < 0) {
      printf("Bind error : %s\n", strerror(errno));
      close(s);
      return -1;
    }
  } else {
    printf("Socket creation error : %s\n", strerror(errno));
  }
  
  return s;
}

//---- bring up an interface ---

static int
iff_up(const char *ifname)
{
  int s, r;
  struct ifreq ifr;

  s = socket(AF_INET, SOCK_DGRAM, 0);

  if (s < 0)
      return -1;

  /* first obtain current IF flags */
  memset(&ifr, 0, sizeof ifr);
  strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
  
  r = ioctl(s, SIOCGIFFLAGS, &ifr);
  if (r == -1) {
    printf("Failed to get interface flags : %s\n", strerror(errno));
  }
  
  if (r != -1) {
    /* set the IFF_UP flag */
    ifr.ifr_flags |= IFF_UP;
    r = ioctl(s, SIOCSIFFLAGS, &ifr);
    if (r == -1) {
      printf("Failed to set interface flags : %s\n", strerror(errno));
    }
  }
  
  close(s);
  
  return r;
}

//---- create the new tunnel interface ---

int
create_tun_iface(const char *name)
{
  int fd;
  struct ifreq ifr;
  
  if ((fd = open(TUN_CTL_DEV,O_RDWR)) != -1) {
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = TUNNEL_MODE;
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s%s", name, "%d");
    
    if (ioctl(fd, TUNSETIFF, (void *)&ifr) != -1) {
      printf("Allocated interface %s.\n", ifr.ifr_name);
      
      if (iff_up(ifr.ifr_name) != -1)
        return fd;
      
    } else {
      printf("Failed to setup tunnel : %s\n", strerror(errno));
    }

  } else
  {
    printf("Failed to open tun control device %s: %s\n", TUN_CTL_DEV, strerror(errno));
  }
  
  close(fd);
  
  return -1;
}

//---- set IP address for interface ---

int
set_ifip(const char *ifname, const char *ip)
{
  int s, r;
  struct ifreq ifr;
  struct sockaddr_in sin;
  
  s = socket(AF_INET, SOCK_STREAM, 0);
  
  memset(&ifr, 0, sizeof(struct ifreq));
  snprintf(ifr.ifr_name, IFNAMSIZ, "%s", ifname);
  
  memset(&sin, 0, sizeof(struct sockaddr_in));
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = inet_addr(ip);
  memcpy(&ifr.ifr_addr, &sin, sizeof(struct sockaddr));
  
  r = ioctl(s, SIOCSIFADDR, (char *)&ifr);
  if (r == -1) {
    printf("Failed to set ip address : %s\n", strerror(errno));
  }
  
  close(s);
  
  return r;
}

//---- send a text string to remote end ---

int
send_message(int sock, uint32_t ip, uint16_t port, const char *str)
{
  struct sockaddr_in to;
  
  to.sin_family = AF_INET;
  to.sin_port = port;
  to.sin_addr.s_addr = ip;
  
  return sendto(sock, str, strlen(str) + 1, 0, (struct sockaddr *)&to, sizeof(to));
}

//---- receive packet from udp socket ---

int
recv_data(int sock, void * buf, int bufsz, struct in_addr *remote_ip)
{
  int r;
  
  struct sockaddr_in from;
  socklen_t fromlen = sizeof(from);
  
  r = recvfrom(sock, buf, bufsz, 0, (struct sockaddr *)&from, &fromlen);
  
  if (r != -1)
    *remote_ip = from.sin_addr;
  else
    printf("Failed to recvfrom : %s\n", strerror(errno));
  
  return r;
}

//---- an event loop linking tunnel with socket ---

int
link_fds(int tun_fd, int udp_sock, uint32_t ip, uint16_t port)
{
  int max_fd, r;
  fd_set fdset;
  char buf[1500];
  
  while (1) {
    FD_ZERO(&fdset);
    FD_SET(tun_fd, &fdset);
    FD_SET(udp_sock, &fdset);
    
    max_fd = (tun_fd > udp_sock) ? tun_fd : udp_sock;
    
    if (select(max_fd + 1, &fdset, NULL, NULL, NULL) < 0) {
      printf("Select error : %s\n", strerror(errno));
      return -1;
    }
    
    if (FD_ISSET(tun_fd, &fdset)) {
      struct sockaddr_in to;

      r = read(tun_fd, buf, sizeof(buf));
      if (r < 0) {
        printf("tun_fd read error : %s\n", strerror(errno));
        return -1;
      }
      
      printf("Read %d bytes from tun\n", r);
      
      memset(&to, 0, sizeof(to));
      to.sin_family = AF_INET;
      to.sin_port = port;
      to.sin_addr.s_addr = ip;
      
      if (sendto(udp_sock, buf, r, 0, (struct sockaddr *)&to, sizeof(to)) < 0) {
        printf("udp_sock send error : %s\n", strerror(errno));
        return -1;
      }
      
    } else {
      struct sockaddr_in from;
      socklen_t fromlen = sizeof(from);
      
      r = recvfrom(udp_sock, buf, sizeof(buf), 0, (struct sockaddr *)&from, &fromlen);
      if (r < 0) {
        printf("udp_sock recv error : %s\n", strerror(errno));
        return -1;
      }
      
      printf("Received %d bytes from sock\n", r);
      
      // if ((from.sin_addr.s_addr != from.sin_addr.s_addr) || (sout.sin_port != from.sin_port))
      if (write(tun_fd, buf, r) < 0) {
        printf("tun_fd write error : %s\n", strerror(errno));
        return -1;
      }
      
    }
  }
}

