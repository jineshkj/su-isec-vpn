/*
 * utility functions ivpn software
 * 
 * Copyright (c) 2014 Jinesh J <jineshkj@gmail.com>
 */

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>

#include "ivpn.h"

#define TUN_CTL_DEV "/dev/net/tun"
#define TUNNEL_MODE IFF_TUN

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
  
  memset(&to, 0, sizeof(to));
  
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
  
  memset(&from, 0, sizeof(from));
  r = recvfrom(sock, buf, bufsz, 0, (struct sockaddr *)&from, &fromlen);
  
  if (r != -1)
    *remote_ip = from.sin_addr;
  else
    printf("Failed to recvfrom : %s\n", strerror(errno));
  
  return r;
}
