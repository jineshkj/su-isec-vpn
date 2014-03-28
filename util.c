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

#include "ivpn.h"

#define TUN_CTL_DEV "/dev/net/tun"
#define TUNNEL_MODE IFF_TUN

//---- creates a udp socket bound to a given port ---

int
create_udp_socket(uint16_t port)
{
  int s;
  struct sockaddr_in sin;
  
  if ((s = socket(PF_INET, SOCK_DGRAM, 0)) != -1) {
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
    sin.sin_port = htons(port);
    
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
  
  if (r != -1) {
    /* set the IFF_UP flag */
    ifr.ifr_flags |= IFF_UP;
    r = ioctl(s, SIOCSIFFLAGS, &ifr);
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
