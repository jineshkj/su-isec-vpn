/*
 * server part of ivpn software
 * 
 * Copyright (c) 2014 Jinesh J <jineshkj@gmail.com>
 */

#include <stdio.h>
#include <unistd.h>

#include "ivpn.h"

static int recv_sock = -1;
static int tun_fd = -1;

//---- entry point for ivpn server ---

int
ivpn_server(uint16_t port)
{
  printf("ivpn server listening on %u\n", port);
  
  if ((recv_sock = create_udp_socket(port)) == -1)
    return -1;
  
  if ((tun_fd = create_tun_iface("ivpn")) == -1)
    return -1;
  
  while (1) {
    printf(".");
    fflush(stdout);
    sleep(1);
  }
  
  return 0;
}
