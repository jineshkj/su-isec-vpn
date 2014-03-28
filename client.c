/*
 * client part of ivpn software
 * 
 * Copyright (c) 2014 Jinesh J <jineshkj@gmail.com>
 */

#include <stdio.h>
#include <unistd.h>

#include "ivpn.h"

static int recv_sock = -1;
static int tun_fd = -1;

//---- entry point for ivpn client ---

int
ivpn_client(uint32_t ip, uint16_t port)
{
  printf("ivpn client connecting to %u:%u\n", ip, port);

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
