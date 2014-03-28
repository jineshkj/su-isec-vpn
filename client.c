/*
 * client part of ivpn software
 * 
 * Copyright (c) 2014 Jinesh J <jineshkj@gmail.com>
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include "ivpn.h"

static uint32_t server_ip = 0;
static uint16_t server_port = 0;

static int udp_sock = -1;
static int tun_fd = -1;

//---- entry point for ivpn client ---

int
ivpn_client(uint32_t ip, uint16_t port)
{
  struct in_addr addr;
  addr.s_addr = ip;
  
  printf("ivpn client connecting to %s:%u\n", inet_ntoa(addr), ntohs(port));
  
  server_ip = ip;
  server_port = port;
  
  if ((udp_sock = create_udp_socket(port)) == -1)
    return -1;
  
  if ((tun_fd = create_tun_iface("ivpn")) == -1)
    return -1;
  
//   if (set_ifip("ivpn0", "10.0.44.1") == -1)
//     return -1;
//   
  
  system("ip addr add 10.0.44.1/24 dev ivpn0");
  system("route add -net 10.0.88.0 netmask 255.255.255.0 dev ivpn0");
  
  send_message(udp_sock, ip, port, "Hello ivpn !!");
  
  return link_fds(tun_fd, udp_sock, server_ip, server_port);
}
