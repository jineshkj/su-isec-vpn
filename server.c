/*
 * server part of ivpn software
 * 
 * Copyright (c) 2014 Jinesh J <jineshkj@gmail.com>
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>

#include "ivpn.h"

static uint32_t client_ip = 0;
static uint16_t client_port = 0;

static int udp_sock = -1;
static int tun_fd = -1;

//---- entry point for ivpn server ---

int
ivpn_server(uint16_t port)
{
  char buf[1500];
  struct in_addr addr;
  
  printf("ivpn server listening on %u\n", ntohs(port));
  
  client_port = port;
  
  if ((udp_sock = create_udp_socket(port)) == -1)
    return -1;
  
  if ((tun_fd = create_tun_iface("ivpn")) == -1)
    return -1;
  
//   if (set_ifip("ivpn0", "10.0.88.1") == -1)
//     return -1;
//   
  system("ip addr add 10.0.88.1/24 dev ivpn0");
  system("route add -net 10.0.44.0 netmask 255.255.255.0 dev ivpn0");
  
  if (recv_data(udp_sock, buf, sizeof(buf), &addr) == -1) {
    return -1;
  }
  buf[sizeof(buf) - 1] = '\0';
  
  printf("Received message : %s\n", buf);
  
  if (strcmp(buf, "Hello ivpn !!") == 0) {
    printf("Connection established from %s\n", inet_ntoa(addr));
    client_ip = addr.s_addr;
  }
  
  while (1) {
    printf(".");
    fflush(stdout);
    sleep(1);
  }
  
  return 0;
}
