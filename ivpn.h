#ifndef ISEC_IVPN_H
#define ISEC_IVPN_H
/*
 * Main header file for ivpn software
 * 
 * Copyright (c) 2014 Jinesh J <jineshkj@gmail.com>
 */

#include <stdint.h>

/* define various exit errors */
#define EX_GOOD         0
#define EX_CLIOPT_ERR   1

#define DEFAULT_PORT  55555

extern int DEBUG_LEVEL;

int
ivpn_server(uint16_t port);

int
ivpn_client(uint32_t ip, uint16_t port);

int
create_udp_socket(uint16_t port);

int
create_tun_iface(const char *name);

#endif // ISEC_IVPN_H
