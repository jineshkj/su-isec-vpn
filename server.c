/*
 * server part of ivpn software
 * 
 * Copyright (c) 2014 Jinesh J <jineshkj@gmail.com>
 */

#include <stdio.h>

#include "ivpn.h"

int
ivpn_server(uint16_t port)
{
  printf("ivpn server listening on %u\n", port);
  
  return 0;
}
