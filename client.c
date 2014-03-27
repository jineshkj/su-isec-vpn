/*
 * client part of ivpn software
 * 
 * Copyright (c) 2014 Jinesh J <jineshkj@gmail.com>
 */

#include <stdio.h>

#include "ivpn.h"

int
ivpn_client(uint32_t ip, uint16_t port)
{
  printf("ivpn client connecting to %u:%u\n", ip, port);

  return 0;
}
