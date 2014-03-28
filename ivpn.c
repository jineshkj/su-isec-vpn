/*
 * Main source file for ivpn software
 * 
 * Copyright (c) 2014 Jinesh J <jineshkj@gmail.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <stdint.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "ivpn.h"

int DEBUG_LEVEL = 0;

static uint16_t PORT = DEFAULT_PORT;
static uint32_t REMOTE_IP = 0; // will be non-zero when program is client

//---- print program usage ---

static void 
usage()
{
  printf("Usage: ivpn [options] [[server ip] <port>]\n");
  printf("\n");
  printf("Options:\n");
  printf("  -h : print help\n");
  printf("  -d : increase debug level\n");
  printf("\n");
}

//---- parse program CLI parameters ---

static void 
parse_options(int argc, char **argv)
{
  int c;
  
  while ((c = getopt(argc, argv, "s:hd")) != -1) {
    switch (c) {
    case 'h':
      usage();
      exit(EX_GOOD);
    case 'd':
      DEBUG_LEVEL++;
      break;
//     case 's':
//       MODE = 1;
//       PORT = atoi(optarg);
//       break;
    default:
      usage();
      exit(EX_CLIOPT_ERR);
    }
  }
  
  if ((argc - optind) > 2)
  {
    printf("Extra parameters in command line\n\n");
    usage();
    exit(EX_CLIOPT_ERR);
  }
  
  if (optind < argc) {
    PORT = atoi(argv[argc-1]);
    
    if ((argc - optind) == 2) {
      struct in_addr addr;
      
      (void) inet_aton(argv[argc - 2], &addr);
      REMOTE_IP = addr.s_addr;
    }
  }
}

//---- main function of vpn software ---

int 
main(int argc, char *argv[])
{
  parse_options(argc, argv);
  
  if (REMOTE_IP != 0) {
    return ivpn_client(REMOTE_IP, PORT);
  } else
  {
    return ivpn_server(PORT);
  }
}
