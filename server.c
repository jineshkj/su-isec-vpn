/*
 * server part of ivpn software
 * 
 * Copyright (c) 2014 Jinesh J <jineshkj@gmail.com>
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

#include "log.h"
#include "util.h"
#include "error.h"
#include "defaults.h"
#include "control.h"
#include "tcputil.h"

static int port = IVPN_SERV_PORT;

static void 
usage()
{
  printf("Usage: ivpn-client [options] [port]\n");
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

  linfo("Parsing command line options");

  while ((c = getopt(argc, argv, "hd")) != -1) {
    switch (c) {
    case 'h':
      ldbg("Parsed help option");
      usage();
      exit(EXIT_OK);
    case 'd':
      set_log_level(LOG_LEVEL_DBG);
      ldbg("Parsed debug option");
      break;
    default:
      ldbg("Parsed unknown option");
      usage();
      exit(EXIT_CLIOPT_ERR);
    }
  }

  /* get port number */
  if (optind < argc) {
    port = atoi(argv[optind]);
    ldbg ("Parsed port as %u", port);
    optind++;
  }

  if (optind < argc) {
    fprintf(stderr, "ERROR: Extra arguments in command line\n\n");
    usage();
    exit(EXIT_CLIOPT_ERR);
  }
}

static int
run_server()
{
  int listenfd;

  ldbg ("Starting server on port %u", port);

  listenfd = tcputil_create_listener(port, IVPN_TCP_BACKLOG);
  if (listenfd == -1)
    exit(EXIT_TCP_ERROR);

  linfo ("Server started on port %u", port);

  // TODO: need a loop termination mechanism using SIGQUIT signal
  while (1) {
    char client_ip[32];
    int client_port;

    ldbg ("Waiting for connection");

    int connfd = tcputil_accept(listenfd, client_ip, sizeof(client_ip),
                                &client_port);

    if (connfd == -1)
      continue;

    linfo ("New connection from %s:%u", client_ip, client_port);

    // TODO: fork child to handle connection

  }

  return 0;
}

int
main(int argc, char *argv[])
{
  parse_options(argc, argv);

  return run_server();
}



#if 0
/***************************************/

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
  
  return link_fds(tun_fd, udp_sock, client_ip, client_port);
}

#endif
