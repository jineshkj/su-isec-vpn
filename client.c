/*
 * client part of ivpn software
 * 
 * Copyright (c) 2014 Jinesh J <jineshkj at gmail dot com>
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
#include "sslutil.h"

static const char *username = 0;
static const char *password = 0;

static const char *server = 0;
static int port = IVPN_SERV_PORT;

static void 
usage()
{
  printf("Usage: ivpn-client [options] server [port]\n");
  printf("\n");
  printf("Options:\n");
  printf("  -u : user name\n");
  printf("  -h : print help\n");
  printf("  -d : increase debug level\n");
  printf("\n");
}

//---- parse program CLI parameters ---

static void 
parse_options(int argc, char **argv)
{
  int c;
  
  while ((c = getopt(argc, argv, "u:hd")) != -1) {
    switch (c) {
    case 'h':
      usage();
      exit(EXIT_OK);
    case 'd':
      set_log_level(LOG_LEVEL_DBG);
      break;
    case 'u':
      username = optarg;
      break;
    default:
      usage();
      exit(EXIT_CLIOPT_ERR);
    }
  }

  /* get server hostname */
  if (optind < argc) {
    server = argv[optind];
    ldbg ("Parsed server host name as %s", server);
    optind++;
  } else
  {
    fprintf(stderr, "ERROR: IVPN server hostname required\n\n");
    usage();
    exit(EXIT_CLIOPT_ERR);
  }
  
  /* get the optional port number */
  if (optind < argc) {
    port = atoi(argv[optind]);
    ldbg ("Parsed server port as %u", port);
    optind++;
  }
  
  if (optind < argc) {
    fprintf(stderr, "ERROR: Extra arguments in command line\n\n");
    usage();
    exit(EXIT_CLIOPT_ERR);
  }
}

static int
control_channel_handler(int connfd)
{
  int data_port = 0;
  sslutil_connection_t ssl_conn;

  linfo("Connection handler started. Initiating SSL handshake.");

  ssl_conn = sslutil_connect(connfd, server);
  if (ssl_conn == 0) {
    linfo("Unable to start SSL session");
    return EXIT_SSL_ERROR;
  }

  if (!ivpn_protocol_handshake(ssl_conn))
    return EXIT_PROTO_ERROR;

  linfo ("IVPN Protocol handshake completed successfully.");

  data_port = ivpn_protocol_authenticate(ssl_conn, username, password);
  if (data_port == 0) {
    linfo ("Authentication failed.");
    return EXIT_AUTH_ERROR;
  }

  linfo ("Authenticated with server. Data port is %u", data_port);

  return 0;
}

static int
run_client()
{
  int connfd = -1;

  ldbg ("Client attempting to connect to %s:%u", server, port);

  connfd = tcputil_connect(server, port);
  if (connfd == -1)
    return -1;

  linfo ("Connected to %s:%u", server, port);

  return control_channel_handler(connfd);
}

int
main(int argc, char *argv[])
{
  parse_options(argc, argv);
  
  if (username == 0) {
    username = get_current_user();
    if (username == 0)
      exit(EXIT_FAILURE);
  }

  password = get_password("Password:");
  if (password == 0) {
    exit(EXIT_PASSWORD);
  }
  
  sslutil_init(CA_CERT_FILE, 0, 0);

  return run_client();
}

#if 0
/***********************/


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
  
  // connect to tcp server
  // read tcp server port number
  // create pipe, set non-block
  // fork child process
  
  // PARENT
  // -------
  // send key and iv to server
  // send key and iv to child
  // scanf() from command line in loop for commands
  
  // CHILD
  // -----
  // all operations as before
  // select() on pipe, udp and tun in loop
  // add support for encryption/decryption
  // add HMAC
  
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

#endif
