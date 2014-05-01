/*
 * client part of ivpn software
 * 
 * Copyright (c) 2014 Jinesh J <jineshkj at gmail dot com>
 */

#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <assert.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "log.h"
#include "util.h"
#include "error.h"
#include "defaults.h"
#include "control.h"
#include "tcputil.h"
#include "sslutil.h"
#include "data_endpoint.h"

static const char *username = 0;

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
  char *password;
  data_endpoint_t *ep;
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

  ep = start_data_endpoint();

  assert(ep != 0);

  usleep(100000); // 100 ms

  password = get_password("Password:");
  if (password == 0) {
    return EXIT_PASSWORD;
  }

  ep->peer_port = ivpn_protocol_authenticate(ssl_conn, username, password, ep->udp_port);
  if (ep->peer_port == 0) {
    linfo ("Authentication failed.");
    return EXIT_AUTH_ERROR;
  }
  memset(password, 0, strlen(password)); // clear plain text password

  linfo ("Authenticated with server. Data port is %u", ep->peer_port);

  ep->peer_ip = inet_addr(get_ip_from_name(server));

  write(ep->write_fd, &ep->peer_ip, sizeof(ep->peer_ip));
  write(ep->write_fd, &ep->peer_port, sizeof(ep->peer_port));

  usleep(100000); // 100 ms

  while (1) {
    char command[64];
    fprintf(stdout, "ivpn> ");
    fflush(stdout);
    if (fgets(command, sizeof(command) - 1, stdin) == 0) {
      linfo("End of input. Terminating...");
      break;
    }

    if (strcmp(command, "quit\n") == 0) {
      linfo("Quit command. Terminating...");
      break;
    }

    if (strcmp(command, "changekey\n") == 0) {
      char key[IVPN_KEY_LENGTH];

      linfo("Performing key change.");
      generate_true_random(key, sizeof(key));

      /* send key to local UDP process first */
      if (write(ep->write_fd, key, sizeof(key)) != sizeof(key)) {
        lerr("Unable to send key to local UDP process : %s. Quitting...", strerror(errno));
        break;
      } else
      {
        linfo("New key sent to local UDP process");
      }

      /* send key to VPN server */
      cm_setkey_t *cm = create_cm_setkey(key);
      if (cm == 0) {
        lerr ("Unable to generate command for sending to VPN server. Quitting...");
        break;
      }

      if (send_control_message(ssl_conn, (cm_header_t *)cm) == 0) {
        lerr ("Unable to sending command to VPN server. Quitting...");
        break;
      }

      cm_header_t *rsp = recv_control_message(ssl_conn);
      if (rsp == 0) {
        lerr ("Unable to receive command from VPN server. Quitting...");
        break;
      }

      if (rsp->cm_type == CM_TYPE_OK) {
        linfo("Setting new key in server succeeded");
      } else
      {
        lerr("Setting new key in server failed. Quitting...");
        break;
      }
    }

  }


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
  set_process_name("ivpn-client");

  parse_options(argc, argv);

  if (geteuid() != 0) {
    lerr("Effective UID is %u. It need to be 0.", geteuid());
    return EXIT_FAILURE;
  }

  if (install_sigchld_handler() == 0)
    return EXIT_FAILURE;

  if (username == 0) {
    username = get_current_user();
    if (username == 0)
      exit(EXIT_FAILURE);
  }

  if (!sslutil_init(CA_CERT_FILE, 0, 0))
    return EXIT_SSL_ERROR;

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
