/*
 * server part of ivpn software
 * 
 * Copyright (c) 2014 Jinesh J <jineshkj@gmail.com>
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "log.h"
#include "util.h"
#include "error.h"
#include "defaults.h"
#include "control.h"
#include "tcputil.h"
#include "sslutil.h"

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


//static int
//control_channel_handler(sslutil_connection_t conn)
//{
//  int r;
//  int rbytes = 0;
//  char buffer[65536]; // TODO: move to static memory
//  cm_header_t *hdr = (cm_header_t *) buffer;
//
//  while (1) {
//    // TODO: process control messages from client
//    linfo("Waiting for control message from client");
//
//    r = sslutil_read(conn, buffer + rbytes, sizeof(cm_header_t) - rbytes);
//    if (r < 0) {
//      lerr ("Not able to read from SSL connection. Terminating.");
//      return EXIT_SSL_ERROR;
//    }
//
//    if (r == 0)
//      break;
//
//    rbytes += r;
//    if (rbytes == sizeof(cm_header_t)) {
//      rbytes = 0;
//
//    }
//  }
//
//  return EXIT_OK;
//}

static int
process_auth_password(sslutil_connection_t conn, cm_auth_password_t *ap)
{
  linfo("Processing password based authentication");

  ldbg("User = %s", ap->username);
  ldbg("Pass = %s", ap->password);

  cm_header_t *rsp = (cm_header_t *) create_cm_auth_response(CM_AUTH_OK, 12345);

  if (send_control_message(conn, rsp))
    return EXIT_OK;

  return EXIT_AUTH_ERROR;
}

static int
process_auth(sslutil_connection_t conn, cm_auth_t *auth)
{
  int ret = EXIT_OK;

  switch (auth->type)
  {
  case CM_AUTH_PASSWORD:
    ret = process_auth_password(conn, (cm_auth_password_t *) auth);
    break;

  default:
    lerr("Unknown authentication type %u", auth->type);
    break;
  }

  return ret;
}

static int
process_control_message(sslutil_connection_t conn, cm_header_t *cm)
{
  int ret = EXIT_OK;

  switch (cm->cm_type)
  {
  case CM_TYPE_AUTH:
    ret = process_auth(conn, (cm_auth_t *) cm);
    break;

  default:
    lerr("Unknown control message type %u", cm->cm_type);
    break;
  }

  return ret;
}

static int
control_channel_handler(int connfd)
{
  int ret = 0;
  sslutil_connection_t ssl_conn;

  linfo("Connection handler started. Initiating SSL handshake.");

  ssl_conn = sslutil_accept(connfd);
  if (ssl_conn == 0) {
    linfo("Unable to start SSL session");
    return EXIT_SSL_ERROR;
  }

  if (!ivpn_protocol_handshake(ssl_conn))
    return EXIT_PROTO_ERROR;

  linfo ("IVPN Protocol handshake completed successfully.");

  while (1) {
    cm_header_t *cm = recv_control_message(ssl_conn);
    if (cm == 0) {
      lerr("Control channel terminated. Stopping.");
      break;
    }

    linfo("Received control message of %u bytes", cm->cm_len);

    ret = process_control_message(ssl_conn, cm);
    if (ret != EXIT_OK)
      break;
  }

  // TODO: terminate gracefully.

  return ret;
}

static pid_t
fork_connection_handler(int connfd)
{
  pid_t childpid;

  childpid = fork();
  switch (childpid)
  {
  case -1:
    lerr ("Could not create child process : %s", strerror(errno));
    break;

  case 0: // child
    exit(control_channel_handler(connfd)); // exit() so we do not return back
    break;

  default: // parent
    break;
  }

  return childpid;
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
    int client_port = 0;
    pid_t conn_handler = 0;

    ldbg ("Waiting for connection");

    int connfd = tcputil_accept(listenfd, client_ip, sizeof(client_ip),
                                &client_port);

    if (connfd == -1)
      continue;

    linfo ("New connection from %s:%u", client_ip, client_port);

    /* start connection handler process */
    if ((conn_handler = fork_connection_handler(connfd)) == -1) {
      lerr ("Unable to start connection handler");
    } else {
      linfo ("Connection handler running as PID %u", conn_handler);
    }

    close (connfd); // connection handler process will use it further
  }

  return 0;
}

int
main(int argc, char *argv[])
{
  parse_options(argc, argv);

  sslutil_init(CA_CERT_FILE, SERVER_CERT_FILE, SERVER_KEY_FILE);

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
