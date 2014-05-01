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
#include <assert.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include "log.h"
#include "util.h"
#include "error.h"
#include "defaults.h"
#include "control.h"
#include "tcputil.h"
#include "sslutil.h"
#include "udputil.h"
#include "data_endpoint.h"

static int port = IVPN_SERV_PORT;
static char client_ip[32];
static data_endpoint_t *ep = 0;
static int quit_process = 0;

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
process_auth_password(sslutil_connection_t conn, cm_auth_password_t *ap)
{
  linfo("Processing password based authentication");

  ldbg("User = %s", ap->username);
  ldbg("Pass = %s", ap->password);

  if (authenticate_user(ap->username, ap->password)) {
    cm_header_t * rsp;

    ep = start_data_endpoint();

    assert (ep != 0);

    rsp = (cm_header_t *) create_cm_auth_response(CM_AUTH_OK, ep->udp_port);

    ep->peer_ip = inet_addr(client_ip);
    ep->peer_port = ntohs(ap->auth.port);
    write(ep->write_fd, &ep->peer_ip, sizeof(ep->peer_ip));
    write(ep->write_fd, &ep->peer_port, sizeof(ep->peer_port));

    if (send_control_message(conn, rsp))
      return EXIT_OK;
  } else
  {
    cm_header_t *rsp = (cm_header_t *) create_cm_auth_response(CM_AUTH_FAIL, 0);

    if (send_control_message(conn, rsp))
      return EXIT_OK;
  }

  return EXIT_PROTO_ERROR;
}

static int
process_auth(sslutil_connection_t conn, cm_auth_t *auth)
{
  int ret = EXIT_OK;

  switch (auth->type)
  {
  case CM_AUTH_PASSWORD:
    ret = process_auth_password(conn, (cm_auth_password_t *) auth);
    memset(auth, 0, sizeof(cm_auth_password_t)); // clear plain text password
    break;

  default:
    lerr("Unknown authentication type %u", auth->type);
    break;
  }

  return ret;
}

static int
process_setkey(sslutil_connection_t conn, cm_setkey_t *sk)
{
  if (ep == 0) {
    lerr("Unable to set new key since data endpoint not yet running");
    return -1;
  }

  cm_header_t response;

  response.cm_len = sizeof(response);

  /* send key to local UDP process */
  if (write(ep->write_fd, sk->key, sizeof(sk->key)) != sizeof(sk->key)) {
    lerr("Unable to send new key to UDP process : %s", strerror(errno));
    response.cm_type = CM_TYPE_FAIL;
  } else
  {
    linfo("New key sent to local UDP process");
    response.cm_type = CM_TYPE_OK;
  }
  memset(sk, 0, sizeof(sk));

  cm_header_hton(&response);
  if (send_control_message(conn, &response) == 0) {
    lerr("Unable to send response back to client. Terminating...");
    quit_process = 1;
  }

  return EXIT_OK;
}

static int
process_control_message(sslutil_connection_t conn, cm_header_t *cm)
{
  int ret = EXIT_OK;

  switch (cm->cm_type)
  {
  case CM_TYPE_SETKEY:
    ret = process_setkey(conn, (cm_setkey_t*)cm);
    break;

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

  while (!quit_process) {
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
  set_process_name("ivpn-server");

  parse_options(argc, argv);

  if (geteuid() != 0) {
    lerr("Effective UID is %u. It need to be 0.", geteuid());
    return EXIT_FAILURE;
  }

  if (install_sigchld_handler() == 0)
    return EXIT_FAILURE;

  if (!sslutil_init(CA_CERT_FILE, SERVER_CERT_FILE, SERVER_KEY_FILE))
    return EXIT_SSL_ERROR;

  return run_server();
}
