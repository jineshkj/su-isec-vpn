
#include "data_endpoint.h"

#include "log.h"
#include "util.h"
#include "error.h"
#include "udputil.h"
#include "cryptutil.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <assert.h>
#include <stdlib.h>

#include <netinet/in.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <arpa/inet.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>

#define TUN_CTL_DEV "/dev/net/tun"
#define TUNNEL_MODE IFF_TUN

#define NUM_PIPES     2

#define PIPE_READ_FD  0
#define PIPE_WRITE_FD 1

#define CHILD_READ_PIPE  0
#define CHILD_WRITE_PIPE 1

#define PARENT_READ_PIPE  CHILD_WRITE_PIPE
#define PARENT_WRITE_PIPE CHILD_READ_PIPE

static int pipes[NUM_PIPES][2] = { { -1, -1 }, {-1, -1 } };

#define CHILD_READ_FD  pipes[CHILD_READ_PIPE][PIPE_READ_FD]
#define CHILD_WRITE_FD pipes[CHILD_WRITE_PIPE][PIPE_WRITE_FD]

#define PARENT_READ_FD  pipes[PARENT_READ_PIPE][PIPE_READ_FD]
#define PARENT_WRITE_FD pipes[PARENT_WRITE_PIPE][PIPE_WRITE_FD]

static int quit_process = 0;
static unsigned char key[IVPN_KEY_LENGTH];

static inline void
close_parent_pipes()
{
  close(PARENT_READ_FD); PARENT_READ_FD = -1;
  close(PARENT_WRITE_FD); PARENT_WRITE_FD = -1;
}

static inline void
close_child_pipes()
{
  close(CHILD_READ_FD); CHILD_READ_FD = -1;
  close(CHILD_WRITE_FD); CHILD_WRITE_FD = -1;
}

static inline void
close_pipes()
{
  close_parent_pipes();
  close_child_pipes();
}

static inline int
create_pipes()
{
  if (pipe(pipes[CHILD_READ_PIPE]) == -1) {
    lerr("Unable to create pipe : %s", strerror(errno));
    return 0;
  }

  if (pipe(pipes[CHILD_WRITE_PIPE]) == -1) {
    lerr("Unable to create pipe : %s", strerror(errno));
    close_child_pipes();
    return 0;
  }

  return 1;
}

static int
set_mtu(const char *ifname, int mtu)
{
  char command[256];

  snprintf(command, sizeof(command), "ifconfig %s mtu %u", ifname, mtu);
  return system(command);
}

//---- create the new tunnel interface ---

int
create_tun_iface()
{
  int tun_fd;
  struct ifreq ifr;

  if ((tun_fd = open(TUN_CTL_DEV, O_RDWR)) == -1) {
    lerr("Unable to open tunnel control device %s : %s", TUN_CTL_DEV,
         strerror(errno));
    return -1;
  }

  memset(&ifr, 0, sizeof(ifr));
  ifr.ifr_flags = TUNNEL_MODE;
  snprintf(ifr.ifr_name, IFNAMSIZ, "%s%s", "ivpn", "%d");

  if (ioctl(tun_fd, TUNSETIFF, (void *)&ifr) == -1) {
    lerr("Failed to setup tunnel %s", strerror(errno));
    close(tun_fd);
    return -1;
  }

  linfo("Allocated interface %s", ifr.ifr_name);

  set_mtu(ifr.ifr_name, IVPN_TUNNEL_MTU); // just to avoid IP fragmentation

  return tun_fd;
}


static int
process_event_on_tunnel(data_endpoint_t *ep)
{
  int t;
  int n;
  int hmaclen;

  static unsigned char tunnel_data[IVPN_DATA_ENDPOINT_BUFSIZ];
  static unsigned char network_data[IVPN_DATA_ENDPOINT_BUFSIZ];
  unsigned char *iv = network_data;

  struct sockaddr_in to;

  if ((t = read(ep->tun_fd, tunnel_data, sizeof(tunnel_data))) < 0) {
    lerr("tun_fd read error : %s", strerror(errno));
    return -1;
  }

  ldbg("Read %d bytes from tunnel", t);

  memset(&to, 0, sizeof(to));
  to.sin_family = AF_INET;
  to.sin_port = htons(ep->peer_port);
  to.sin_addr.s_addr = ep->peer_ip;

  memset(key, 0, sizeof(key)); // ??

  /* add 32 byte IV first */
  generate_pseudo_random(iv, IVPN_IV_LENGTH);

  /* add encrypted data now */
  if (!encrypt_data(tunnel_data, t, network_data + IVPN_IV_LENGTH, &n, iv, key)) {
    lerr("Not able to encrypt data");
    return -1;
  }

  ldbg("Encrypted data contains %d bytes", n);

  n += IVPN_IV_LENGTH;

  /* add HMAC for the entire encrypted packet */
  if (!hmac_data(network_data, n, key, network_data + n, &hmaclen)) {
    return -1;
  }

  assert(hmaclen == IVPN_HMAC_LENGTH);

  n += hmaclen;

  if (sendto(ep->udp_sock, network_data, n, 0, (struct sockaddr *)&to, sizeof(to)) < n) {
    lerr("udp_sock send error : %s", strerror(errno));
    return -1;
  }

  return t;
}

static int
process_event_on_udp(data_endpoint_t *ep)
{
  int n;
  int t;
  static unsigned char network_data[IVPN_DATA_ENDPOINT_BUFSIZ]; // should be enough since MTU is just 1500
  static unsigned char tunnel_data[IVPN_DATA_ENDPOINT_BUFSIZ];
  unsigned char *iv = network_data;

  struct sockaddr_in from;
  socklen_t fromlen = sizeof(from);

  n = recvfrom(ep->udp_sock, network_data, sizeof(network_data), 0, (struct sockaddr *)&from, &fromlen);
  if (n < 0) {
    lerr("udp_sock receive error : %s", strerror(errno));
    return -1;
  }

  ldbg("Received %d bytes from sock", n);

  memset(key, 0, sizeof(key));

  /* verify hmac */
  n -= IVPN_HMAC_LENGTH;
  if (!hmac_verify(network_data, n, key, network_data + n)) {
    lerr("HMAC verification for data failed. Discarding packet.");
    return -1;
  }

  /* decrypt data */
  n -= IVPN_KEY_LENGTH;
  if (!decrypt_data(network_data + IVPN_KEY_LENGTH, n, tunnel_data, &t, iv, key)) {
    lerr("Not able to encrypt data");
    return -1;
  }

  ldbg("Decrypted %d bytes", t);

  // if ((from.sin_addr.s_addr != from.sin_addr.s_addr) || (sout.sin_port != from.sin_port))
  if (write(ep->tun_fd, tunnel_data, t) < t) {
    lerr("tun_fd write error : %s", strerror(errno));
    return -1;
  }

  return n;
}

static int
process_event_on_pipe(data_endpoint_t *ep)
{
  int r;

  r = read(ep->read_fd, key, sizeof(key));

  ldbg ("Read %d bytes from control pipe, %d", r, sizeof(key));

  if (r < sizeof(key)) {
    lerr("Error reading from control pipe. Quitting process.");
    quit_process = 1;
    return -1;
  }

  linfo("New key received by local UDP process");

  return 0;
}


//---- an event loop linking tunnel with socket ---

static int
data_endpoint_event_loop(data_endpoint_t *ep)
{
  int max_fd;
  fd_set fdset;

  linfo("Data end-point event loop started");

  while (!quit_process) {
    // TODO: replace select() with epoll()
    FD_ZERO(&fdset);
    FD_SET(ep->tun_fd, &fdset);
    FD_SET(ep->udp_sock, &fdset);
    FD_SET(ep->read_fd, &fdset);

    max_fd = (ep->tun_fd > ep->udp_sock) ? ep->tun_fd : ep->udp_sock;
    if (ep->read_fd > max_fd)
      max_fd = ep->read_fd;

    if (select(max_fd + 1, &fdset, NULL, NULL, NULL) < 0) {
      lerr("Select error : %s", strerror(errno));
      return -1;
    }

    if (FD_ISSET(ep->tun_fd, &fdset)) {
      process_event_on_tunnel(ep);
    } else if (FD_ISSET(ep->udp_sock, &fdset)) {
      process_event_on_udp(ep);
    } else {
      process_event_on_pipe(ep);
    }
  }

  linfo("Data end-point event loop ended");

  return 0;
}

static int
data_endpoint_main(data_endpoint_t *ep)
{
  struct in_addr in;
  ssize_t r1, r2;

  linfo("Waiting for peer IP and port");

  /* wait for the control end point to send you the peer IP and
     port number */
  r1 = read(ep->read_fd, &ep->peer_ip, sizeof(ep->peer_ip));
  r2 = read(ep->read_fd, &ep->peer_port, sizeof(ep->peer_port));

  if (r1 != sizeof(ep->peer_ip) || r2 != sizeof(ep->peer_port)) {
    lerr("UDP end-point process terminating due to TCP end-point termination");
    return EXIT_PROTO_ERROR;
  }

  in.s_addr = ep->peer_ip;
  linfo("Peer IP = %s, port = %u", inet_ntoa(in), ntohs(ep->peer_port));


  return data_endpoint_event_loop(ep);
}

data_endpoint_t *
start_data_endpoint()
{
  static data_endpoint_t ep; // expecting only one data end point

  if (ep.pid != 0) {
    lerr("Can not start data end point. Already running.");
    return 0;
  }

  memset(&ep, 0, sizeof(ep));

  ep.tun_fd = create_tun_iface();
  if (ep.tun_fd == -1)
    goto ERR_EXIT;

  ep.udp_sock = create_udp_socket();
  if (ep.udp_sock == -1)
    goto ERR_EXIT;

  ep.udp_port = get_udp_port(ep.udp_sock);
  if (ep.udp_port == 0)
    goto ERR_EXIT;

  if (!create_pipes())
    goto ERR_EXIT;

  ep.pid = fork();
  switch (ep.pid)
  {
  case -1:
    lerr ("Could not create child process for data end point: %s",
          strerror(errno));
    ep.pid = 0;
    goto ERR_EXIT;
    break;

  case 0: // child
    ep.read_fd = CHILD_READ_FD;
    ep.write_fd = CHILD_WRITE_FD;

    close_parent_pipes();

    exit(data_endpoint_main(&ep)); // exit() so we do not return back
    break;

  default: // parent
    linfo("Data end point process started as PID %u", ep.pid);

    ep.read_fd = PARENT_READ_FD;
    ep.write_fd = PARENT_WRITE_FD;

    close_child_pipes();

    close(ep.tun_fd); ep.tun_fd = -1;
    close(ep.udp_sock); ep.udp_sock = -1;
    break;
  }

  return &ep;

ERR_EXIT:
  if (ep.tun_fd != -1) {
    close(ep.tun_fd); ep.tun_fd = -1;
  }

  if (ep.udp_sock != -1) {
    close(ep.udp_sock); ep.udp_sock = -1;
  }

  close_pipes();

  memset(&ep, 0, sizeof(ep)); // just in case

  return 0;
}
