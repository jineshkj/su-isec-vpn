
#include <assert.h>

#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "log.h"

#include "sslutil.h"

static SSL_CTX *ssl_client_ctx = 0;
static SSL_CTX *ssl_server_ctx = 0;

static inline void
log_ssl_err(const char *prefix)
{
  long e = ERR_get_error();
  lerr ("%s : %lu - %s", prefix, e, ERR_reason_error_string(e));
}

static int
valid_peer_common_name(SSL *ssl, const char *CN)
{
  X509 *peer_cert;
  char  peer_name[256];

  peer_cert = SSL_get_peer_certificate (ssl);
  if (peer_cert == 0) {
    log_ssl_err ("Not able to find peer certificate");
    return 0;
  }

  if (X509_NAME_get_text_by_NID(X509_get_subject_name(peer_cert),
                                NID_commonName, peer_name,
                                sizeof(peer_name)) == -1) {
    log_ssl_err ("CN not found in peer certificate");
    peer_name[0] = '\0';
  }

  X509_free (peer_cert);

  if (strcmp(peer_name, CN) != 0) {
    lerr ("Peer certificate Common Name is %s. Expected %s", peer_name, CN);
    return 0;
  }

  return 1;
}

/* returns 1 on success, 0 on failure */
int
sslutil_init(const char *cacert_file, const char *certfile, 
             const char *keyfile)
{
  SSLeay_add_ssl_algorithms();
  SSL_load_error_strings();

  ERR_clear_error();
  
  if (!ssl_client_ctx)
    ssl_client_ctx = SSL_CTX_new (SSLv23_client_method());
  
  if (ssl_client_ctx == 0) {
    log_ssl_err ("Unable to create SSL client context");
    goto FAILURE;
  }
  
  if (!ssl_server_ctx)
    ssl_server_ctx = SSL_CTX_new (SSLv23_server_method());
  
  if (ssl_server_ctx == 0) {
    log_ssl_err ("Unable to create SSL server context");
    goto FAILURE;
  }
  
  /* load custom CA certificate if given */
  if (cacert_file) {
    SSL_CTX_load_verify_locations(ssl_client_ctx, cacert_file, NULL);
    SSL_CTX_load_verify_locations(ssl_server_ctx, cacert_file, NULL);
  }
  
  /* set server certificate and private key if given */
  if (certfile && SSL_CTX_use_certificate_file(ssl_server_ctx, certfile, 
   SSL_FILETYPE_PEM) != 1) {
    log_ssl_err ("Unable to load server certificate");
    goto FAILURE;
  }
  
  if (keyfile && SSL_CTX_use_PrivateKey_file(ssl_server_ctx, keyfile,
   SSL_FILETYPE_PEM) != 1) {
    log_ssl_err ("Unable to load server private key");
      goto FAILURE;
  }

  if (certfile || keyfile) {
    if (SSL_CTX_check_private_key(ssl_server_ctx) != 1) {
      log_ssl_err (
          "Server certificate does not validate with the given private key");
      goto FAILURE;
    }
  }

  return 1;

FAILURE:
  if (ssl_client_ctx) {
    SSL_CTX_free(ssl_client_ctx);
    ssl_client_ctx = 0;
  }
  
  if (ssl_server_ctx) {
    SSL_CTX_free(ssl_server_ctx);
    ssl_server_ctx = 0;
  }
  
  return 0;
}

sslutil_connection_t
sslutil_connect(int sock, const char *CN)
{
  SSL *ssl = 0;
  
  assert (ssl_client_ctx != 0);
  
  ERR_clear_error();

  ssl = SSL_new (ssl_client_ctx);
  if (ssl == 0) {
    log_ssl_err ("Unable to create SSL client object");
    return 0;
  }
  
  SSL_set_verify(ssl, SSL_VERIFY_PEER, NULL);
    
  if (SSL_set_fd (ssl, sock) != 1) {
    log_ssl_err ("Unable to set FD for SSL object");
    SSL_free(ssl);
    return 0;
  }
  
  if (SSL_connect (ssl) != 1) {
    log_ssl_err ("Unable to complete SSL connection");
    SSL_free(ssl);
    return 0;
  }

  /* client need to verify server's certificate */
  if (SSL_get_verify_result(ssl) != X509_V_OK) {
    log_ssl_err ("Unable to successfully verify SSL protocol");
    SSL_free(ssl);
    return 0;
  }
  
  if (!valid_peer_common_name(ssl, CN)) {
    lerr ("Peer certificate validation failed");
    SSL_free(ssl);
    return 0;
  }

  return (sslutil_connection_t) ssl;
}

sslutil_connection_t
sslutil_accept(int sock)
{
  SSL *ssl = 0;
  
  assert (ssl_server_ctx != 0);
  
  ERR_clear_error();

  ssl = SSL_new (ssl_server_ctx);
  if (ssl == 0) {
    log_ssl_err ("Unable to create SSL server object");
    return 0;
  }
  
  /* VPN server will not be verifiying the client's certificate */
  SSL_set_verify(ssl, SSL_VERIFY_NONE, NULL);
    
  if (SSL_set_fd (ssl, sock) != 1) {
    log_ssl_err ("Unable to set FD for SSL object");
    SSL_free(ssl);
    return 0;
  }
  
  if (SSL_accept(ssl) != 1) {
    log_ssl_err ("Unable to perform SSL accept");
    SSL_free(ssl);
    return 0;
  }
  
  return (sslutil_connection_t) ssl;
}

int
sslutil_read(sslutil_connection_t c, void *buf, int siz)
{
  int ret;
  
  ERR_clear_error();

  if ((ret = SSL_read((SSL *) c, buf, siz)) < 0)
    log_ssl_err ("Read failed on SSL object");
  
  return ret;
}

int
sslutil_write(sslutil_connection_t c, const void *buf, int siz)
{
  int ret;
  
  ERR_clear_error();

  if ((ret = SSL_write((SSL *) c, buf, siz)) < 0)
    log_ssl_err ("Write failed on SSL object");
  
  return ret;
}

int
sslutil_read_all(sslutil_connection_t c, void *buf, int siz)
{
  int rbytes = 0;

  while (siz > 0) {
    int r = sslutil_read(c, buf + rbytes, siz);
    if (r < 0)
      return -1;

    if (r == 0) // probably end of connection
      break;

    rbytes += r;
    siz -= r;
  }

  return rbytes;
}

int
sslutil_write_all(sslutil_connection_t c, const void *buf, int siz)
{
  int wbytes = 0;

  while (siz > 0) {
    int w = sslutil_write(c, buf + wbytes, siz);
    if (w < 0)
      return -1;

    if (w == 0) // probably end of connection
      break;

    wbytes += w;
    siz -= w;
  }

  return wbytes;
}
