#ifndef ISEC_SSLUTIL_H
#define ISEC_SSLUTIL_H

typedef void * sslutil_connection_t;

int
sslutil_init(const char *cacert_file, const char *certfile, 
             const char *keyfile);

sslutil_connection_t
sslutil_connect(int sock, const char *CN);

sslutil_connection_t
sslutil_accept(int sock);

int
sslutil_read(sslutil_connection_t c, void *buf, int siz);

int
sslutil_write(sslutil_connection_t c, const void *buf, int siz);

#endif // ISEC_SSLUTIL_H
