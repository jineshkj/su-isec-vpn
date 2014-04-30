#ifndef IVPN_CRYPTUTIL_H
#define IVPN_CRYPTUTIL_H

int
encrypt_data(const void *in, int inlen, void *out, int *outlen,
             const void *iv, const void *key);

int
decrypt_data(const void *in, int inlen, void *out, int *outlen,
             const void *iv, const void *key);

#endif // IVPN_CRYPTUTIL_H
