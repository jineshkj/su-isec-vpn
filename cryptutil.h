#ifndef IVPN_CRYPTUTIL_H
#define IVPN_CRYPTUTIL_H

int
encrypt_data(const void *in, int inlen, void *out, int *outlen,
             const void *iv, const void *key);

int
decrypt_data(const void *in, int inlen, void *out, int *outlen,
             const void *iv, const void *key);

int
hmac_data(const void *in, int inlen, const void *key, void *out, int *outlen);

int
hmac_verify(const void *data, int datalen, const void *key, const void *hmac);

#endif // IVPN_CRYPTUTIL_H
