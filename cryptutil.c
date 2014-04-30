
#include "defaults.h"

#include "log.h"
#include "cryptutil.h"

#include <openssl/err.h>
#include <openssl/evp.h>

static EVP_CIPHER_CTX ctx;
static int initialized = 0;

static inline void
log_crypt_err(const char *prefix)
{
  long e = ERR_get_error();
  lerr ("%s : %lu - %s", prefix, e, ERR_reason_error_string(e));
}

static inline void
cryptutil_init()
{
  ERR_clear_error();

  if (initialized)
    return;

  EVP_CIPHER_CTX_init(&ctx);
  ERR_load_crypto_strings();

  initialized = 1;
}

int
encrypt_data(const void *in, int inlen, void *out, int *outlen,
             const void *iv, const void *key)
{
  int len;

  cryptutil_init();

   /* In this we are using 256 bit AES (i.e. a 256 bit key). The
    * IV size for *most* modes is the same as the block size. For AES this
    * is 128 bits */
  if(EVP_EncryptInit_ex(&ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
    log_crypt_err("Not able to initialize encrypt context for AES-256");
    return 0;
  }

   /* Provide the message to be encrypted, and obtain the encrypted output */
   if(EVP_EncryptUpdate(&ctx, out, &len, in, inlen) != 1) {
     log_crypt_err("Not able to encrypt using AES-256");
     return 0;
   }

   *outlen = len;

   /* Finalise the encryption. Further ciphertext bytes may be written at
    * this stage
    */
   if(EVP_EncryptFinal_ex(&ctx, out + len, &len) != 1) {
     log_crypt_err("Not able to finalize encryption using AES-256");
     return 0;
   }

   *outlen += len;

   return 1;
}

int
decrypt_data(const void *in, int inlen, void *out, int *outlen,
             const void *iv, const void *key)
{
  int len;

  cryptutil_init();

   /* In this we are using 256 bit AES (i.e. a 256 bit key). The
    * IV size for *most* modes is the same as the block size. For AES this
    * is 128 bits
    */
  if(EVP_DecryptInit_ex(&ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
    log_crypt_err("Not able to initialize decrypt context for AES-256");
    return 0;
  }

   /* Provide the cypher text to be decrypted, and obtain the plaintext output */
   if(EVP_DecryptUpdate(&ctx, out, &len, in, inlen) != 1) {
     log_crypt_err("Not able to decrypt using AES-256");
     return 0;
   }

   *outlen = len;

   /* Finalise the encryption. Further ciphertext bytes may be written at
    * this stage.
    */
   if(EVP_DecryptFinal_ex(&ctx, out + len, &len) != 1) {
     log_crypt_err("Not able to finalize encryption using AES-256");
     return 0;
   }

   *outlen += len;

   return 1;
}
