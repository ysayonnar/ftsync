#ifndef AUTH_H
#define AUTH_H

#include <openssl/evp.h>

EVP_PKEY *auth_generate_rsa_key();

char *auth_get_pubkey_pem(EVP_PKEY *pkey, int *out_len);
EVP_PKEY *auth_load_pubkey_pem(const char *pem, int len);

int auth_rsa_encrypt(EVP_PKEY *pkey, const unsigned char *data, size_t data_len,
                     unsigned char *out, size_t *out_len);
int auth_rsa_decrypt(EVP_PKEY *pkey, const unsigned char *enc, size_t enc_len,
                     unsigned char *out, size_t *out_len);

int auth_server_handshake(int client_sock);
int auth_client_handshake(int sock);

#endif
