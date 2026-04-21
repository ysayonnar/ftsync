#include "../../include/auth.h"
#include "../../include/common.h"
#include "../../include/protocol.h"

#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uuid/uuid.h>

EVP_PKEY *auth_generate_rsa_key(void) {
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
	if (!ctx)
		return NULL;

	if (EVP_PKEY_keygen_init(ctx) <= 0 ||
		EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) {
		EVP_PKEY_CTX_free(ctx);
		return NULL;
	}

	EVP_PKEY *pkey = NULL;
	EVP_PKEY_keygen(ctx, &pkey);
	EVP_PKEY_CTX_free(ctx);
	return pkey;
}

char *auth_get_pubkey_pem(EVP_PKEY *pkey, int *out_len) {
	BIO *bio = BIO_new(BIO_s_mem());
	if (!bio)
		return NULL;

	if (!PEM_write_bio_PUBKEY(bio, pkey)) {
		BIO_free(bio);
		return NULL;
	}

	char *pem_data;
	long pem_len = BIO_get_mem_data(bio, &pem_data);

	char *result = malloc(pem_len + 1);
	if (!result) {
		BIO_free(bio);
		return NULL;
	}

	memcpy(result, pem_data, pem_len);
	result[pem_len] = '\0';
	*out_len = (int)pem_len;

	BIO_free(bio);
	return result;
}

EVP_PKEY *auth_load_pubkey_pem(const char *pem, int len) {
	BIO *bio = BIO_new_mem_buf(pem, len);
	if (!bio)
		return NULL;

	EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
	BIO_free(bio);
	return pkey;
}

int auth_rsa_encrypt(EVP_PKEY *pkey, const unsigned char *data, size_t data_len,
					 unsigned char *out, size_t *out_len) {
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
	if (!ctx)
		return -1;

	if (EVP_PKEY_encrypt_init(ctx) <= 0 ||
		EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0 ||
		EVP_PKEY_encrypt(ctx, out, out_len, data, data_len) <= 0) {
		EVP_PKEY_CTX_free(ctx);
		return -1;
	}

	EVP_PKEY_CTX_free(ctx);
	return 0;
}

int auth_rsa_decrypt(EVP_PKEY *pkey, const unsigned char *enc, size_t enc_len,
					 unsigned char *out, size_t *out_len) {
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
	if (!ctx)
		return -1;

	if (EVP_PKEY_decrypt_init(ctx) <= 0 ||
		EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0 ||
		EVP_PKEY_decrypt(ctx, out, out_len, enc, enc_len) <= 0) {
		EVP_PKEY_CTX_free(ctx);
		return -1;
	}

	EVP_PKEY_CTX_free(ctx);
	return 0;
}

int auth_server_handshake(int client_sock) {
	message_header_t hdr;

	if (recv_exact(client_sock, &hdr, sizeof(hdr)) <= 0 ||
		!validate_magic(hdr.magic) || hdr.command_id != CMD_AUTH_PUBKEY) {
		fprintf(stderr, "[AUTH] expected client public key\n");
		return -1;
	}

	uint32_t pem_len = ntohl(hdr.payload_size);
	if (pem_len == 0 || pem_len > 4096) {
		fprintf(stderr, "[AUTH] invalid public key size: %u\n", pem_len);
		return -1;
	}

	char *pem = malloc(pem_len + 1);
	if (!pem)
		return -1;

	if (recv_exact(client_sock, pem, pem_len) <= 0) {
		free(pem);
		fprintf(stderr, "[AUTH] failed to receive public key\n");
		return -1;
	}
	pem[pem_len] = '\0';

	EVP_PKEY *client_pubkey = auth_load_pubkey_pem(pem, (int)pem_len);
	free(pem);

	if (!client_pubkey) {
		fprintf(stderr, "[AUTH] failed to parse public key\n");
		return -1;
	}

	uuid_t uuid;
	uuid_generate(uuid);

	char uuid_str[37];
	uuid_unparse(uuid, uuid_str);
	printf("[AUTH] challenge UUID: %s\n", uuid_str);

	unsigned char encrypted[512];
	size_t enc_len = sizeof(encrypted);

	if (auth_rsa_encrypt(client_pubkey, uuid, sizeof(uuid), encrypted, &enc_len) < 0) {
		EVP_PKEY_free(client_pubkey);
		fprintf(stderr, "[AUTH] failed to encrypt UUID\n");
		return -1;
	}
	EVP_PKEY_free(client_pubkey);

	message_header_t challenge_hdr;
	challenge_hdr.magic[0] = MAGIC_1;
	challenge_hdr.magic[1] = MAGIC_2;
	challenge_hdr.command_id = CMD_AUTH_CHALLENGE;
	challenge_hdr.payload_size = htonl((uint32_t)enc_len);

	if (send_exact(client_sock, &challenge_hdr, sizeof(challenge_hdr)) <= 0 ||
		send_exact(client_sock, encrypted, enc_len) <= 0) {
		fprintf(stderr, "[AUTH] failed to send challenge\n");
		return -1;
	}

	message_header_t resp_hdr;
	if (recv_exact(client_sock, &resp_hdr, sizeof(resp_hdr)) <= 0 ||
		!validate_magic(resp_hdr.magic) || resp_hdr.command_id != CMD_AUTH_RESPONSE) {
		fprintf(stderr, "[AUTH] expected challenge response\n");
		return -1;
	}

	uint32_t resp_len = ntohl(resp_hdr.payload_size);
	if (resp_len != sizeof(uuid_t)) {
		fprintf(stderr, "[AUTH] invalid response size: %u\n", resp_len);
		return -1;
	}

	uuid_t received_uuid;
	if (recv_exact(client_sock, received_uuid, sizeof(received_uuid)) <= 0) {
		fprintf(stderr, "[AUTH] failed to receive response\n");
		return -1;
	}

	message_header_t result_hdr;
	result_hdr.magic[0] = MAGIC_1;
	result_hdr.magic[1] = MAGIC_2;
	result_hdr.payload_size = 0;

	if (memcmp(uuid, received_uuid, sizeof(uuid_t)) != 0) {
		result_hdr.command_id = CMD_AUTH_FAIL;
		send_exact(client_sock, &result_hdr, sizeof(result_hdr));
		fprintf(stderr, "[AUTH] authentication failed: UUID mismatch\n");
		return -1;
	}

	result_hdr.command_id = CMD_AUTH_OK;
	send_exact(client_sock, &result_hdr, sizeof(result_hdr));
	printf("[AUTH] client authenticated (socket:%d)\n", client_sock);
	return 0;
}

int auth_client_handshake(int sock) {
	EVP_PKEY *pkey = auth_generate_rsa_key();
	if (!pkey) {
		fprintf(stderr, "[AUTH] failed to generate RSA key\n");
		return -1;
	}

	int pem_len;
	char *pem = auth_get_pubkey_pem(pkey, &pem_len);
	if (!pem) {
		EVP_PKEY_free(pkey);
		fprintf(stderr, "[AUTH] failed to export public key\n");
		return -1;
	}

	message_header_t pubkey_hdr;
	pubkey_hdr.magic[0] = MAGIC_1;
	pubkey_hdr.magic[1] = MAGIC_2;
	pubkey_hdr.command_id = CMD_AUTH_PUBKEY;
	pubkey_hdr.payload_size = htonl((uint32_t)pem_len);

	if (send_exact(sock, &pubkey_hdr, sizeof(pubkey_hdr)) <= 0 ||
		send_exact(sock, pem, pem_len) <= 0) {
		free(pem);
		EVP_PKEY_free(pkey);
		fprintf(stderr, "[AUTH] failed to send public key\n");
		return -1;
	}
	free(pem);

	message_header_t challenge_hdr;
	if (recv_exact(sock, &challenge_hdr, sizeof(challenge_hdr)) <= 0 ||
		!validate_magic(challenge_hdr.magic) ||
		challenge_hdr.command_id != CMD_AUTH_CHALLENGE) {
		EVP_PKEY_free(pkey);
		fprintf(stderr, "[AUTH] expected UUID challenge from daemon\n");
		return -1;
	}

	uint32_t enc_len = ntohl(challenge_hdr.payload_size);
	if (enc_len == 0 || enc_len > 512) {
		EVP_PKEY_free(pkey);
		fprintf(stderr, "[AUTH] invalid challenge size: %u\n", enc_len);
		return -1;
	}

	unsigned char *encrypted = malloc(enc_len);
	if (!encrypted) {
		EVP_PKEY_free(pkey);
		return -1;
	}

	if (recv_exact(sock, encrypted, enc_len) <= 0) {
		free(encrypted);
		EVP_PKEY_free(pkey);
		fprintf(stderr, "[AUTH] failed to receive challenge\n");
		return -1;
	}

	unsigned char decrypted[256];
	size_t dec_len = sizeof(decrypted);

	if (auth_rsa_decrypt(pkey, encrypted, enc_len, decrypted, &dec_len) < 0) {
		free(encrypted);
		EVP_PKEY_free(pkey);
		fprintf(stderr, "[AUTH] failed to decrypt UUID\n");
		return -1;
	}
	free(encrypted);
	EVP_PKEY_free(pkey);

	message_header_t resp_hdr;
	resp_hdr.magic[0] = MAGIC_1;
	resp_hdr.magic[1] = MAGIC_2;
	resp_hdr.command_id = CMD_AUTH_RESPONSE;
	resp_hdr.payload_size = htonl((uint32_t)dec_len);

	if (send_exact(sock, &resp_hdr, sizeof(resp_hdr)) <= 0 ||
		send_exact(sock, decrypted, dec_len) <= 0) {
		fprintf(stderr, "[AUTH] failed to send response\n");
		return -1;
	}

	message_header_t result_hdr;
	if (recv_exact(sock, &result_hdr, sizeof(result_hdr)) <= 0 ||
		!validate_magic(result_hdr.magic)) {
		fprintf(stderr, "[AUTH] failed to receive auth result\n");
		return -1;
	}

	if (result_hdr.command_id != CMD_AUTH_OK) {
		fprintf(stderr, "[AUTH] authentication rejected by daemon\n");
		return -1;
	}

	return 0;
}
