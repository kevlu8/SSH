#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct aes_ctx {
	uint8_t key[16];
	uint64_t nonce;
	uint64_t ctr;
} aes_ctx;

/**
 * Initialize the AES context.
 * @param key AES key
 * @param nonce AES nonce
 * @param iv AES IV
 * @return The initialized AES context
 */
aes_ctx *aes_init(const uint8_t *, const uint64_t, const uint64_t);

/**
 * Encrypt a block of data.
 * @param ctx AES context
 * @param dst Destination buffer
 * @param src Source buffer
 * @param len Length of source buffer
 */
void aes_encrypt(aes_ctx *, char **, const char *, size_t);

/**
 * Decrypt a block of data.
 * @param ctx AES context
 * @param dst Destination buffer
 * @param src Source buffer
 * @param len Length of source buffer
 */
void aes_decrypt(aes_ctx *, char **, const char *, size_t);
