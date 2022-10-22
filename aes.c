#include "aes.h"

extern void aes_encrypt_block(uint8_t *, uint8_t *);

aes_ctx *aes_init(const uint8_t *key, const uint64_t nonce, const uint64_t iv) {
	// Allocate memory for the context
	aes_ctx *ctx = malloc(sizeof(aes_ctx));
	if (ctx == NULL) {
		return NULL;
	}
	// Initialize the context
	ctx->nonce = nonce;
	ctx->ctr = iv;
	memcpy(ctx->key, key, 16);
	return ctx;
}

void aes_encrypt(aes_ctx *ctx, char **dst, const char *src, size_t len) {
	// len is assumed to be a multiple of 16
	// Allocate memory for the ciphertext
	*dst = malloc(len);
	// For every block of plaintext
	for (size_t i = 0; i < len; i += 16) {
		// Build the block with the nonce and counter
		uint8_t block[16];
		memcpy(block, &ctx->nonce, 8);
		memcpy(block + 8, &ctx->ctr, 8);
		// Increment the counter
		ctx->ctr++;
		// Encrypt the block
		aes_encrypt_block(block, ctx->key);
		// XOR the block with the plaintext
		for (int j = 0; j < 16; j++) {
			(*dst)[i + j] = src[i + j] ^ block[j];
		}
	}
}

// Encryption and decryption are the same operation in AES-CTR
inline void aes_decrypt(aes_ctx *ctx, char **dst, const char *src, size_t len) { aes_encrypt(ctx, dst, src, len); }
