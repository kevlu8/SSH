#include "aes.h"

extern void aes_encrypt_block(uint8_t *, uint8_t *);

enum aes_result aes_init(aes_ctx *ctx, const uint8_t *key, const uint64_t nonce, const uint64_t iv) {
	// Initialize the context
	ctx->nonce = nonce;
	ctx->ctr = iv;
	memcpy(ctx->key, key, 16);
	ctx->residual_size = 0;
	return AES_SUCCESS;
}

enum aes_result aes_encrypt_update(aes_ctx *ctx, const char *data, const size_t data_size, char *out, size_t *out_size) {
	// Allocate memory for the ciphertext
	*out_size = (ctx->residual_size + data_size) & (-1 << 4);
	// Copy the residual data
	memcpy(out, ctx->residual, ctx->residual_size);
	// Copy the data
	memcpy(out + ctx->residual_size, data, *out_size - ctx->residual_size);
	// Encrypt the data
	for (size_t i = 0; i < *out_size; i += 16) {
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
			out[i + j] ^= block[j];
		}
	}
	// Save the residual data
	ctx->residual_size = data_size - *out_size + ctx->residual_size;
	memcpy(ctx->residual, data + *out_size - ctx->residual_size, ctx->residual_size);
	return AES_SUCCESS;
}

enum aes_result aes_encrypt_finalize(aes_ctx *ctx, const char *data, const size_t data_size, char *out, size_t *out_size) {
	// Allocate memory for the ciphertext
	*out_size = ctx->residual_size + data_size;
	// Copy the residual data
	memcpy(out, ctx->residual, ctx->residual_size);
	ctx->residual_size = 0;
	// Copy the data
	memcpy(out + ctx->residual_size, data, data_size);
	// Encrypt the data
	for (size_t i = 0; i < *out_size; i += 16) {
		// Build the block with the nonce and counter
		uint8_t block[16];
		memcpy(block, &ctx->nonce, 8);
		memcpy(block + 8, &ctx->ctr, 8);
		// Increment the counter
		ctx->ctr++;
		// Encrypt the block
		aes_encrypt_block(block, ctx->key);
		// XOR the block with the plaintext
		for (int j = 0; j + i < *out_size; j++) {
			out[i + j] ^= block[j];
		}
	}
	return AES_SUCCESS;
}

// Encryption and decryption are the same operation in AES-CTR
inline enum aes_result aes_decrypt_update(aes_ctx *ctx, const char *data, const size_t data_size, char *out, size_t *out_size) { return aes_encrypt_update(ctx, data, data_size, out, out_size); }
inline enum aes_result aes_decrypt_finalize(aes_ctx *ctx, const char *data, const size_t data_size, char *out, size_t *out_size) { return aes_encrypt_finalize(ctx, data, data_size, out, out_size); }
