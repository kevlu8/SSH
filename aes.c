#include "aes.h"

int pad(char **padded, const char *buf, size_t len) {
	size_t padlen = 17 - (len + 1 % 16);
	*padded = malloc(len + padlen);
	memcpy(*padded, buf, len);
	memset(*padded + len, padlen, padlen);
	return len + padlen;
}

aes_ctx *aes_init(const uint8_t *key, const uint64_t nonce, const uint64_t iv) {
	aes_ctx *ctx = malloc(sizeof(aes_ctx));
	if (ctx == NULL) {
		return NULL;
	}
	ctx->nonce = nonce;
	ctx->ctr = iv;
	memcpy(ctx->key, key, 16);
	return ctx;
}

void aes_encrypt(aes_ctx *ctx, char **dst, const char *src, size_t len) {
	char *padded;
	int paddedlen = pad(&padded, src, len);
	*dst = malloc(paddedlen);
	for (int i = 0; i < paddedlen; i += 16) {
		uint8_t block[16];
		memcpy(block, &ctx->nonce, 8);
		memcpy(block + 8, &ctx->ctr, 8);
		ctx->ctr++;
		aes_encrypt_block(block, ctx->key);
		for (int j = 0; j < 16; j++) {
			(*dst)[i + j] = src[i + j] ^ block[j];
		}
	}
	free(padded);
}

int aes_decrypt(aes_ctx *ctx, char **dst, const char *src, size_t len) {
	char *padded = malloc(len);
	for (int i = 0; i < len; i += 16) {
		uint8_t block[16];
		memcpy(block, &ctx->nonce, 8);
		memcpy(block + 8, &ctx->ctr, 8);
		ctx->ctr++;
		aes_encrypt_block(block, ctx->key);
		for (int j = 0; j < 16; j++) {
			padded[i + j] = src[i + j] ^ block[j];
		}
	}
	int padlen = padded[len - 1];
	*dst = malloc(len - padlen);
	memcpy(*dst, padded, len - padlen);
	free(padded);
}