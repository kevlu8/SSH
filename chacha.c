#include "chacha.h"

#define _paddedlen(len) ((len) + 15 - (((len) + 15) & 15))

extern void __inc_nonce(uint32_t *state);
extern void __chacha_block(uint32_t state[16], char block[64]);
extern void _poly1305_mac(const char *msg, const size_t msg_len, const char *key, char *out);

enum chacha_result chacha_ctx_init(chacha_ctx *ctx, const char key[32], const char nonce[12]) {
	// build the state
	// first 4 blocks are constant
	memcpy(ctx->state, "expand 32-byte k", 16);
	// next 8 blocks are key
	memcpy(ctx->state + 4, key, 32);
	// next block is counter (initialized as 1)
	ctx->state[12] = 1;
	// next 3 blocks are nonce
	memcpy(ctx->state + 13, nonce, 12);

	// build the poly1305 keygen state (copy the other state)
	memcpy(ctx->mac_state, ctx->state, 64);
	// set the counter to 0
	ctx->mac_state[12] = 0;

	// nothing leftover
	ctx->residual_size = 0;
	// nothing existing
	ctx->existing = NULL;
	ctx->existing_len = 0;
	// not used yet
	ctx->used = 0;
	return CHACHA_SUCCESS;
}

enum chacha_result chacha_ctx_destroy(chacha_ctx *ctx) {
	if (ctx->existing != NULL)
		free(ctx->existing);
	return CHACHA_SUCCESS;
}

enum chacha_result chacha_encrypt_update(chacha_ctx *ctx, const char *data, const size_t data_size) {
	// refuse to proceed if used to decrypt
	if (ctx->used == CHACHA_DECRYPT)
		return CHACHA_ERROR_USED;
	ctx->used = CHACHA_ENCRYPT;
	// allocate enough space for the residual and the new data
	char *in = malloc(ctx->residual_size + data_size);
	if (in == NULL)
		return CHACHA_ERROR_MALLOC;
	// copy the residual and the new data into the buffer
	memcpy(in, ctx->residual, ctx->residual_size);
	memcpy(in + ctx->residual_size, data, data_size);
	// reallocate so there is enough space to append the output (cut off to a multiple of 64)
	size_t out_size = (data_size + ctx->residual_size) & ~((size_t)63);
	char *tmp;
	if (ctx->existing == NULL)
		tmp = malloc(ctx->existing_len + out_size);
	else
		tmp = realloc(ctx->existing, ctx->existing_len + out_size);
	if (tmp == NULL)
		return CHACHA_ERROR_MALLOC;
	ctx->existing = tmp;
	// the part of the plaintext that is not a multiple of 64 is the new residual
	ctx->residual_size = (data_size + ctx->residual_size) & 63;
	memcpy(ctx->residual, in + out_size, ctx->residual_size);
	// append the plaintext to the end of the existing ciphertext
	memcpy(ctx->existing + ctx->existing_len, in, out_size);
	// plaintext is no longer needed
	free(in);
	// make a counter for the number of bytes encrypted
	size_t encrypted = 0;
	// while there is still enough data for a full block
	while (encrypted + 64 <= out_size) {
		// encrypt the block (inplace)
		__chacha_block(ctx->state, ctx->existing + ctx->existing_len + encrypted);
		encrypted += 64;
		// increment the counter
		ctx->state[12]++;
	}
	// update the length of the existing ciphertext
	ctx->existing_len += out_size;
	return CHACHA_SUCCESS;
}

enum chacha_result chacha_encrypt_finalize(chacha_ctx *ctx, const char *data, const size_t data_size, const char *aad, const size_t aad_len, char **out, size_t *out_size) {
	// refuse to proceed if used to decrypt
	if (ctx->used == CHACHA_DECRYPT)
		return CHACHA_ERROR_USED;
	ctx->used = CHACHA_ENCRYPT;
	// if there is enouth to make one full block of data (together with residual), pass it onto update
	size_t used = 0;
	if (ctx->residual_size + data_size >= 64) {
		used = data_size - ((ctx->residual_size + data_size) & ((size_t)63));
		chacha_encrypt_update(ctx, data, used);
	}
	// copy the rest into a temporary buffer
	char tmp[64] = {0};
	memcpy(tmp, ctx->residual, ctx->residual_size);
	memcpy(tmp + ctx->residual_size, data + used, data_size - used);
	// encrypt the block (inplace)
	__chacha_block(ctx->state, tmp);
	ctx->state[12]++;
	// copy whatever was significant into existing
	char *tmp2;
	if (ctx->existing == NULL)
		tmp2 = malloc(ctx->existing_len + ctx->residual_size + data_size - used);
	else
		tmp2 = realloc(ctx->existing, ctx->existing_len + ctx->residual_size + data_size - used);
	if (tmp2 == NULL)
		return CHACHA_ERROR_MALLOC;
	ctx->existing = tmp2;
	memcpy(ctx->existing + ctx->existing_len, tmp, ctx->residual_size + data_size - used);
	ctx->existing_len += ctx->residual_size + data_size - used;
	// set the residual size to 0
	ctx->residual_size = 0;
	// everything is now encrypted and in existing
	// calculate the mac key
	memset(tmp, 0, 64);
	__chacha_block(ctx->mac_state, tmp);
	__inc_nonce(ctx->mac_state);
	// aead construction
	// allocate enough space for the ciphertext and the tag (along with padding and other stuff)
	*out = calloc(_paddedlen(aad_len) + _paddedlen(ctx->existing_len) + 48, 1);
	// copy the aad into the output
	memcpy(*out, aad, aad_len);
	// no need for padding since we can just ignore the extra bytes
	// copy the ciphertext into the output
	memcpy(*out + _paddedlen(aad_len), ctx->existing, ctx->existing_len);
	// free existing
	free(ctx->existing);
	ctx->existing = NULL;
	// copy aad_len and ciphertext_len into the output
	memcpy(*out + _paddedlen(aad_len) + _paddedlen(ctx->existing_len), &aad_len, 8);
	memcpy(*out + _paddedlen(aad_len) + _paddedlen(ctx->existing_len) + 8, &ctx->existing_len, 8);
	// // calculate the mac
	_poly1305_mac(*out, _paddedlen(aad_len) + _paddedlen(ctx->existing_len) + 16, tmp, tmp);
	// _poly1305_mac("Cryptographic Forum Research Group\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff", 48, "\x85\xd6\xbe\x78\x57\x55\x6d\x33\x7f\x44\x52\xfe\x42\xd5\x06\xa8\x01\x03\x80\x8a\xfb\x0d\xb2\xfd\x4a\xbf\xf6\xaf\x41\x49\xf5\x1b", tmp);
	// copy the mac into the output
	memcpy(*out + _paddedlen(aad_len) + _paddedlen(ctx->existing_len) + 16, tmp, 16);
	// return the length of the output
	*out_size = _paddedlen(aad_len) + _paddedlen(ctx->existing_len) + 32;
	return CHACHA_SUCCESS;
}

enum chacha_result chacha_decrypt_update(chacha_ctx *ctx, const char *data, const size_t data_size) {
	// refuse to proceed if used to encrypt
	if (ctx->used == CHACHA_ENCRYPT)
		return CHACHA_ERROR_USED;
	ctx->used = CHACHA_DECRYPT;
	// append data to existing
	char *tmp;
	if (ctx->existing == NULL)
		tmp = malloc(ctx->existing_len + data_size);
	else
		tmp = realloc(ctx->existing, ctx->existing_len + data_size);
	if (tmp == NULL)
		return CHACHA_ERROR_MALLOC;
	ctx->existing = tmp;
	memcpy(ctx->existing + ctx->existing_len, data, data_size);
	ctx->existing_len += data_size;
	return CHACHA_SUCCESS;
}

enum chacha_result chacha_decrypt_finalize(chacha_ctx *ctx, const char *data, const size_t data_size, char **aad, size_t *aad_len, char **out, size_t *out_size) {
	// refuse to proceed if used to decrypt
	if (ctx->used == CHACHA_ENCRYPT)
		return CHACHA_ERROR_USED;
	ctx->used = CHACHA_DECRYPT;
	// append data to existing
	if (data_size)
		chacha_decrypt_update(ctx, data, data_size);
	// verify the mac
	// calculate the mac key
	char tmp[64] = {0};
	__chacha_block(ctx->mac_state, tmp);
	__inc_nonce(ctx->mac_state);
	// calculate the mac
	_poly1305_mac(ctx->existing, ctx->existing_len - 16, tmp, tmp);
	// compare the macs
	if (memcmp(tmp, ctx->existing + ctx->existing_len - 16, 16) != 0)
		return CHACHA_ERROR_MAC;
	// aead deconstruction
	// copy the aad_len and ciphertext_len from the end of the ciphertext
	size_t tmp_len;
	memcpy(&tmp_len, ctx->existing + ctx->existing_len - 32, 8);
	memcpy(out_size, ctx->existing + ctx->existing_len - 24, 8);
	if (aad != NULL) {
		*aad_len = tmp_len;
		// allocate enough space for the aad
		*aad = malloc(*aad_len);
		if (*aad == NULL)
			return CHACHA_ERROR_MALLOC;
		// copy the aad
		memcpy(*aad, ctx->existing, *aad_len);
	}
	// allocate enough space for the ciphertext
	*out = malloc(*out_size);
	if (*out == NULL)
		return CHACHA_ERROR_MALLOC;
	// copy the ciphertext
	memcpy(*out, ctx->existing + _paddedlen(tmp_len), *out_size);
	// free existing
	free(ctx->existing);
	ctx->existing = NULL;
	// decrypt the ciphertext
	size_t decrypted = 0;
	while (decrypted + 64 <= *out_size) {
		__chacha_block(ctx->state, *out + decrypted);
		ctx->state[12]++;
		decrypted += 64;
	}
	if (decrypted < *out_size) {
		memcpy(tmp, *out + decrypted, *out_size - decrypted);
		__chacha_block(ctx->state, tmp);
		ctx->state[12]++;
		memcpy(*out + decrypted, tmp, *out_size - decrypted);
	}
	return CHACHA_SUCCESS;
}
