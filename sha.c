#include "sha.h"

#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define BSIG0(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define BSIG1(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define SSIG0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ ((x) >> 3))
#define SSIG1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ ((x) >> 10))

const uint32_t K256[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be,
	0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa,
	0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85,
	0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
	0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
	0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

void sha256_digest_block(uint32_t *state, const void *block) {
	uint32_t w[64] = {0};
	uint32_t a, b, c, d, e, f, g, h;
	uint32_t t1, t2;
	int i;

	for (i = 0; i < 16; i++) {
		w[i] = __bswap_32(((const uint32_t *)block)[i]);
	}

	for (i = 16; i < 64; i++) {
		w[i] = SSIG1(w[i - 2]) + w[i - 7] + SSIG0(w[i - 15]) + w[i - 16];
	}

	a = state[0];
	b = state[1];
	c = state[2];
	d = state[3];
	e = state[4];
	f = state[5];
	g = state[6];
	h = state[7];

	for (i = 0; i < 64; i++) {
		t1 = h + BSIG1(e) + CH(e, f, g) + K256[i] + w[i];
		t2 = BSIG0(a) + MAJ(a, b, c);
		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;
	}

	state[0] = a + state[0];
	state[1] = b + state[1];
	state[2] = c + state[2];
	state[3] = d + state[3];
	state[4] = e + state[4];
	state[5] = f + state[5];
	state[6] = g + state[6];
	state[7] = h + state[7];
}

void sha256_init(sha256_ctx *ctx) {
	ctx->count = 0;
	ctx->state[0] = 0x6A09E667;
	ctx->state[1] = 0xBB67AE85;
	ctx->state[2] = 0x3C6EF372;
	ctx->state[3] = 0xA54FF53A;
	ctx->state[4] = 0x510E527F;
	ctx->state[5] = 0x9B05688C;
	ctx->state[6] = 0x1F83D9AB;
	ctx->state[7] = 0x5BE0CD19;
	ctx->buflen = 0;
	memset(ctx->buf, 0xdb, 64);
}

void sha256_update(sha256_ctx *ctx, const void *data, size_t len) {
	// How many bytes to copy
	size_t fill = 64 - ctx->buflen;

	// Update the length of the message
	ctx->count += len;

	// Copy the data into the buffer to fill it
	if (ctx->buflen && len >= fill) {
		memcpy(ctx->buf + ctx->buflen, data, fill);
		data = (const uint8_t *)data + fill;
		len -= fill;
		sha256_digest_block(ctx->state, ctx->buf);
		ctx->buflen = 0;
	}

	// Continually digest the data in 64 byte chunks
	while (len >= 64) {
		sha256_digest_block(ctx->state, data);
		data = (const uint8_t *)data + 64;
		len -= 64;
		ctx->buflen = 0;
	}

	// Copy the remaining data into the buffer
	if (len > 0) {
		memcpy(ctx->buf + ctx->buflen, data, len);
		// Update the length of the buffer
		ctx->buflen += len;
	}
}

void sha256_final(struct sha256_ctx *ctx, unsigned char *digest) {
	// If there is not enough space for the length, digest the block
	if (ctx->buflen >= 56) {
		memset(ctx->buf + ctx->buflen, 0, 64 - ctx->buflen);
		ctx->buf[ctx->buflen] = 0x80;
		sha256_digest_block(ctx->state, ctx->buf);
		memset(ctx->buf, 0, 56);
	}
	// Pad the buffer with zeros
	memset(ctx->buf + ctx->buflen, 0, 56 - ctx->buflen);
	ctx->buf[ctx->buflen] = 0x80;
	// Append the length of the message
	ctx->count = __bswap_64(ctx->count << 3);
	memcpy(ctx->buf + 56, &ctx->count, 8);

	// Digest the final block
	sha256_digest_block(ctx->state, ctx->buf);

	// Store the result
	for (int i = 0; i < 8; i++) {
		digest[i * 4 + 0] = ctx->state[i] >> 24;
		digest[i * 4 + 1] = ctx->state[i] >> 16;
		digest[i * 4 + 2] = ctx->state[i] >> 8;
		digest[i * 4 + 3] = ctx->state[i];
	}
}

void sha256_digest(const void *data, size_t len, unsigned char *result) {
	sha256_ctx ctx;
	sha256_init(&ctx);
	sha256_update(&ctx, data, len);
	sha256_final(&ctx, result);
}
