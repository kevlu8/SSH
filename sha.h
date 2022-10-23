#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct sha256_ctx {
	uint32_t state[8];
	uint64_t count;
	uint8_t buf[64];
	uint8_t buflen;
} sha256_ctx;

/**
 * @brief Initialize a SHA256 context
 * @param ctx SHA256 context to initialize
 */
void sha256_init(struct sha256_ctx *ctx);

/**
 * @brief Update a SHA256 context with data
 * @param ctx SHA256 context to update
 * @param data Data to update with
 * @param len Length of data
 */
void sha256_update(struct sha256_ctx *ctx, const void *data, size_t len);

/**
 * @brief Finalize a SHA256 context
 * @param ctx SHA256 context to finalize
 * @param digest Buffer to store digest in
 */
void sha256_final(struct sha256_ctx *ctx, unsigned char *digest);

/**
 * @brief Calculate a SHA256 digest
 * @param data Data to calculate digest of
 * @param len Length of data
 * @param digest Buffer to store digest in
 */
void sha256_digest(const void *data, size_t len, unsigned char *digest);
