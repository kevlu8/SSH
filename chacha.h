#pragma once

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

enum chacha_result {
	CHACHA_SUCCESS = 0,
	CHACHA_ERROR_USED = -1,
	CHACHA_ERROR_MAC = -2,
	CHACHA_ERROR_MALLOC = -3,
};

enum ctx_used {
	CHACHA_ENCRYPT = 1,
	CHACHA_DECRYPT = 2,
};

typedef struct {
	uint32_t state[16];
	uint32_t mac_state[16];
	uint8_t residual[63];
	uint8_t residual_size;
	uint8_t *existing;
	size_t existing_len;
	// flags for whether this object has been used to encrypt or decrypt
	enum ctx_used used;
} chacha_ctx;

/**
 * @brief Initialize a chacha_ctx object
 *
 * @param ctx The chacha_ctx object to initialize
 * @param key The key to use
 * @param nonce The nonce to use
 * @return CHACHA_SUCCESS on success, <0 on error
 */
enum chacha_result chacha_ctx_init(chacha_ctx *, const char[32], const char[12]);

/**
 * @brief Destroy a chacha_ctx object
 *
 * @param ctx The chacha_ctx object to destroy
 * @return CHACHA_SUCCESS on success, <0 on error
 */
enum chacha_result chacha_ctx_destroy(chacha_ctx *);

/**
 * @brief Update the chacha_ctx object with new plaintext data
 *
 * @param ctx The chacha_ctx object to update
 * @param data The data to update with
 * @param data_size The size of the data
 * @return CHACHA_SUCCESS on success, <0 on error
 */
enum chacha_result chacha_encrypt_update(chacha_ctx *, const char *, const size_t);

/**
 * @brief Finalize encryption (add mac)
 *
 * @param ctx The chacha_ctx object to finalize
 * @param data The data to finalize with
 * @param data_size The size of the data
 * @param aad The additional authenticated data
 * @param aad_size The size of the additional authenticated data
 * @param out The output buffer
 * @param out_size The size of the output buffer
 * @return CHACHA_SUCCESS on success, <0 on error
 */
enum chacha_result chacha_encrypt_finalize(chacha_ctx *, const char *, const size_t, const char *, const size_t, char **, size_t *);

/**
 * @brief Update the chacha_ctx object with new ciphertext data
 *
 * @param ctx The chacha_ctx object to update
 * @param data The data to update with
 * @param data_size The size of the data
 * @return CHACHA_SUCCESS on success, <0 on error
 */
enum chacha_result chacha_decrypt_update(chacha_ctx *, const char *, const size_t);

/**
 * @brief Finalize decryption (check mac)
 * @note If AAD is NULL, it will be ignored
 * @warning If finalize is called not at the end of the stream, it will fail
 *
 * @param ctx The chacha_ctx object to finalize
 * @param data The data to finalize with
 * @param data_size The size of the data
 * @param aad The additional authenticated data
 * @param aad_size The size of the additional authenticated data
 * @param out The output buffer
 * @param out_size The size of the output buffer
 * @return CHACHA_SUCCESS on success, <0 on error
 */
enum chacha_result chacha_decrypt_finalize(chacha_ctx *, const char *, const size_t, char **, size_t *, char **, size_t *);
