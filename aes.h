#pragma once

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

enum aes_result {
	AES_SUCCESS = 0,
};

typedef struct aes_ctx {
	uint8_t key[16];
	uint64_t nonce;
	uint64_t ctr;
	uint8_t residual[15];
	uint8_t residual_size;
} aes_ctx;

/**
 * @brief Initialize the AES context.
 * @param ctx AES context
 * @param key AES key
 * @param nonce AES nonce
 * @param iv AES IV
 * @return AES_SUCCESS on success, <0 on error
 */
enum aes_result aes_init(aes_ctx *, const uint8_t *, const uint64_t, const uint64_t);

/**
 * @brief Update the AES context with new data.
 * @param ctx AES context
 * @param data Source buffer
 * @param data_len Length of source buffer
 * @param out Destination buffer
 * @param out_len Length of data written
 * @return AES_SUCCESS on success, <0 on error
 */
enum aes_result aes_encrypt_update(aes_ctx *, const char *, const size_t, char *, size_t *);

/**
 * @brief Finalize the AES context.
 * @param ctx AES context
 * @param data Source buffer
 * @param data_len Length of source buffer
 * @param out Destination buffer
 * @param out_len Length of data written
 * @return AES_SUCCESS on success, <0 on error
 */
enum aes_result aes_encrypt_finalize(aes_ctx *, const char *, const size_t, char *, size_t *);

/**
 * @brief Update the AES context with new data.
 * @param ctx AES context
 * @param data Source buffer
 * @param data_len Length of source buffer
 * @param out Destination buffer
 * @param out_len Length of data written
 * @return AES_SUCCESS on success, <0 on error
 */
enum aes_result aes_decrypt_update(aes_ctx *, const char *, const size_t, char *, size_t *);

/**
 * @brief Finalize the AES context.
 * @param ctx AES context
 * @param data Source buffer
 * @param data_len Length of source buffer
 * @param out Destination buffer
 * @param out_len Length of data written
 * @return AES_SUCCESS on success, <0 on error
 */
enum aes_result aes_decrypt_finalize(aes_ctx *, const char *, const size_t, char *, size_t *);
