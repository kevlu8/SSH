#include "base64.h"
#include "ec.h"
#include "random.h"
#include "sha.h"
#include <stdio.h>

typedef struct ECDSA_keypair {
	EC_point *pubkey;
	mpz_t privkey;
} ECDSA_keypair;

// Private key = a
// Public key = aG

// Calculate digest z of message
// Choose random value k
// K = kG
// r = K.x
// s = (z + ra) * K^-1
// Signature = (r, s)

// Verify signature
// Calculate digest z of message
// w = s^-1
// u1 = zw
// u2 = rw
// S = u1*G + u2*aG
// if S.x == r then signature is valid

/**
 * @brief Initialize the ECDSA subsystem.
 */
void ECDSA_init();

/**
 * @brief Initialize an ECDSA keypair
 * @param keypair The keypair to initialize
 */
void ECDSA_init_keypair(ECDSA_keypair *);

/**
 * @brief Load a private key from a file
 * @param filename The name of the file to load
 * @param keypair The object to store the key in
 */
void ECDSA_load_privkey(const char *, ECDSA_keypair *);

/**
 * @brief Load a public key from a file
 * @param filename The name of the file to load
 * @param keypair The object to store the key in
 */
void ECDSA_load_pubkey(const char *, ECDSA_keypair *);

/**
 * @brief Load a keypair from a file
 * @param privkey The name of the file to load the private key from
 * @param pubkey The name of the file to load the public key from
 * @param keypair The object to store the key in
 */
void ECDSA_load_keypair(const char *, const char *, ECDSA_keypair *);

/**
 * @brief Sign a message
 * @param keypair The keypair to sign with
 * @param message The message to sign
 * @param len The length of the message
 * @param signature The signature to store the result in
 * @param siglen The length of the signature
 */
void ECDSA_sign(ECDSA_keypair *, const char *, int, char **, int *);

/**
 * @brief Verify a signature
 * @param keypair The keypair to verify with
 * @param message The message to verify
 * @param signature The signature to verify
 * @return 1 if the signature is valid, 0 otherwise
 */
int ECDSA_verify(ECDSA_keypair *, const char *, int, const char *);

/**
 * @brief Free an ECDSA keypair
 * @param keypair The keypair to free
 */
void ECDSA_free_keypair(ECDSA_keypair *);
