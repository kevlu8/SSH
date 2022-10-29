#include "ecdsa.h"

void ECDSA_init_keypair(ECDSA_keypair *keypair) {
	keypair->pubkey = malloc(sizeof(EC_point));
	EC_init(keypair->pubkey);
	mpz_init(keypair->privkey);
}

void ECDSA_load_privkey(const char *filename, ECDSA_keypair *keypair) {
	char *data;
	int len;
	load_base64(filename, &data, &len);
	mpz_import(keypair->privkey, len, 1, 1, 0, 0, data);
}

void ECDSA_load_pubkey(const char *filename, ECDSA_keypair *keypair) {
	char *data;
	int len;
	load_base64(filename, &data, &len);
	keypair->pubkey->inf = 0;
	if (data[0] == 0x04) {
		// 0x04 means uncompressed
		mpz_import(keypair->pubkey->y, len / 2, 1, 1, 0, 0, data + 1);
		mpz_import(keypair->pubkey->x, len / 2, 1, 1, 0, 0, data + len / 2 + 1);
	} else if (data[0] == 0x02 || data[0] == 0x03) {
		// 0x02 means y is even
		// 0x03 means y is odd
		mpz_t tmp;
		mpz_init(tmp);
		mpz_import(tmp, len - 1, 1, 1, 0, 0, data + 1);
		EC_set_x(keypair->pubkey, tmp);
		mpz_clear(tmp);
		if (mpz_tstbit(keypair->pubkey->y, 0) != data[0] - 2) {
			EC_neg(keypair->pubkey, keypair->pubkey);
		}
	} else {
		printf("Unknown public key format");
		exit(1);
	}
}

void ECDSA_load_keypair(const char *privkey_filename, const char *pubkey_filename, ECDSA_keypair *keypair) {
	ECDSA_load_privkey(privkey_filename, keypair);
	ECDSA_load_pubkey(pubkey_filename, keypair);
}

void ECDSA_sign(ECDSA_keypair *keypair, const char *message, int len, char **signature, int *siglen) {
	char *z, *buf_k;
	z = malloc(32);
	int field_bitlen = EC_field_size();
	int field_bytelen = (field_bitlen + 7) / 8;
	buf_k = malloc(field_bytelen);
	mpz_t k, r, s, z_mpz, tmp;
	EC_point G, K;
	int rlen, slen;
	mpz_inits(k, r, s, z_mpz, tmp, NULL);
	EC_init_generator(&G);
	EC_init(&K);
	// z is the message digest
	sha256_digest(message, len, z);
	// save z as an mpz_t
	mpz_import(z_mpz, 32, 1, 1, 0, 0, z);
	// choose random k
	do {
		randbytes(buf_k, field_bytelen);
		mpz_import(k, field_bytelen, 1, 1, 0, 0, buf_k);
	} while (!EC_in_field(k));
	// K = kG
	EC_mul(&K, &G, k);
	// r = K.x
	mpz_set(r, K.x);
	// tmp = ra
	mpz_mul(tmp, r, keypair->privkey);
	EC_mod(tmp, tmp);
	// tmp = z + ra
	mpz_add(tmp, z_mpz, tmp);
	EC_mod(tmp, tmp);
	// s = (z + ra) * K^-1
	EC_div(s, tmp, k);
	// calculate length of r and s
	rlen = (mpz_sizeinbase(r, 2) + 7) / 8;
	slen = (mpz_sizeinbase(s, 2) + 7) / 8;
	// allocate memory for signature
	*siglen = rlen + slen + 8;
	*signature = malloc(*siglen);
	// save r and s
	mpz_export(*signature + 4, NULL, 1, 1, 0, 0, r);
	mpz_export(*signature + 8 + rlen, NULL, 1, 1, 0, 0, s);
	// save lengths of r and s
	(*signature)[0] = rlen >> 24;
	(*signature)[1] = rlen >> 16;
	(*signature)[2] = rlen >> 8;
	(*signature)[3] = rlen;
	(*signature)[4 + rlen] = slen >> 24;
	(*signature)[5 + rlen] = slen >> 16;
	(*signature)[6 + rlen] = slen >> 8;
	(*signature)[7 + rlen] = slen;
}

int ECDSA_verify(ECDSA_keypair *keypair, const char *message, int len, const char *signature) {
	char *z;
	z = malloc(32);
	mpz_t r, s, z_mpz, w, u1, u2;
	EC_point G, u1G, u2G, S;
	int rlen, slen;
	mpz_inits(r, s, z_mpz, w, u1, u2, NULL);
	EC_init_generator(&G);
	EC_init(&u1G);
	EC_init(&u2G);
	EC_init(&S);
	// z is the message digest
	sha256_digest(message, len, z);
	// save z as an mpz_t
	mpz_import(z_mpz, 32, 1, 1, 0, 0, z);
	// load r and s
	rlen = signature[0] << 24 | signature[1] << 16 | signature[2] << 8 | signature[3];
	slen = signature[4 + rlen] << 24 | signature[5 + rlen] << 16 | signature[6 + rlen] << 8 | signature[7 + rlen];
	mpz_import(r, rlen, 1, 1, 0, 0, signature + 4);
	mpz_import(s, slen, 1, 1, 0, 0, signature + 8 + rlen);
	// check if r and s are in the correct range
	if (!EC_in_field(r) || !EC_in_field(s)) {
		return 0;
	}
	// u1 = z * s^-1
	EC_div(u1, z_mpz, s);
	// u2 = r * s^-1
	EC_div(u2, r, s);
	// u1G = u1*G
	EC_mul(&u1G, &G, u1);
	// u2G = u2*aG
	EC_mul(&u2G, keypair->pubkey, u2);
	// S = u1G + u2G
	EC_add(&S, &u1G, &u2G);
	// check if r = S.x
	return mpz_cmp(r, S.x) == 0;
}

void ECDSA_free_keypair(ECDSA_keypair *keypair) {
	mpz_clear(keypair->privkey);
	EC_clear(keypair->pubkey);
	free(keypair->pubkey);
}
