#include "ecdsa.h"

unsigned char ECDSA_initialized = 0;

void ECDSA_init() {
	if (ECDSA_initialized)
		return;
	ECDSA_initialized = 1;
	EC_init_curve("nistp256");
}

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
	free(data);
}

void ECDSA_load_pubkey(const char *filename, ECDSA_keypair *keypair) {
	char *data;
	int len;
	load_base64(filename, &data, &len);
	EC_parse_point(data, len, keypair->pubkey);
	free(data);
	keypair->pubkey->inf = 0;
}

void ECDSA_load_keypair(const char *privkey_filename, const char *pubkey_filename, ECDSA_keypair *keypair) {
	ECDSA_load_privkey(privkey_filename, keypair);
	ECDSA_load_pubkey(pubkey_filename, keypair);
}

void print_num(mpz_t x) { gmp_printf("0x%Zx\n", x); }

void ECDSA_sign(ECDSA_keypair *keypair, const char *message, int len, char **signature, int *siglen) {
	char *e, *buf_k;
	e = malloc(32);
	mpz_t k, r, s, n, e_mpz;
	mpz_inits(k, r, s, n, e_mpz, NULL);
	EC_point G, kG;
	EC_init_generator(&G);
	EC_init(&kG);
	EC_order(n);
	// compute e
	sha256_digest(message, len, e);
	mpz_import(e_mpz, 32, 1, 1, 0, 0, e);
	// generate k
	buf_k = malloc((mpz_sizeinbase(n, 2) + 7) / 8);
	do {
		randbytes(buf_k, (mpz_sizeinbase(n, 2) + 7) / 8);
		mpz_import(k, (mpz_sizeinbase(n, 2) + 7) / 8, 1, 1, 0, 0, buf_k);
	} while (mpz_cmp(k, n) >= 0 || mpz_cmp_ui(k, 0) == 0);
	// mpz_import(k, 32, 1, 1, 0, 0, "\xD1\x6B\x6A\xE8\x27\xF1\x71\x75\xE0\x40\x87\x1A\x1C\x7E\xC3\x50\x01\x92\xC4\xC9\x26\x77\x33\x6E\xC2\x53\x7A\xCA\xEE\x00\x08\xE0");
	// compute kG
	EC_mul(&kG, &G, k);
	// r = kG.x
	mpz_set(r, kG.x);
	// s = (e + r * d) / k
	mpz_mul(s, r, keypair->privkey);
	mpz_add(s, s, e_mpz);
	mpz_invert(k, k, n);
	mpz_mul(s, s, k);
	mpz_mod(s, s, n);
	// save r and s
	int rlen = (mpz_sizeinbase(r, 2) + 7) / 8;
	int slen = (mpz_sizeinbase(s, 2) + 7) / 8;
	// extra 0 byte is added if "sign bit" is set (first bit is for r, second bit is for s)
	uint8_t extra = 0;
	rlen = (mpz_sizeinbase(r, 2) + 7) / 8;
	// add extra 0 byte if "sign bit" is set
	if (rlen * 8 == mpz_sizeinbase(r, 2))
		extra |= 1;
	slen = (mpz_sizeinbase(s, 2) + 7) / 8;
	// add extra 0 byte if "sign bit" is set
	if (slen * 8 == mpz_sizeinbase(s, 2))
		extra |= 2;
	// SSH signature format:
	// allocate memory for signature
	*siglen = rlen + slen + 12 + (extra & 1) + (extra >> 1);
	*signature = calloc(*siglen, 1);
	// save r and s
	mpz_export(*signature + 8 + (extra & 1), NULL, 1, 1, 0, 0, r);
	mpz_export(*signature + 12 + rlen + (extra & 1) + (extra >> 1), NULL, 1, 1, 0, 0, s);
	// save lengths of r and s
	(*signature)[0] = (*siglen - 4) >> 24;
	(*signature)[1] = ((*siglen - 4) >> 16) & 0xff;
	(*signature)[2] = ((*siglen - 4) >> 8) & 0xff;
	(*signature)[3] = (*siglen - 4) & 0xff;
	(*signature)[4] = (rlen + (extra & 1)) >> 24;
	(*signature)[5] = ((rlen + (extra & 1)) >> 16) & 0xff;
	(*signature)[6] = ((rlen + (extra & 1)) >> 8) & 0xff;
	(*signature)[7] = (rlen + (extra & 1)) & 0xff;
	(*signature)[rlen + (extra & 1) + 8] = (slen + (extra >> 1)) >> 24;
	(*signature)[rlen + (extra & 1) + 9] = ((slen + (extra >> 1)) >> 16) & 0xff;
	(*signature)[rlen + (extra & 1) + 10] = ((slen + (extra >> 1)) >> 8) & 0xff;
	(*signature)[rlen + (extra & 1) + 11] = (slen + (extra >> 1)) & 0xff;
	// DER signature format:
	// // allocate memory for signature
	// *siglen = rlen + slen + 6 + (extra & 1) + (extra >> 1);
	// *signature = calloc(*siglen, 1);
	// // save r and s
	// mpz_export(*signature + 4 + (extra & 1), NULL, 1, 1, 0, 0, r);
	// mpz_export(*signature + 6 + rlen + (extra & 1) + (extra >> 1), NULL, 1, 1, 0, 0, s);
	// // save lengths of r and s
	// (*signature)[0] = 0x30;
	// (*signature)[1] = *siglen - 2;
	// (*signature)[2] = 0x02;
	// (*signature)[3] = rlen + (extra & 1);
	// (*signature)[rlen + (extra & 1) + 4] = 0x02;
	// (*signature)[rlen + (extra & 1) + 5] = slen + (extra >> 1);
	// free(buf_k);
	// free(e);
	// mpz_clears(k, r, s, n, e_mpz, NULL);
	// EC_clear(&G);
	// EC_clear(&kG);
	return 0;
}

int ECDSA_verify(ECDSA_keypair *keypair, const char *message, int len, const char *signature) {
	char *e;
	e = malloc(32);
	mpz_t r, s, e_mpz, w, u1, u2, n;
	EC_point G, u1G, u2Q, X;
	int rlen, slen;
	mpz_inits(r, s, e_mpz, w, u1, u2, n, NULL);
	EC_init_generator(&G);
	EC_init(&u1G);
	EC_init(&u2Q);
	EC_init(&X);
	EC_order(n);
	// load r and s
	rlen = (signature[4] << 24) | (signature[5] << 16) | (signature[6] << 8) | signature[7];
	slen = (signature[rlen + 8] << 24) | (signature[rlen + 9] << 16) | (signature[rlen + 10] << 8) | signature[rlen + 11];
	mpz_import(r, rlen, 1, 1, 0, 0, signature + 8);
	mpz_import(s, slen, 1, 1, 0, 0, signature + rlen + 12);
	// check if r and s are in range
	if (mpz_cmp_ui(r, 0) <= 0 || mpz_cmp(r, n) >= 0 || mpz_cmp_ui(s, 0) <= 0 || mpz_cmp(s, n) >= 0) {
		free(e);
		mpz_clears(r, s, e_mpz, w, u1, u2, n, NULL);
		EC_clear(&G);
		EC_clear(&u1G);
		EC_clear(&u2Q);
		EC_clear(&X);
		return -1;
	}
	// compute e
	sha256_digest(message, len, e);
	mpz_import(e_mpz, 32, 1, 1, 0, 0, e);
	// compute w = s^-1
	mpz_invert(w, s, n);
	// compute u1 = ew
	mpz_mul(u1, e_mpz, w);
	mpz_mod(u1, u1, n);
	// compute u2 = rw
	mpz_mul(u2, r, w);
	mpz_mod(u2, u2, n);
	// compute X = u1G + u2Q
	EC_mul(&u1G, &G, u1);
	EC_mul(&u2Q, keypair->pubkey, u2);
	EC_add(&X, &u1G, &u2Q);
	// if X is the point at infinity, return error
	if (X.inf) {
		free(e);
		mpz_clears(r, s, e_mpz, w, u1, u2, n, NULL);
		EC_clear(&G);
		EC_clear(&u1G);
		EC_clear(&u2Q);
		EC_clear(&X);
		return -1;
	}
	// check if r == X.x
	int res;
	// X.x = X.x mod n
	mpz_mod(X.x, X.x, n);
	// r = r mod n
	mpz_mod(r, r, n);
	if (mpz_cmp(r, X.x) == 0)
		res = 0;
	else
		res = -1;
	free(e);
	mpz_clears(r, s, e_mpz, w, u1, u2, n, NULL);
	EC_clear(&G);
	EC_clear(&u1G);
	EC_clear(&u2Q);
	EC_clear(&X);
	return res;
}

void ECDSA_free_keypair(ECDSA_keypair *keypair) {
	mpz_clear(keypair->privkey);
	EC_clear(keypair->pubkey);
	free(keypair->pubkey);
}
