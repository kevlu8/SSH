#include "ecdsa.h"

void ECDSA_init() { EC_init_curve("nistp256"); }

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
	EC_parse_point(data, len, keypair->pubkey);
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
	} while (mpz_cmp(k, n) >= 0);
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
	// allocate memory for signature
	*siglen = rlen + slen + 6 + (extra & 1) + (extra >> 1);
	*signature = calloc(*siglen, 1);
	// save r and s
	mpz_export(*signature + 4 + (extra & 1), NULL, 1, 1, 0, 0, r);
	mpz_export(*signature + 6 + rlen + (extra & 1) + (extra >> 1), NULL, 1, 1, 0, 0, s);
	// save lengths of r and s
	(*signature)[0] = 0x30;
	(*signature)[1] = *siglen - 2;
	(*signature)[2] = 0x02;
	(*signature)[3] = rlen + (extra & 1);
	(*signature)[rlen + (extra & 1) + 4] = 0x02;
	(*signature)[rlen + (extra & 1) + 5] = slen + (extra >> 1);
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
