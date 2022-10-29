#include "ec.h"

mpz_t P, Q, A, B;
EC_point G;

void EC_init_curve(const char *curve) {
	if (strncmp(curve, "nistp256", 9) == 0) {
		mpz_init_set_str(P, "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16);
		mpz_init_set_str(Q, "3fffffffc0000000400000000000000000000000400000000000000000000000", 16);
		mpz_init_set_str(A, "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc", 16);
		mpz_init_set_str(B, "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16);
		mpz_init_set_str(G.x, "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16);
		mpz_init_set_str(G.y, "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16);
	} else if (strncmp(curve, "nistp384", 9) == 0) {
		mpz_init_set_str(P, "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff", 16);
		mpz_init_set_str(Q, "3fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffbfffffffc00000000000000040000000", 16);
		mpz_init_set_str(A, "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc", 16);
		mpz_init_set_str(B, "b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef", 16);
		mpz_init_set_str(G.x, "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7", 16);
		mpz_init_set_str(G.y, "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f", 16);
	} else if (strncmp(curve, "nistp521", 9) == 0) {
		mpz_init_set_str(P, "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16);
		mpz_init_set_str(Q, "8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", 16);
		mpz_init_set_str(A, "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc", 16);
		mpz_init_set_str(B, "0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00", 16);
		mpz_init_set_str(G.x, "00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66", 16);
		mpz_init_set_str(G.y, "011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650", 16);
	}
	// TODO: add error handling
	G.inf = 0;
}

int EC_field_size() { return mpz_sizeinbase(P, 2); }

int EC_in_field(const mpz_t x) { return mpz_cmp(x, P) < 0; }

void EC_mod(mpz_t y, const mpz_t x) { mpz_mod(y, x, P); }

void EC_div(mpz_t z, const mpz_t x, const mpz_t y) {
	mpz_t inv;
	mpz_init(inv);
	mpz_invert(inv, y, P);
	mpz_mul(z, x, inv);
	mpz_mod(z, z, P);
	mpz_clear(inv);
}

void EC_calc_y(EC_point *p) {
	mpz_t temp;
	mpz_init(temp);
	// temp = x^3 + A * x + B
	mpz_powm_ui(temp, p->x, 2, P);
	mpz_add(temp, temp, A);
	mpz_mod(temp, temp, P);
	mpz_mul(temp, temp, p->x);
	mpz_add(temp, temp, B);
	mpz_mod(temp, temp, P);
	// y = sqrt(temp)
	mpz_powm(p->y, temp, Q, P);
	mpz_clear(temp);
}

void EC_init(EC_point *p) {
	mpz_init2(p->x, 256);
	mpz_init2(p->y, 256);
	p->inf = 1;
}

void EC_init_generator(EC_point *p) {
	mpz_init_set(p->x, G.x);
	mpz_init_set(p->y, G.y);
	p->inf = 0;
}

void EC_clear(EC_point *p) {
	mpz_clear(p->x);
	mpz_clear(p->y);
}

void EC_set(EC_point *p, const mpz_t x, const mpz_t y) {
	mpz_set(p->x, x);
	mpz_set(p->y, y);
	p->inf = 0;
}

void EC_set_generator(EC_point *p) {
	mpz_set(p->x, G.x);
	mpz_set(p->y, G.y);
	p->inf = 0;
}

void EC_set_inf(EC_point *p) { p->inf = 1; }

void EC_set_x(EC_point *p, const mpz_t x) {
	mpz_set(p->x, x);
	p->inf = 0;
	EC_calc_y(p);
}

void EC_copy(EC_point *p, const EC_point *a) {
	mpz_set(p->x, a->x);
	mpz_set(p->y, a->y);
	p->inf = a->inf;
}

void EC_add(EC_point *p, const EC_point *a, const EC_point *b) {
	// If a is the point at infinity, return b
	if (a->inf) {
		mpz_set(p->x, b->x);
		mpz_set(p->y, b->y);
		p->inf = b->inf;
		return;
	}
	// If b is the point at infinity, return a
	if (b->inf) {
		mpz_set(p->x, a->x);
		mpz_set(p->y, a->y);
		p->inf = a->inf;
		return;
	}
	// If a.x == b.x and a.y != b.y, return the point at infinity
	// If a.x == b.x and a.y == b.y, return EC_double(a)
	if (mpz_cmp(a->x, b->x) == 0) {
		if (mpz_cmp(a->y, b->y) == 0) {
			EC_double(p, a);
			return;
		} else {
			mpz_set_ui(p->x, 0);
			mpz_set_ui(p->y, 0);
			p->inf = 1;
			return;
		}
	}
	mpz_t m, temp;
	mpz_inits(m, temp, NULL);
	EC_point ans;
	EC_init(&ans);
	// m = (a.y - b.y)
	mpz_sub(m, b->y, a->y);
	mpz_mod(m, m, P);
	// temp = (a.x - b.x)^-1
	mpz_sub(temp, b->x, a->x);
	mpz_mod(temp, temp, P);
	mpz_invert(temp, temp, P);
	// m = (a.y - b.y) * (a.x - b.x)^-1
	mpz_mul(m, m, temp);
	mpz_mod(m, m, P);
	// temp = m^2
	mpz_mul(temp, m, m);
	// p.x = m^2 - a.x - b.x
	mpz_sub(temp, temp, a->x);
	mpz_sub(temp, temp, b->x);
	mpz_mod(ans.x, temp, P);
	// temp = p.x - a.x
	mpz_sub(temp, ans.x, a->x);
	// p.y = m * (p.x - a.x)
	mpz_mul(ans.y, m, temp);
	// p.y = m * (p.x - a.x) + a.y
	mpz_add(ans.y, ans.y, a->y);
	mpz_neg(ans.y, ans.y);
	mpz_mod(ans.y, ans.y, P);
	mpz_clears(m, temp, NULL);
	EC_copy(p, &ans);
	p->inf = 0;
	EC_clear(&ans);
}

void EC_double(EC_point *p, const EC_point *a) {
	// If a is the point at infinity, return the point at infinity
	if (a->inf) {
		mpz_set_ui(p->x, 0);
		mpz_set_ui(p->y, 0);
		p->inf = 1;
		return;
	}
	// If a.y == 0, return the point at infinity
	// Attempting to double a point with y == 0 will result in a division by zero
	if (mpz_cmp_ui(a->y, 0) == 0) {
		mpz_set_ui(p->x, 0);
		mpz_set_ui(p->y, 0);
		p->inf = 1;
		return;
	}
	mpz_t m, temp;
	mpz_inits(m, temp, NULL);
	EC_point ans;
	EC_init(&ans);
	// m = a.x^2
	mpz_powm_ui(m, a->x, 2, P);
	// m = 3 * a.x^2
	mpz_mul_ui(m, m, 3);
	// m = 3 * a.x^2 + A
	mpz_add(m, m, A);
	mpz_mod(m, m, P);
	// temp = (2 * a.y)^-1
	mpz_mul_ui(temp, a->y, 2);
	mpz_invert(temp, temp, P);
	// m = (3 * a.x^2 + A) * (2 * a.y)^-1
	mpz_mul(m, m, temp);
	mpz_mod(m, m, P);
	// temp = m^2
	mpz_mul(temp, m, m);
	// p.x = m^2 - 2 * a.x
	mpz_sub(temp, temp, a->x);
	mpz_sub(temp, temp, a->x);
	mpz_mod(ans.x, temp, P);
	// temp = p.x - a.x
	mpz_sub(temp, ans.x, a->x);
	// p.y = m * (p.x - a.x)
	mpz_mul(ans.y, m, temp);
	// p.y = m * (p.x - a.x) + a.y
	mpz_add(ans.y, ans.y, a->y);
	mpz_neg(ans.y, ans.y);
	mpz_mod(ans.y, ans.y, P);
	mpz_clears(m, temp, NULL);
	EC_copy(p, &ans);
	p->inf = 0;
	EC_clear(&ans);
}

void EC_mul(EC_point *p, const EC_point *a, const mpz_t k) {
	// If k == 0, return the point at infinity
	if (mpz_cmp_ui(k, 0) == 0) {
		mpz_set_ui(p->x, 0);
		mpz_set_ui(p->y, 0);
		p->inf = 1;
		return;
	}
	// If k == 1, return a
	if (mpz_cmp_ui(k, 1) == 0) {
		mpz_set(p->x, a->x);
		mpz_set(p->y, a->y);
		p->inf = a->inf;
		return;
	}
	// If k == 2, return EC_double(a)
	if (mpz_cmp_ui(k, 2) == 0) {
		EC_double(p, a);
		return;
	}
	// Double and add algorithm
	EC_point r;
	EC_init(&r);
	EC_copy(&r, a);
	for (int i = mpz_sizeinbase(k, 2) - 2; i >= 0; i--) {
		EC_double(&r, &r);
		if (mpz_tstbit(k, i)) {
			EC_add(&r, &r, a);
		}
	}
	EC_copy(p, &r);
	EC_clear(&r);
}

void EC_neg(EC_point *p, const EC_point *a) {
	mpz_set(p->x, a->x);
	if (mpz_cmp_ui(a->y, 0) == 0) {
		mpz_set_ui(p->y, 0);
	} else {
		mpz_sub(p->y, P, a->y);
	}
	p->inf = a->inf;
}

int EC_on_curve(const EC_point *p) {
	// If p is the point at infinity, return 1
	if (p->inf) {
		return 1;
	}
	mpz_t l, r;
	mpz_inits(l, r, NULL);
	// l = y^2
	mpz_powm_ui(l, p->y, 2, P);
	mpz_mod(l, l, P);
	// r = x^3 + A * x + B
	mpz_powm_ui(r, p->x, 2, P);
	mpz_add(r, r, A);
	mpz_mod(r, r, P);
	mpz_mul(r, r, p->x);
	mpz_add(r, r, B);
	mpz_mod(r, r, P);
	// If l == r, return 1
	if (mpz_cmp(l, r) == 0) {
		mpz_clears(l, r, NULL);
		return 1;
	}
	// Otherwise, return 0
	mpz_clears(l, r, NULL);
	return 0;
}

int EC_equal(const EC_point *a, const EC_point *b) {
	// If a and b are both the point at infinity, return 1
	if (a->inf && b->inf) {
		return 1;
	}
	// If a and b are not both the point at infinity, and a.x == b.x and a.y == b.y, return 1
	if (!a->inf && !b->inf && mpz_cmp(a->x, b->x) == 0 && mpz_cmp(a->y, b->y) == 0) {
		return 1;
	}
	// Otherwise, return 0
	return 0;
}

void EC_print(const EC_point *p) {
	if (p->inf) {
		printf("inf");
	} else {
		gmp_printf("(0x%Zx, 0x%Zx)", p->x, p->y);
	}
	putchar(10);
}
