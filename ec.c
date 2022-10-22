#include "ec.h"

mpz_t P, Q, A, B;
EC_point G;

void init_curve() {
	mpz_init_set_str(P, "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16);
	mpz_init_set_str(Q, "3fffffffc0000000400000000000000000000000400000000000000000000000", 16);
	mpz_init_set_str(A, "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc", 16);
	mpz_init_set_str(B, "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16);
	mpz_init_set_str(G.x, "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16);
	mpz_init_set_str(G.y, "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16);
	G.inf = 0;
}

void calc_y(EC_point *p) {
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

void EC_set(EC_point *p, mpz_t x, mpz_t y) {
	mpz_set(p->x, x);
	mpz_set(p->y, y);
	p->inf = 0;
}

void EC_set_x(EC_point *p, mpz_t x) {
	mpz_set(p->x, x);
	p->inf = 0;
	calc_y(p);
}

void EC_copy(EC_point *p, EC_point *a) {
	mpz_set(p->x, a->x);
	mpz_set(p->y, a->y);
	p->inf = a->inf;
}

void EC_add(EC_point *p, EC_point *a, EC_point *b) {
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
			mpz_set(p->x, 0);
			mpz_set(p->y, 0);
			p->inf = 1;
			return;
		}
	}
	mpz_t m, temp;
	mpz_inits(m, temp, NULL);
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
	mpz_mod(p->x, temp, P);
	calc_y(p);
	mpz_clears(m, temp, NULL);
	p->inf = 0;
}

void EC_double(EC_point *p, EC_point *a) {
	// If a is the point at infinity, return the point at infinity
	if (a->inf) {
		mpz_set(p->x, 0);
		mpz_set(p->y, 0);
		p->inf = 1;
		return;
	}
	// If a.y == 0, return the point at infinity
	// Attempting to double a point with y == 0 will result in a division by zero
	if (mpz_cmp_ui(a->y, 0) == 0) {
		mpz_set(p->x, 0);
		mpz_set(p->y, 0);
		p->inf = 1;
		return;
	}
	mpz_t m, temp;
	mpz_inits(m, temp, NULL);
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
	mpz_sub(temp, temp, a->x);
	mpz_sub(temp, temp, a->x);
	mpz_mod(p->x, temp, P);
	calc_y(p);
	mpz_clears(m, temp, NULL);
	p->inf = 0;
}

void EC_mul(EC_point *p, EC_point *a, mpz_t k) {
	// If k == 0, return the point at infinity
	if (mpz_cmp_ui(k, 0) == 0) {
		mpz_set(p->x, 0);
		mpz_set(p->y, 0);
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
	EC_copy(&r, a);
	for (int i = mpz_sizeinbase(k, 2) - 2; i >= 0; i--) {
		EC_double(&r, &r);
		if (mpz_tstbit(k, i)) {
			EC_add(&r, &r, a);
		}
	}
}

void EC_neg(EC_point *p, EC_point *a) {
	mpz_set(p->x, a->x);
	if (mpz_cmp(a->y, 0) == 0) {
		mpz_set(p->y, 0);
	} else {
		mpz_sub(p->y, P, a->y);
	}
	p->inf = a->inf;
}

int EC_on_curve(EC_point *p) {
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

int EC_equal(EC_point *a, EC_point *b) {
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
