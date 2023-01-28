#include <gmp.h>
#include <stdio.h>
#include <string.h>

typedef struct EC_point {
	mpz_t x;
	mpz_t y;
	char inf;
} EC_point;

/**
 * @brief Initialize constants for the curve
 * @param curve The curve to initialize
 */
void EC_init_curve(const char *);

/**
 * @brief Return the field size in bits
 * @return The field size in bits
 */
int EC_field_size();

/**
 * @brief Test if a value is in the curve's field
 * @param x The value to test
 * @return 1 if the value is in the field, 0 otherwise
 */
int EC_in_field(const mpz_t);

/**
 * @brief Perform a modular reduction on a value
 * @param y The result of the reduction
 * @param x The value to reduce
 */
void EC_mod(mpz_t, const mpz_t);

/**
 * @brief Perform a division in the curve's field
 * @param z The result of the division
 * @param x The dividend
 * @param y The divisor
 */
void EC_div(mpz_t, const mpz_t, const mpz_t);

/**
 * @brief Initialize an EC_point
 * @param p The point to initialize
 */
void EC_init(EC_point *p);

/**
 * @brief Initialize the generator point
 *
 */
void EC_init_generator(EC_point *p);

/**
 * @brief Clear an EC_point
 * @param p The point to clear
 */
void EC_clear(EC_point *p);

/**
 * @brief Set an EC_point to the generator point
 * @param p The point to set
 */
void EC_set_generator(EC_point *p);

/**
 * @brief Set an EC_point to the point at infinity
 * @param p The point to set
 */
void EC_set_inf(EC_point *p);

/**
 * @brief Set an EC_point to a value
 * @param p The point to set
 * @param x The x coordinate of the point
 * @param y The y coordinate of the point
 */
void EC_set(EC_point *p, const mpz_t x, const mpz_t y);

/**
 * @brief Set an EC_point to a value
 * @param p The point to set
 * @param x The x coordinate of the point
 */
void EC_set_x(EC_point *p, const mpz_t x);

/**
 * @brief Copy an EC_point
 *
 * @param p The destination point
 * @param a The source point
 */
void EC_copy(EC_point *p, const EC_point *a);

/**
 * @brief Add two EC_points
 * @param p The point to store the result
 * @param a The first point
 * @param b The second point
 */
void EC_add(EC_point *, const EC_point *, const EC_point *);

/**
 * @brief Double an EC_point
 * @param p The point to store the result
 * @param a The point to double
 */
void EC_double(EC_point *, const EC_point *);

/**
 * @brief Multiply an EC_point by a scalar
 * @param p The point to store the result
 * @param a The point to multiply
 * @param k The scalar
 */
void EC_mul(EC_point *, const EC_point *, const mpz_t);

/**
 * @brief Calculate the negation of an EC_point
 * @param p The point to store the result
 * @param a The point to negate
 */
void EC_neg(EC_point *, const EC_point *);

/**
 * @brief Check if an EC_point is on the curve
 * @param p The point to check
 * @return 1 if the point is on the curve, 0 otherwise
 */
int EC_on_curve(const EC_point *);

/**
 * @brief Check if two EC_points are equal
 * @param a The first point
 * @param b The second point
 * @return 1 if the points are equal, 0 otherwise
 */
int EC_equal(const EC_point *, const EC_point *);

/**
 * @brief Print an EC_point
 * @param p The point to print
 */
void EC_print(const EC_point *);

/**
 * @brief Calculate the y coordinate of a point given the x coordinate
 * @param p The point to perform the calculation on
 */
void EC_calc_y(EC_point *);

/**
 * @brief Load an EC_point from an octet string
 * @param data The octet string
 * @param len The length of the octet string
 * @param p The point to store the result
 */
void EC_parse_point(const char *, const int, EC_point *);

/**
 * @brief Store an EC_point in an octet string
 * @param p The point to store
 * @param data The octet string
 * @param len The length of the octet string
 */
void EC_serialize_point(const EC_point *, char **, int *);
