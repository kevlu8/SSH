#include <gmp.h>
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
void init_curve(const char *);

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
 * @brief Set an EC_point to a value
 * @param p The point to set
 * @param x The x coordinate of the point
 * @param y The y coordinate of the point
 */
void EC_set(EC_point *p, mpz_t x, mpz_t y);

/**
 * @brief Set an EC_point to a value
 * @param p The point to set
 * @param x The x coordinate of the point
 */
void EC_set_x(EC_point *p, mpz_t x);

/**
 * @brief Copy an EC_point
 *
 * @param p The destination point
 * @param a The source point
 */
void EC_copy(EC_point *p, EC_point *a);

/**
 * @brief Add two EC_points
 * @param p The point to store the result
 * @param a The first point
 * @param b The second point
 */
void EC_add(EC_point *, EC_point *, EC_point *);

/**
 * @brief Double an EC_point
 * @param p The point to store the result
 * @param a The point to double
 */
void EC_double(EC_point *, EC_point *);

/**
 * @brief Multiply an EC_point by a scalar
 * @param p The point to store the result
 * @param a The point to multiply
 * @param k The scalar
 */
void EC_mul(EC_point *, EC_point *, mpz_t);

/**
 * @brief Calculate the negation of an EC_point
 * @param p The point to store the result
 * @param a The point to negate
 */
void EC_neg(EC_point *, EC_point *);

/**
 * @brief Check if an EC_point is on the curve
 * @param p The point to check
 * @return 1 if the point is on the curve, 0 otherwise
 */
int EC_on_curve(EC_point *);

/**
 * @brief Check if two EC_points are equal
 * @param a The first point
 * @param b The second point
 * @return 1 if the points are equal, 0 otherwise
 */
int EC_equal(EC_point *, EC_point *);

void calc_y(EC_point *);
