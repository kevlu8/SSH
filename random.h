#pragma once

#include <stddef.h>

/**
 * @brief Generate a random buffer of the given size.
 * @param buf The buffer to fill.
 * @param len The size of the buffer.
 */
void randbytes(unsigned char *, size_t);

/**
 * @brief Generate a random integer in the range [min, max].
 *
 * @param min The minimum value.
 * @param max The maximum value.
 * @return The random integer.
 */
int randint(int, int);
