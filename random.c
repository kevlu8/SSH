#include "random.h"
#include <stdio.h>

void randbytes(unsigned char *buf, size_t len) {
	FILE *fp = fopen("/dev/urandom", "r");
	fread(buf, 1, len, fp);
	fclose(fp);
}
