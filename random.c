#include "random.h"
#include <stdio.h>

void randbytes(unsigned char *buf, size_t len) {
	FILE *fp = fopen("/dev/urandom", "r");
	fread(buf, 1, len, fp);
	fclose(fp);
}

int randint(int min, int max) {
	unsigned int buf;
	int ans;
	do {
		randbytes(&buf, 4);
		ans = min + (buf & ((1 << (32 - __builtin_clz(max - min))) - 1));
	} while (ans > max);
	return ans;
}
