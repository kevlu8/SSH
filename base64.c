#include "base64.h"

void load_base64(const char *filename, char **data, int *len) {
	FILE *fp = fopen(filename, "r");
	if (fp == NULL) {
		printf("Error opening file %s for reading\n", filename);
		exit(1);
	}
	// Get file size
	fseek(fp, 0, SEEK_END);
	*len = (ftell(fp) / 4) * 3;
	fseek(fp, 0, SEEK_SET);
	*data = malloc(*len);
	char buffer[4];
	int i = 0;
	while (i < *len) {
		// Read 4 bytes at a time
		fread(buffer, 1, 4, fp);
		// Convert each character to 6 bits
		for (int j = 0; j < 4; j++) {
			if (buffer[j] >= 'A' && buffer[j] <= 'Z') {
				buffer[j] -= 'A';
			} else if (buffer[j] >= 'a' && buffer[j] <= 'z') {
				buffer[j] -= 'a' - 26;
			} else if (buffer[j] >= '0' && buffer[j] <= '9') {
				buffer[j] -= '0' - 52;
			} else if (buffer[j] == '+') {
				buffer[j] = 62;
			} else if (buffer[j] == '/') {
				buffer[j] = 63;
			} else if (buffer[j] == '=') {
				buffer[j] = -1;
				(*len)--;
			}
		}
		// Convert 6 bits to 8 bits
		(*data)[i++] = (buffer[0] << 2) | (buffer[1] >> 4);
		if (buffer[2] != -1) {
			(*data)[i++] = (buffer[1] << 4) | (buffer[2] >> 2);
			if (buffer[3] != -1) {
				(*data)[i++] = (buffer[2] << 6) | buffer[3];
			}
		}
	}
	fclose(fp);
}

void save_base64(const char *filename, const char *data, int len) {
	FILE *fp = fopen(filename, "w");
	if (fp == NULL) {
		printf("Error opening file %s for writing\n", filename);
		exit(1);
	}
	char buffer[4];
	int i = 0;
	while (i + 3 <= len) {
		// Convert 8 bits to 6 bits
		buffer[0] = (data[i++] >> 2) & 0x3F;
		buffer[1] = ((data[i] << 4) | (data[i + 1] >> 4)) & 0x3F;
		buffer[2] = ((data[i + 1] << 2) | (data[i + 2] >> 6)) & 0x3F;
		buffer[3] = data[i + 2] & 0x3F;
		// Convert each 6 bits to a character
		for (int j = 0; j < 4; j++) {
			if (buffer[j] < 26) {
				buffer[j] += 'A';
			} else if (buffer[j] < 52) {
				buffer[j] += 'a' - 26;
			} else if (buffer[j] < 62) {
				buffer[j] += '0' - 52;
			} else if (buffer[j] == 62) {
				buffer[j] = '+';
			} else if (buffer[j] == 63) {
				buffer[j] = '/';
			}
		}
		// Write 4 characters at a time
		fwrite(buffer, 1, 4, fp);
	}

	// Add remaining bytes and padding
	if (len % 3 == 1) {
		buffer[0] = (data[i] >> 2) & 0x3F;
		buffer[1] = (data[i] << 4) & 0x3F;
		if (buffer[0] < 26) {
			buffer[0] += 'A';
		} else if (buffer[0] < 52) {
			buffer[0] += 'a' - 26;
		} else if (buffer[0] < 62) {
			buffer[0] += '0' - 52;
		} else if (buffer[0] == 62) {
			buffer[0] = '+';
		} else if (buffer[0] == 63) {
			buffer[0] = '/';
		}
		if (buffer[1] < 26) {
			buffer[1] += 'A';
		} else if (buffer[1] < 52) {
			buffer[1] += 'a' - 26;
		}
		buffer[2] = '=';
		buffer[3] = '=';
		fwrite(buffer, 1, 4, fp);
	} else if (len % 3 == 2) {
		buffer[0] = (data[i] >> 2) & 0x3F;
		buffer[1] = ((data[i] << 4) | (data[i + 1] >> 4)) & 0x3F;
		buffer[2] = (data[i + 1] << 2) & 0x3F;
		for (int j = 0; j < 3; j++) {
			if (buffer[j] < 26) {
				buffer[j] += 'A';
			} else if (buffer[j] < 52) {
				buffer[j] += 'a' - 26;
			} else if (buffer[j] < 62) {
				buffer[j] += '0' - 52;
			} else if (buffer[j] == 62) {
				buffer[j] = '+';
			} else if (buffer[j] == 63) {
				buffer[j] = '/';
			}
		}
		buffer[3] = '=';
		fwrite(buffer, 1, 4, fp);
	}
	fclose(fp);
}

void base64_encode(const char *data, int len, char **out, int *out_len) {
	*out_len = ((len / 3) + (len % 3 != 0)) * 4;
	*out = malloc(*out_len);
	char buffer[4];
	int i = 0;
	int k = 0;
	while (i + 3 <= len) {
		// Convert 8 bits to 6 bits
		buffer[0] = (data[i] >> 2) & 0x3F;
		buffer[1] = ((data[i] << 4) | (data[i + 1] >> 4)) & 0x3F;
		buffer[2] = ((data[i + 1] << 2) | (data[i + 2] >> 6)) & 0x3F;
		buffer[3] = data[i + 2] & 0x3F;
		// Convert each 6 bits to a character
		for (int j = 0; j < 4; j++) {
			if (buffer[j] < 26) {
				buffer[j] += 'A';
			} else if (buffer[j] < 52) {
				buffer[j] += 'a' - 26;
			} else if (buffer[j] < 62) {
				buffer[j] += '0' - 52;
			} else if (buffer[j] == 62) {
				buffer[j] = '+';
			} else if (buffer[j] == 63) {
				buffer[j] = '/';
			}
		}
		// Write 4 characters at a time
		for (int j = 0; j < 4; j++) {
			(*out)[k++] = buffer[j];
		}
		i += 3;
	}
	// Handle the last 1 or 2 bytes
	if (len % 3 == 1) {
		buffer[0] = (data[i] >> 2) & 0x3F;
		buffer[1] = (data[i] << 4) & 0x3F;
		if (buffer[0] < 26) {
			buffer[0] += 'A';
		} else if (buffer[0] < 52) {
			buffer[0] += 'a' - 26;
		} else if (buffer[0] < 62) {
			buffer[0] += '0' - 52;
		} else if (buffer[0] == 62) {
			buffer[0] = '+';
		} else if (buffer[0] == 63) {
			buffer[0] = '/';
		}
		if (buffer[1] < 26) {
			buffer[1] += 'A';
		} else if (buffer[1] < 52) {
			buffer[1] += 'a' - 26;
		}
		buffer[2] = '=';
		buffer[3] = '=';
		for (int j = 0; j < 4; j++) {
			(*out)[k++] = buffer[j];
		}
	} else if (len % 3 == 2) {
		buffer[0] = (data[i] >> 2) & 0x3F;
		buffer[1] = ((data[i] << 4) | (data[i + 1] >> 4)) & 0x3F;
		buffer[2] = (data[i + 1] << 2) & 0x3F;
		for (int j = 0; j < 3; j++) {
			if (buffer[j] < 26) {
				buffer[j] += 'A';
			} else if (buffer[j] < 52) {
				buffer[j] += 'a' - 26;
			} else if (buffer[j] < 62) {
				buffer[j] += '0' - 52;
			} else if (buffer[j] == 62) {
				buffer[j] = '+';
			} else if (buffer[j] == 63) {
				buffer[j] = '/';
			}
		}
		buffer[3] = '=';
		for (int j = 0; j < 4; j++) {
			(*out)[k++] = buffer[j];
		}
	}
}

void base64_decode(const char *data, int len, char **out, int *out_len) {
	*out_len = (len >> 2) * 3 - (data[len - 1] == '=') - (data[len - 2] == '=');
	*out = malloc(*out_len);
	char buffer[4];
	int i = 0;
	int k = 0;
	while (i < len) {
		// Read 4 characters at a time
		for (int j = 0; j < 4; j++) {
			buffer[j] = data[i++];
			// Convert each character to 6 bits
			if (buffer[j] >= 'A' && buffer[j] <= 'Z') {
				buffer[j] -= 'A';
			} else if (buffer[j] >= 'a' && buffer[j] <= 'z') {
				buffer[j] -= 'a' - 26;
			} else if (buffer[j] >= '0' && buffer[j] <= '9') {
				buffer[j] -= '0' - 52;
			} else if (buffer[j] == '+') {
				buffer[j] = 62;
			} else if (buffer[j] == '/') {
				buffer[j] = 63;
			} else if (buffer[j] == '=') {
				buffer[j] = -1;
			}
		}
		// Convert 6 bits to 8 bits
		(*out)[k++] = (buffer[0] << 2) | (buffer[1] >> 4);
		if (buffer[2] != -1) {
			(*out)[k++] = (buffer[1] << 4) | (buffer[2] >> 2);
			if (buffer[3] != -1) {
				(*out)[k++] = (buffer[2] << 6) | buffer[3];
			}
		}
	}
}
