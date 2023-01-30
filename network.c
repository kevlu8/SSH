#include "network.h"

// does not free pointer
char *_make_packet(const char *buf, const int len) {
	// calculate padding length
	int padlen = 16 - (len + 5) % 16;
	if (padlen < 4)
		padlen += 16;
	// add random length to padding
	padlen += randint(0, (236 - padlen) / 8) * 8;
	// allocate memory for packet
	char *packet = malloc(len + padlen + 5);
	// write packet length
	*(int *)packet = htonl(len + padlen + 1);
	// write padding length
	packet[4] = padlen;
	// write payload
	memcpy(packet + 5, buf, len);
	// write padding
	randbytes(packet + 5 + len, padlen);
	// return packet
	return packet;
}

void send_packet(const int s, const char *buf, const int len) {
	unsigned char *packet = _make_packet(buf, len);
	int res;
	while (1) {
		send(s, packet, len + 5 + packet[4], 0);
		if (res != -1 || errno != EAGAIN || errno != EWOULDBLOCK)
			break;
		usleep(1000);
	}
	free(packet);
}

int recv_packet(const int s, char *buf) {
	// receive first 4 bytes
	int len;
	while (1) {
		len = recv(s, buf, 4, 0);
		if (len != -1 || errno != EAGAIN || errno != EWOULDBLOCK)
			break;
		usleep(1000);
	}
	if (len != 4)
		return -1;
	int datalen = ntohl(*(int *)buf);
	// receive rest of packet
	while (1) {
		len = recv(s, buf, datalen, 0);
		if (len != -1 || errno != EAGAIN || errno != EWOULDBLOCK)
			break;
		usleep(1000);
	}
	if (len != datalen)
		return -1;
	int paddinglen = *(unsigned char *)buf;
	// move payload to beginning of buffer
	memmove(buf, buf + 1, datalen - paddinglen - 1);
	// return length of payload
	return datalen - paddinglen - 1;
}

void send_packet_chacha(const int s, const char *buf) { send(s, buf, 35000, 0); }

int recv_packet_chacha(const int s, char *buf) { return recv(s, buf, 35000, 0); }

void send_packet_aes(aes_ctx *ctx, const int s, const char *buf, const int len) {}

int recv_packet_aes(aes_ctx *ctx, const int s, char *buf) {
	// read the first 16 bytes
	int len = recv(s, buf, 16, 0);
	if (len != 16)
		return -1;
	// decrypt the first 16 bytes
	aes_decrypt_finalize(ctx, buf, 16, buf, &len);
	// get the length of the packet
	int datalen = ntohl(*(int *)buf);
	// read the rest of the packet (12 bytes already read)
	len = recv(s, buf + 16, datalen - 12, 0);
	if (len != datalen - 12)
		return -1;
	// decrypt the rest of the packet
	aes_decrypt_finalize(ctx, buf + 16, datalen - 12, buf + 16, &len);
	int padlen = (unsigned char)buf[4];
	// move payload to beginning of buffer
	memmove(buf, buf + 5, datalen - 1 - padlen);
	// return length of payload
	return datalen - 1 - padlen;
}
