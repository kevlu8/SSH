#include "aes.h"
#include "chacha.h"
#include "ec.h"
#include "ecdsa.h"
#include "network.h"
#include "random.h"
#include "sha.h"
#include <signal.h>

void handler() {
	fprintf(stderr, "Connection closed by or unable to connect to remote host\n");
	exit(1);
}

// supported methods
char *kex_algos[] = {
	"ecdh-sha2-nistp256",
	// "ecdh-sha2-nistp384",
	// "ecdh-sha2-nistp521",
	// "diffie-hellman-group-exchange-sha256",
	// "diffie-hellman-group14-sha256",
};

char *hostkey_algos[] = {
	"ecdsa-sha2-nistp256",
	// "ecdsa-sha2-nistp384",
	// "ecdsa-sha2-nistp521",
};

char *enc_algos[] = {
	"aes128-ctr",
	// "chacha20-poly1305@openssh.com"
};

char *mac_algos[] = {
	"hmac-sha2-256",
};

char *comp_algos[] = {
	"none",
	// "zlib",
};

int main(int argc, char **argv) {
	char buf[35000];
	int len;
	int hlen = 0;
	char tmp[128];

	// register signal handlers
	signal(SIGPIPE, handler);

	// establish connection to server
	int s = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in addr = {0};
	addr.sin_family = AF_INET;
	inet_pton(AF_INET, argc == 2 ? argv[1] : "127.0.0.1", &addr.sin_addr);
	addr.sin_port = htons(argc == 3 ? strtol(argv[2], NULL, 10) : 22);
	connect(s, (struct sockaddr *)&addr, sizeof(addr));

	// send and receive identification string
	char *identification = "SSH-2.0-PZSSH_0.1\r\n";
	send(s, identification, strlen(identification), 0);
	len = recv(s, buf, sizeof(buf), 0);

	// initialize exchange hash
	sha256_ctx Hctx;
	sha256_init(&Hctx);
	*(int *)tmp = htonl(strlen(identification) - 2);
	sha256_update(&Hctx, tmp, 4);
	sha256_update(&Hctx, identification, strlen(identification) - 2);
	*(int *)tmp = htonl(len - 2);
	sha256_update(&Hctx, tmp, 4);
	sha256_update(&Hctx, buf, len - 2);

	// send key exchange init
	// first byte is packet type
	buf[0] = 0x14;
	// next 16 bytes are cookie
	randbytes(buf + 1, 16);
	// next 4 bytes are length of kex_algos
	// ignore for now
	// copy in kex_algos
	len = 1 + 16;
	char *p = buf + 1 + 16 + 4;
	for (int i = 0; i < sizeof(kex_algos) / sizeof(char *); i++) {
		if (i != 0)
			*p++ = ',';
		strcpy(p, kex_algos[i]);
		p += strlen(kex_algos[i]);
	}
	// copy in length of kex_algos
	*(int *)(buf + len) = htonl(p - (buf + len) - 4);
	len = p - buf;
	// next 4 bytes are length of hostkey_algos
	// ignore for now
	// copy in hostkey_algos
	p = buf + len + 4;
	for (int i = 0; i < sizeof(hostkey_algos) / sizeof(char *); i++) {
		if (i != 0)
			*p++ = ',';
		strcpy(p, hostkey_algos[i]);
		p += strlen(hostkey_algos[i]);
	}
	// copy in length of hostkey_algos
	*(int *)(buf + len) = htonl(p - (buf + len) - 4);
	len = p - buf;
	// do the following twice (once for c->s and once for s->c)
	for (int x = 0; x < 2; x++) {
		// next 4 bytes are length of enc_algos
		// ignore for now
		// copy in enc_algos
		p = buf + len + 4;
		for (int i = 0; i < sizeof(enc_algos) / sizeof(char *); i++) {
			if (i != 0)
				*p++ = ',';
			strcpy(p, enc_algos[i]);
			p += strlen(enc_algos[i]);
		}
		// copy in length of enc_algos
		*(int *)(buf + len) = htonl(p - (buf + len) - 4);
		len = p - buf;
	}
	// do the following twice (once for c->s and once for s->c)
	for (int x = 0; x < 2; x++) {
		// next 4 bytes are length of mac_algos
		// ignore for now
		// copy in mac_algos
		p = buf + len + 4;
		for (int i = 0; i < sizeof(mac_algos) / sizeof(char *); i++) {
			if (i != 0)
				*p++ = ',';
			strcpy(p, mac_algos[i]);
			p += strlen(mac_algos[i]);
		}
		// copy in length of mac_algos
		*(int *)(buf + len) = htonl(p - (buf + len) - 4);
		len = p - buf;
	}
	// do the following twice (once for c->s and once for s->c)
	for (int x = 0; x < 2; x++) {
		// next 4 bytes are length of comp_algos
		// ignore for now
		// copy in comp_algos
		p = buf + len + 4;
		for (int i = 0; i < sizeof(comp_algos) / sizeof(char *); i++) {
			if (i != 0)
				*p++ = ',';
			strcpy(p, comp_algos[i]);
			p += strlen(comp_algos[i]);
		}
		// copy in length of comp_algos
		*(int *)(buf + len) = htonl(p - (buf + len) - 4);
		len = p - buf;
	}
	// next 8 bytes are zero for languages
	memset(buf + len, 0, 8);
	len += 8;
	// next 1 byte is boolean for first_kex_packet_follows
	buf[len++] = 0;
	// next 4 bytes are 0 by spec
	memset(buf + len, 0, 4);
	len += 4;
	// send packet
	send_packet(s, buf, len);
	// add the packet to the exchange hash
	*(int *)tmp = htonl(len);
	sha256_update(&Hctx, tmp, 4);
	sha256_update(&Hctx, buf, len);

	// receive key exchange init
	len = recv_packet(s, buf);
	// if the packet type is wrong, exit
	if (buf[0] != 0x14) {
		fprintf(stderr, "Expected packet type: SSH_MSG_KEXINIT");
		return 1;
	}
	// add the packet to the exchange hash
	*(int *)tmp = htonl(len);
	sha256_update(&Hctx, tmp, 4);
	sha256_update(&Hctx, buf, len);

	// start dh kex
	// get the buffer ready
	buf[0] = 0x1e;
	// next 4 bytes are length of the key
	// ignore for now
	len = 5;
	// generate client private key
	char x[32];
	mpz_t mpz_x, n;
	mpz_inits(mpz_x, n, NULL);
	EC_init_curve("nistp256");
	EC_order(n);
	do {
		randbytes(x, sizeof(x));
		mpz_import(mpz_x, sizeof(x), 1, 1, 0, 0, x);
	} while (mpz_cmp(mpz_x, n) >= 0 || mpz_cmp_ui(mpz_x, 0) == 0);
	// generate client public key
	EC_point Q;
	EC_init_generator(&Q);
	EC_mul(&Q, &Q, mpz_x);
	// store client public key
	len += EC_serialize_point(&Q, buf + len);
	EC_clear(&Q);
	mpz_clear(n);
	// copy in length of key
	*(int *)(buf + 1) = htonl(len - 5);
	send_packet(s, buf, len);
	// store e for adding to the exchange hash
	memcpy(tmp + 8, buf + 5, len - 5);
	*(int *)(tmp + 4) = htonl(len - 5);

	// receive server dh kex reply
	len = recv_packet(s, buf);
	// if the packet type is wrong, exit
	if (buf[0] != 0x1f) {
		fprintf(stderr, "Expected packet type: SSH_MSG_KEXDH_REPLY");
		return 1;
	}
	// add the server host key to the exchange hash
	int hostkey_len = ntohl(*(int *)(buf + 1));
	sha256_update(&Hctx, buf + 1, hostkey_len + 4);
	// add e to the exchange hash
	sha256_update(&Hctx, tmp + 4, ntohl(*(int *)(tmp + 4)) + 4);
	// get the server host key
	EC_init(&Q);
	p = buf + 5 + hostkey_len - 65;
	EC_parse_point(p, 65, &Q);
	p += 65;
	// get the server dh public key
	EC_point f;
	EC_init(&f);
	EC_parse_point(p + 4, ntohl(*(int *)p), &f);
	// add f to the exchange hash
	*(int *)tmp = htonl(ntohl(*(int *)p));
	sha256_update(&Hctx, tmp, 4);
	sha256_update(&Hctx, p + 4, ntohl(*(int *)p));
	p += 4 + ntohl(*(int *)p);
	// calculate K
	EC_mul(&f, &f, mpz_x);
	mpz_clear(mpz_x);
	// add K to the exchange hash
	char K[33];
	int Klen = (mpz_sizeinbase(f.x, 2) + 8) / 8;
	mpz_export(K + Klen - 32, NULL, 1, 1, 0, 0, f.x);
	EC_clear(&f);
	*(int *)tmp = htonl(Klen);
	sha256_update(&Hctx, tmp, 4);
	sha256_update(&Hctx, K, Klen);
	// finalize the exchange hash
	unsigned char H[32];
	sha256_final(&Hctx, H);
	// get the signature
	int sig_len = ntohl(*(int *)p);
	p += 4;
	p += ntohl(*(int *)p) + 4;
	// load the host key
	ECDSA_keypair keypair;
	ECDSA_init(&keypair);
	keypair.pubkey = &Q;
	if (ECDSA_verify(&keypair, H, 32, p)) {
		fprintf(stderr, "Signature verification failed\n");
		return 1;
	}
	EC_clear(&Q);

	// send new keys
	buf[0] = 0x15;
	send_packet(s, buf, 1);

	// receive new keys
	len = recv_packet(s, buf);
	// if the packet type is wrong, exit
	if (buf[0] != 0x15) {
		fprintf(stderr, "Expected packet type: SSH_MSG_NEWKEYS");
		return 1;
	}
	// generate new keys
	sha256_init(&Hctx);
	*(int *)tmp = htonl(Klen);
	memcpy(tmp + 4, K, Klen);
	memcpy(tmp + Klen + 4, H, 32);
	memcpy(tmp + Klen + 37, H, 32);
	char ivctos[32];
	char ivstoc[32];
	char kctos[32];
	char kstoc[32];
	char mctos[32];
	char mstoc[32];
	tmp[Klen + 36] = 'A';
	sha256_digest(tmp, Klen + 69, ivctos);
	tmp[Klen + 36] = 'B';
	sha256_digest(tmp, Klen + 69, ivstoc);
	tmp[Klen + 36] = 'C';
	sha256_digest(tmp, Klen + 69, kctos);
	tmp[Klen + 36] = 'D';
	sha256_digest(tmp, Klen + 69, kstoc);
	tmp[Klen + 36] = 'E';
	sha256_digest(tmp, Klen + 69, mctos);
	tmp[Klen + 36] = 'F';
	sha256_digest(tmp, Klen + 69, mstoc);

	// initialize ciphers (macs are not implemented yet)
	// client to server
	aes_ctx c2s;
	aes_init(&c2s, kctos, (uint64_t *)ivctos);
	// server to client
	aes_ctx s2c;
	aes_init(&s2c, kstoc, (uint64_t *)ivstoc);

	len = recv_packet_aes(&s2c, s, buf);

	for (int i = 0; i < len; i++)
		putchar(buf[i]);

	return 0;
}
