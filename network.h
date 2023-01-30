#include "aes.h"
#include "random.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

void send_packet(const int, const char *, const int);
int recv_packet(const int, char *);
void send_packet_chacha(const int, const char *);
int recv_packet_chacha(const int, char *);
void send_packet_aes(aes_ctx *, const int, const char *, const int);
int recv_packet_aes(aes_ctx *, const int, char *);
