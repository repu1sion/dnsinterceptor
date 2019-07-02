//gcc client.c -o client && ./client

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

struct dns_header
{
	u_int16_t id; /* a 16 bit identifier assigned by the client */
	u_int16_t qr:1;
	u_int16_t opcode:4;
	u_int16_t aa:1;
	u_int16_t tc:1;
	u_int16_t rd:1;
	u_int16_t ra:1;
	u_int16_t z:3;
	u_int16_t rcode:4;
	u_int16_t qdcount;
	u_int16_t ancount;
	u_int16_t nscount;
	u_int16_t arcount;
};

struct dns_packet
{
	struct dns_header header;
//	struct dns_question question;
	char *data;
	u_int16_t data_size;
};

int main (int argc, char **argv)
{
	struct dns_packet *packet;
	struct sockaddr_in sin;
	int sin_len = sizeof (sin);
	int sock;
	char buf[256] = {0};
	int buf_len = 0;

	sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (sock < 0)
	{                                                                                                              
                printf("can't open socket\n");                                                                         
                return 1;                                                                                     
        }                                                                                                              
        else                                                                                                           
        {                                                                                                              
                printf("socket opened with value: %d\n", sock);
        }
	memset ((char *) &sin, 0, sizeof (sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(53);
	inet_aton("127.0.0.1", &sin.sin_addr);
//	inet_aton("201.6.0.103", &sin.sin_addr);

	packet = calloc(1, sizeof (struct dns_packet));
	packet->header.id = 2048;

	memcpy(buf, &packet->header, 12);
	buf_len = 12;
	memcpy(buf + buf_len, "www.uol.com.br", sizeof("www.uol.com.br"));
	buf_len += sizeof("www.uol.com.br");

	sendto(sock, buf, buf_len, 0, (struct sockaddr *) &sin, sin_len);
	recv(sock, buf, 255, 0);

	printf("%s\n", buf);

	return 0;
}
