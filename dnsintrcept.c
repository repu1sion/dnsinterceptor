// gcc dnsintrcept.c -o dnsintrcept

//-------------------------------------- headers ----------------------
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>  /* for hostname */
#include <sys/types.h>  /* below 5 for ip addr */
#include <sys/socket.h>
#include <sys/stat.h>     /* for stat() */
#include <sys/ioctl.h>
#include <netinet/in.h> /* for AF_INET, AF_INET6 families */
#include <net/if.h>
#include <ifaddrs.h> /* for getifaddrs() */
#include <arpa/inet.h>
#include <netdb.h>  /* for getnameinfo() */
#include <netpacket/packet.h>
#include <net/ethernet.h> /* the L2 protocols */
#include <errno.h>

//-------------------------------------- defines  ----------------------
#define DEBUG

#ifdef DEBUG
 #define debug(x...) printf(x)
#else
 #define debug(x...)
#endif

#define APP_NAME "[dsn_interceptor] "
#define VERSION "0.1"

#define CONFIG_NAME "/etc/boot-menu.txt"

#define PACKET_SIZE 512

//-------------------------------------- structs  ----------------------
struct dns_config
{
	char *config_file;
	int fg;
	char *host;
	int port;
};

struct dns_server
{
	struct dns_config config;
	int listenfd;
} dns_server;

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

struct dns_response_packet
{
	char *name;
	u_int16_t type;
	u_int16_t class;
	u_int32_t ttl;
	u_int16_t rdlength;
	char *rdata;
};

struct dns_question
{
	char *qname;
	u_int16_t qtype;
	u_int16_t qclass;
};

//-------------------------------------- funcs -------------------------
int init()
{
	int rv = 0;
	int sd;
	struct sockaddr_in sin;

	debug("Initializing DNS server.\n");
	memset(&dns_server, 0x0, sizeof(dns_server));

	dns_server.config.config_file = NULL;
	dns_server.config.fg = 0;
	dns_server.config.port = 53;
	dns_server.config.host = "127.0.0.1";

	dns_server.listenfd = 0;

	debug("Opening sockets.\n");

	/* TODO - O_CLOEXEC and O_NONBLOCK */
	sd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sd < 0)
	{
		printf("can't open socket\n");
		rv = 1; return rv;
	}
	else
	{
		debug("socket opened with value: %d\n", sd);
	}

	memset((char *)&sin, 0x0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(dns_server.config.port);
	sin.sin_addr.s_addr = inet_addr(dns_server.config.host);
	rv = bind(sd, (struct sockaddr *)&sin, sizeof(sin));
	if (rv < 0)
	{
		printf("bind failed\n");
		printf("error: %s , rv = %d\n", strerror(errno), rv);
		rv = 1; return rv;
	}

	dns_server.listenfd = sd; 

	return rv;
}

void dns_print_header (struct dns_header *header)
{
	printf ("ID: %d\n", header->id);
	printf ("qr: %d\n", header->qr);
	printf ("opcode: %d\n", header->opcode);
	printf ("aa: %d\n", header->aa);
	printf ("tc: %d\n", header->tc);
	printf ("rd: %d\n", header->rd);
	printf ("ra: %d\n", header->ra);
	printf ("z: %d\n", header->z);
	printf ("rcode: %d\n", header->rcode);

	printf ("qdcount: %d\n", header->qdcount);
	printf ("ancount: %d\n", header->ancount);
	printf ("nscount: %d\n", header->nscount);
	printf ("arcount: %d\n", header->arcount);
}

void dns_print_packet (struct dns_packet *packet)
{
	dns_print_header (&packet->header);
	printf ("data_size: %d\n", packet->data_size);
	printf ("data: %s\n", packet->data);
}

int dns_header_parse(struct dns_header *header, void *data)
{
	memcpy(header, data, 12);

	header->id = ntohs (header->id);
	header->qdcount = ntohs (header->qdcount);
	header->ancount = ntohs (header->ancount);
	header->nscount = ntohs (header->nscount);
	header->arcount = ntohs (header->arcount);

	return 1;
}

int dns_question_parse(struct dns_packet *pkt)
{
	u_int16_t i = 0, j, length;
	char *question = pkt->data;

	length = question[i++];
	do
	{
		printf("SIZE: %d\n", length);
		for (j = 0; j < length; j++)
		{
			printf("%c", question[i + j]);
		}
		printf("\n");
		i += length;
		length = question[i++];
	} while (length != 0 && i < pkt->data_size);

	return 1;
}

int dns_request_parse(struct dns_packet *pkt, void *data, u_int16_t size)
{
	int i;

	dns_header_parse(&pkt->header, data);

	pkt->data = malloc(size - 12);
	memcpy(pkt->data, data + 12, size - 12);
	pkt->data_size = size - 12;

	i = 0;
	while (i < pkt->header.qdcount)
	{
		dns_question_parse(pkt);
		i++;
	}

	return 1;
}

void dns_daemon()
{
	int req_size;
	char buf[PACKET_SIZE+4] = {0};
	socklen_t from_len;
	struct sockaddr_in from;
	struct dns_packet *pkt;

	from_len = sizeof (from);

	printf("Accepting connections on %s\n", dns_server.config.host);
	while(1)	
	{
		req_size = recvfrom(dns_server.listenfd, buf, PACKET_SIZE+4, 0, 
					(struct sockaddr *)&from, &from_len);
		debug("client: %s %d\n", strerror(errno), req_size);
		if (req_size > 0)
		{
			pkt = calloc(1, sizeof(struct dns_packet));
			dns_request_parse(pkt, buf, req_size);

			dns_print_packet(pkt);

			free (pkt->data);
			free (pkt);
		}
	}
}

int main(int argc, char *argv[])
{
	int i;
	int rv;

	printf(APP_NAME "version %s \n", VERSION);

	rv = init();
	if (rv)
	{
		printf("init failed\n");
		return 1;
	}

	dns_daemon();

#if 0
	while (1)
	{
		usleep(10000);
	}
#endif

	return 0;
}
