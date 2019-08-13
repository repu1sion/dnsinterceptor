// gcc dnsintrcept.c -o dnsintrcept
//
// we accept DNS requests as raw UDP sockets, with IP and UDP headers
// if we just use clear UDP sockets - we get only dns query

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
#define VERSION "0.7"

#define CONFIG_NAME "/etc/boot-menu.txt"	//XXX - rename config

#define PACKET_SIZE 512
#define INET_ADDRSTRLEN 16
#define UDPH_LENGTH 8 

//whitelist
#define WHITE_LIST_SIZE 2048
#define WHITE_LIST_FILENAME "au.dat"
#define WHITE_LIST_LINELENGTH 128

//OPTIONS
//#define RAW_SOCKET


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

//-------------------------------------- globals -----------------------
char whitelist[WHITE_LIST_SIZE][WHITE_LIST_LINELENGTH] = {0};
unsigned int whitelist_hosts = 0;	//global num of hosts in whitelist
unsigned int new_whitelist = 1;		//set to 1 if new whitelist found

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
	dns_server.config.host = "127.0.0.1";	//XXX - not used actually, INADDR_ANY used instead

	dns_server.listenfd = 0;

	debug("Opening sockets.\n");

	// Raw udp sockets are used to send manually constructed udp packets. 
#ifdef RAW_SOCKET
	sd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
#else
	sd = socket(AF_INET, SOCK_DGRAM, 0);
#endif
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
	//listen on all interfaces, not localhost only
	sin.sin_addr.s_addr = INADDR_ANY;
	//sin.sin_addr.s_addr = inet_addr(dns_server.config.host);

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

//return num of opened tx socket
int init_tx_socket()
{
	int rv = -1;
	struct sockaddr_in sin;

#ifdef RAW_SOCKET
	int one = 1;
	const int *val = &one;
#endif

#ifdef RAW_SOCKET
	rv = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
#else
	rv = socket(AF_INET, SOCK_DGRAM, 0);
#endif
	if (rv < 0)
	{
		printf("can't open socket\n");
		rv = -1; return rv;
	}
	else
	{
		debug("tx socket opened with value: %d\n", rv);
	}

	//setup udp source port to 53, so 8.8.8.8 will return response to this port
	memset((char *)&sin, 0x0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(dns_server.config.port);
	//listen on all interfaces, not localhost only
	sin.sin_addr.s_addr = INADDR_ANY;
	//sin.sin_addr.s_addr = inet_addr(dns_server.config.host);

	if (bind(rv, (struct sockaddr *)&sin, sizeof(sin)) == -1)
	{
		printf("tx bind failed\n");
		printf("error: %s \n", strerror(errno));
		rv = -1; return rv;
	}

	/*Inform the kernel do not fill up the packet structure. we will build our own...*/
#ifdef RAW_SOCKET
	if(setsockopt(rv, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
	{
		rv = -2;
		perror("setsockopt() error");
	}
	else
		printf("setsockopt() is OK.\n");
#endif

	return rv;
}


void hexdump(void *addr, unsigned int size)
{
        unsigned int i;
        /* move with 1 byte step */
        unsigned char *p = (unsigned char*)addr;

        printf("addr : %p \n", addr);

        if (!size)
        {
                printf("bad size %u\n",size);
                return;
        }

        for (i = 0; i < size; i++)
        {
                if (!(i % 16))    /* 16 bytes on line */
                {
                        if (i)
                                printf("\n");
                        printf("0x%lX | ", (long unsigned int)(p+i)); /* print addr at the line begin */
                }
                printf("%02X ", p[i]); /* space here */
        }

        printf("\n");
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

//check if there is new whitelist and download and save it as file au.dat
void get_whitelist()
{
	int i;
	int lines_cnt = 0; 
	char line[WHITE_LIST_LINELENGTH] = {0};

	if (new_whitelist)
	{
		FILE *f = fopen(WHITE_LIST_FILENAME, "r");
		if (!f)
		{
			printf("failed to open whitelist\n");
			return;
		}
		
		whitelist_hosts = 0;
		memset(whitelist, 0x0, sizeof(whitelist));
			
		while(fgets(line, sizeof(line), f))
		{	//skip first line
			if (!lines_cnt)
			{
				lines_cnt++; continue;	
			}

			//add ip till slash to whitelist
			for (i = 0; i < WHITE_LIST_LINELENGTH; i++)
			{
				if (line[i] == '/')
				{
					//debug("found slash\n");
					break;
				}
			}

			//debug("num of chars to copy: %d\n", i);
			if (i < WHITE_LIST_LINELENGTH)
				strncpy(whitelist[whitelist_hosts++], line, i);
			
			if (++lines_cnt == WHITE_LIST_SIZE)
				break;
		}

		//just debug
		printf("-----whitelist hosts: %d -----\n", whitelist_hosts);
		for (i = 0; i < whitelist_hosts; i++)
		{
			printf("#%d. %s\n", i, whitelist[i]);	
		}

		fclose(f);

		new_whitelist = 0;
	}
}

//return 1 if in whitelist, 0 if not
int in_whitelist(char *str)
{
	int rv = 0;


	//TODO:
	//go through list of whitelisted ip addresses
	// if found - break and return 1
	// else - return 0
	

	return rv;
}

void dns_daemon()
{
	int req_size;
	ssize_t sent_bytes;
	int iph_length = 0;
	char str[INET_ADDRSTRLEN] = {0};
	char buf[PACKET_SIZE+4] = {0};
	char bufsend[PACKET_SIZE+4] = {0};
	socklen_t from_len;
	struct sockaddr_in from;
	struct sockaddr_in dest_addr;
	struct dns_packet *pkt;

	from_len = sizeof(from);

	//set dest addr
	memset((char *)&dest_addr, 0x0, sizeof(dest_addr));
        dest_addr.sin_family = AF_INET;
        dest_addr.sin_port = htons(53);
        dest_addr.sin_addr.s_addr = inet_addr("8.8.8.8");

	printf("Accepting connections on %s\n", dns_server.config.host);
	while(1)
	{	//check for new whitelist, dl, save etc
		get_whitelist();

		//we get packet starting from IP header.
		//socket, buf, buf_size, addr_from,
		req_size = recvfrom(dns_server.listenfd, buf, PACKET_SIZE+4, 0, 
					(struct sockaddr *)&from, &from_len);
		debug("rcvd : %s, bytes: %d\n", strerror(errno), req_size);

		if (req_size < 12) //min size is 12 bytes
		{
			printf("error: packet size is less than min size, skip.\n");
			continue;
		}

		debug("-----packet dump-----:\n");
		hexdump(buf, req_size);

		//ipv4 common packet
		if (from.sin_family == AF_INET)
		{
			//get ip address
			inet_ntop(AF_INET, &(from.sin_addr), str, INET_ADDRSTRLEN);
			debug("ip: %s\n", str);
			//comparing ip as string with whitelist of hosts
			if (in_whitelist(str))
			{
				debug("ip %s is in whitelist\n", str);
			}
			else
			{
				debug("ip %s is NOT in whitelist\n", str);
			}
		}

#ifdef RAW_SOCKET
		//get ip-header length
		iph_length = (buf[0] & 0x0f) * 4;
		debug("skip ip header with length: %d and udp header with length: %d\n",
			 iph_length, UDPH_LENGTH);
#endif
		pkt = calloc(1, sizeof(struct dns_packet));
		//dns_request_parse(pkt, buf + iph_length + UDPH_LENGTH, req_size);
		//dns_print_packet(pkt);

		//forward packet to google 8.8.8.8 DNS -------------------------
		memset(bufsend, 0x0, PACKET_SIZE+4);
		memcpy(bufsend, buf, req_size);
#ifdef RAW_SOCKET
		bufsend[12] = 192;
		bufsend[13] = 168;
		bufsend[14] = 0;
		bufsend[15] = 2;

		bufsend[16] = 8;
		bufsend[17] = 8;
		bufsend[18] = 8;
		bufsend[19] = 8;
#endif
		debug("-----fwd packet dump-----:\n");
		hexdump(bufsend, req_size);

		sent_bytes = sendto(dns_server.listenfd, bufsend, req_size, 0, 
					(struct sockaddr*)&dest_addr, sizeof(dest_addr));
		printf("sent bytes: %zd\n", sent_bytes);
		if (sent_bytes < 0)
		{
			printf("error: failed to send packet. errno: %s\n", strerror(errno));
		}

		free(pkt->data);
		free(pkt);
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
#if 0
	rv = init_tx_socket();
	if (rv < 0)
	{
		printf("tx init failed\n");
		return 1;
	}
#endif
	dns_daemon();

#if 0
	while (1)
	{
		usleep(10000);
	}
#endif

	return 0;
}
