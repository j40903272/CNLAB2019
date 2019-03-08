#ifndef __HEADER_H__
#define __HEADER_H__


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/ip.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>


#define ECHO_REPLY 	0
#define ECHO_REQUEST 8
#define TIME_EXEC 11

// #define ErrorAndExit(status) \
//     fprintf(stderr, "Error: Line %u in file %s\n\n", __LINE__, __FILE__); \
//		exit(0);

struct icmp_pkt{
	uint8_t type;
	uint8_t code;
	uint16_t checksum;
	uint16_t id;
	uint16_t seq;
	// char data[32];
};



unsigned long long timediff(struct timeval *);
unsigned short checkSum(const struct icmp_pkt *);
void build_pkt(struct icmp_pkt *, int);
void print_pkt_info(struct ip *, struct icmp_pkt *);
int parse_pkt(char*, const int);


#endif /* __HEADER_H__ */
