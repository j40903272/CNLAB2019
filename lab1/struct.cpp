/*  Structures defined in headers files
    just listing out to be clear
*/
//#include "header.h"
#include <stdint.h>
#include <sys/types.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/time.h>

//// netinet/in.h
//struct sockaddr_in {
//    short sin_family;
//    unsigned short sin_port;
//    struct in_addr sin_addr;
//    unsigned char sin_zero[8];
//};
//
//typedef uint32_t in_addr_t;
//struct in_addr
//{
//    in_addr_t s_addr;
//};


//// sys/time.h
//struct timeval {
//    time_t      tv_sec;     /* seconds */
//    suseconds_t tv_usec;    /* microseconds */
//};
// netinet/ip.h
struct ip {
#if BYTE_ORDER == LITTLE_ENDIAN 
    u_char  ip_hl:4,        /* header length */
            ip_v:4;         /* version */
#endif
#if BYTE_ORDER == BIG_ENDIAN 
    u_char  ip_v:4,         /* version */
            ip_hl:4;        /* header length */
#endif
    u_char  ip_tos;         /* type of service */
    short   ip_len;         /* total length */
    u_short ip_id;          /* identification */
    short   ip_off;         /* fragment offset field */
#define IP_DF 0x4000        /* dont fragment flag */
#define IP_MF 0x2000        /* more fragments flag */
    u_char  ip_ttl;         /* time to live */
    u_char  ip_p;           /* protocol */
    u_short ip_sum;         /* checksum */
    struct  in_addr ip_src,ip_dst;  /* source and dest address */
};


