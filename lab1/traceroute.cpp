#include "header.h"
#include <stdio.h>
#include <stdlib.h>
#include <iostream>

#define DEBUG
struct timeval timestamp;
using namespace std;

int main(int argc, char* argv[]){
#ifdef DEBUG
	cout << "**************TEST START**************\n";
	cout.flush();
#endif // DEBUG

    if(argc != 2){
        fprintf(stderr, "Usage : traceroute HOSTNAME\n");
        exit(0);
	}
	else
	{
		string arg_value = string(argv[1]);
		cout << arg_value << endl;
	}

    int ttl = 1, n = 0;
    socklen_t fromlen = sizeof(struct sockaddr_in);
    char buf[1024];
    struct hostent *host;
    struct icmp_pkt icmp_pkt;
    struct in_addr sin_addr;
    struct sockaddr_in send, recv;

    memset(&buf, 0, sizeof(buf));
    memset(&icmp_pkt, 0, sizeof(icmp_pkt));
    memset(&sin_addr, 0, sizeof(sin_addr));
    memset(&send, 0, sizeof(struct sockaddr_in));
    memset(&recv, 0, sizeof(struct sockaddr_in));


    // 0. get hostname & address
    if(inet_aton(argv[1], &sin_addr) == 0){
        // domain name
        if((host = gethostbyname(argv[1])) == NULL){
            herror("gethostbyname");
            exit(0);
        }
        sin_addr = *(struct in_addr *)host->h_addr_list[0];
    }else{
        if((host = gethostbyaddr(&sin_addr, sizeof(struct in_addr), AF_INET)) == NULL){
            // herror(" gethostbyaddr");
            host = new hostent();
            host->h_name = new char[64]();
            strcpy(host->h_name, inet_ntoa(sin_addr));
        }
    }
    fprintf(stderr, "\nTrace [%s] [%s] : %d bytes of data.\n\n", host->h_name, inet_ntoa(sin_addr), (int)sizeof(struct icmp_pkt));

    // 1. create sockets
    int send_sock = 0, recv_sock = 0;
    if((send_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1){
        perror("socket error");
        exit(0);
    }
    if((recv_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1){
        perror(strerror(recv_sock));
        exit(0);
    }
    // fill in send address
    send.sin_family = AF_INET;
    send.sin_addr = sin_addr;


	struct timeval timeout;
	timeout.tv_sec = 0;
	timeout.tv_usec = 100;

    while(ttl < 30){
        if(setsockopt(send_sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) == -1){
            perror("set socket");
            continue;
        }
		if (setsockopt(recv_sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0)
		{
			perror("setsockopt failed\n");
			continue;
		}
		if (setsockopt(recv_sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0)
		{
			perror("setsockopt failed\n");
			continue;
		}

		//if (setsockopt(recv_sock, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout,
		//	sizeof(timeout)) < 0)
		//	perror("setsockopt failed\n");

        // 2. create icmp packet
        memset(&icmp_pkt, 0, sizeof(struct icmp_pkt));
        build_pkt(&icmp_pkt, ttl);


        // 3. send & receive
        if(sendto(send_sock, &icmp_pkt, sizeof(icmp_pkt), 0, (struct sockaddr *)&send, sizeof(send)) == -1){
            perror("sendto");
            continue;
        }
        if((n = recvfrom(recv_sock, buf, sizeof(buf), 0, (struct sockaddr *)&recv, &fromlen))  == -1){
			if (n == -1 && errno == EAGAIN)
			{
			}
			else
			{
				perror("recvform");
				continue;
			}
        }

        // 4. 解析封包 + 5. 輸出結果
        ttl += parse_pkt(buf, n);
    }

#ifdef DEBUG
	cout << "**************TEST END**************\n";
	cout.flush();
#endif // DEBUG


    return 0;
}

