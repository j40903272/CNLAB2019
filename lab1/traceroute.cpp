#include "header.h"

struct timeval timestamp;

int main(int argc, char* argv[]){
	// printf("%d %d %d\n", sizeof(unsigned short), sizeof(short), sizeof(unsigned char));
	// return 0;
	
	if(argc != 2){
		fprintf(stderr, "Usage : traceroute HOSTNAME\n");
		exit(0);
	}

	int ttl = 2, n = 0;
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


    

    // create hostname & address
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


    // create sockets
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




	// start
	while(ttl < 30){
		if(setsockopt(send_sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) == -1){
			perror("set socket");
			continue;
		}

		memset(&icmp_pkt, 0, sizeof(struct icmp_pkt));
		build_pkt(&icmp_pkt, ttl);

		if(sendto(send_sock, &icmp_pkt, sizeof(icmp_pkt), 0, (struct sockaddr *)&send, sizeof(send)) == -1){
            perror("sendto");
            continue;
        }
        if((n = recvfrom(recv_sock, buf, sizeof(buf), 0, (struct sockaddr *)&recv, &fromlen))  == -1){
            perror("recvform");
            continue;
        }
        ttl += parse_pkt(buf, n);
        // if(recv.sin_addr.s_addr == sin_addr.s_addr)
        // 	break;
	}


	return 0;
} 

