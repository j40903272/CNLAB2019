#include "header.h"

struct timeval timestamp;

int main(int argc, char* argv[]){
    if(argc != 2){
        fprintf(stderr, "Usage : traceroute HOSTNAME\n");
        exit(0);
    }

    int ttl = 1, n = 0, cnt = 0;
    socklen_t fromlen = sizeof(struct sockaddr_in);
    char buf[1024];
    struct hostent *host;
    struct icmp_pkt icmp_pkt;
    struct in_addr sin_addr;
    struct sockaddr_in send, recv;
    struct timeval timeout;
    struct parse_result result;


    memset(&buf, 0, sizeof(buf));
    memset(&icmp_pkt, 0, sizeof(icmp_pkt));
    memset(&sin_addr, 0, sizeof(sin_addr));
    memset(&send, 0, sizeof(struct sockaddr_in));
    memset(&recv, 0, sizeof(struct sockaddr_in));
    timeout.tv_sec = 1;
    timeout.tv_usec = 10000;




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



    bool hashostname = false;
    unsigned long long time_record[3];
    struct in_addr node_ip;

    while(ttl < 30){
        
        if(setsockopt(send_sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) == -1){
            perror("set send socket");
            exit(0);
        }
        if (setsockopt(recv_sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
            perror("set recv socket");
            exit(0);
        }
        // 2. create icmp packet
        memset(&icmp_pkt, 0, sizeof(struct icmp_pkt));
        build_pkt(&icmp_pkt, ttl);


        // 3. send & receive
        if(sendto(send_sock, &icmp_pkt, sizeof(icmp_pkt), 0, (struct sockaddr *)&send, sizeof(send)) == -1){
            perror("sendto");
            exit(0);
        }
        if((n = recvfrom(recv_sock, buf, sizeof(buf), 0, (struct sockaddr *)&recv, &fromlen))  == -1){
            if(errno != EAGAIN)
                perror("recvform");
        }

        // 4. 解析封包
        result = parse_pkt(buf, n, ttl);
        if(result.flag == PARSE_FAIL)
            continue;
        else if(result.flag == PARSE_SUCCESS){
            time_record[cnt] = result.travel_time;
            node_ip = result.ip->ip_src;
            hashostname = true;
        }
        else
            time_record[cnt] = 99999;

        
        
        // 5. 輸出結果
        if(cnt++ == 2){
            // print log
            fprintf(stderr, "%2d\t", ttl);

            if(!hashostname)
                fprintf(stderr, "Timeout\t\t");
            else
                fprintf(stderr, "%s\t", inet_ntoa(node_ip));

            
            for(int i = 0 ; i < 3 ; i++){
                if(time_record[i] == 99999)
                    fprintf(stderr, "        *%c", " \n"[i == 2]);
                else
                    fprintf(stderr, "%6lld ms%c", time_record[i], " \n"[i == 2]);
            }
            // reset
            cnt = 0;
            hashostname = false;
            ttl++;

            //if(!memcmp(node_ip, sin_addr, sizeof(node_ip)))
            if(node_ip.s_addr == sin_addr.s_addr)
                break;
        }
    }


    return 0;
}

