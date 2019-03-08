#include "header.h"

extern struct timeval timestamp;

unsigned long long timediff(struct timeval *st){
	struct timeval ed;
	gettimeofday(&ed, NULL);
    unsigned long long t = 1000000 * (ed.tv_sec-st->tv_sec)+ ed.tv_usec-st->tv_usec;
    return t/1000;
}

unsigned short checkSum(const struct icmp_pkt *pkt){
	unsigned short *pt = (unsigned short *)pkt;
	uint32_t sum = 0;
	for(int i = 0 ; i < 4 ; i++)
		sum += *pt++;
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	return (unsigned short) ~sum;
}

void build_pkt(struct icmp_pkt *icmp, int ttl){
	icmp->type = ECHO_REQUEST;
	icmp->code = 0;
    icmp->id = getpid();
    icmp->seq = ttl;
    icmp->checksum = checkSum(icmp);
    gettimeofday(&timestamp, NULL);
}

void print_pkt_info(struct ip *ip, struct icmp_pkt *icmp){
	fprintf(stderr, "%d %s\n", icmp->seq, inet_ntoa(ip->ip_src));
	fprintf(stderr, "\ttype %d\n", icmp->type);
	fprintf(stderr, "\tcode %d\n", icmp->code);
	fprintf(stderr, "\tchecksum %d\n", icmp->checksum);
	fprintf(stderr, "\tid %d\n", icmp->id);
	fprintf(stderr, "\tseq %d\n", icmp->seq);
}

int parse_pkt(char buf[], const int pkt_len){
	struct ip *ip;
	struct icmp_pkt *icmp;
	int ttl_add = 1;
	static int cnt = 0;


	ip = (struct ip *)buf;
	int ip_len = ip->ip_hl << 2;
	icmp = (struct icmp_pkt *)(buf + ip_len);

	// ip check
	if(ip->ip_p != IPPROTO_ICMP)
		return 0;
	else if((pkt_len - ip_len) < 8){
		fprintf(stderr, "malformed packet\n");
		return 0;
	}

	// icmp check
	if(icmp->type == ECHO_REPLY && icmp->id == getpid()){
		if(cnt == 2)
			ttl_add = 30;
	}
	else if(icmp->type == TIME_EXEC){
		icmp = (struct icmp_pkt *)((char*)icmp + ip_len + 8);
		if(icmp->id != getpid())
			return 0;
		icmp->type = TIME_EXEC;
	}

	//print_pkt_info(ip, icmp);
	if(cnt == 0)
		fprintf(stderr, "%2d\t%s\t%6lld ms ", icmp->seq, inet_ntoa(ip->ip_src), timediff(&timestamp));
	else
		fprintf(stderr, "%6lld ms%c", timediff(&timestamp), "\t\n"[cnt==2]);
	

	if(cnt++ == 2)
		cnt = 0;
	else
		ttl_add = 0;

	return ttl_add;
}