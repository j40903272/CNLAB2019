#include "header.h"

extern struct timeval timestamp;

class pkt_task
{
public:
	pkt_task();
	pkt_task(std::vector<char> ,int, bool, int, int);
	~pkt_task();
	int pkt_len;
	int ip_len;
	bool timeout_flag;
	int seq_number;
	std::vector<char> buff;
private:

};


pkt_task::pkt_task()
{
}
pkt_task::pkt_task(std::vector<char> _buff, int _pkt_len, bool _timeout_flag, int _seq_number, int _ip_len)
{
	//std::vector<char> tmp(_buff,_buff + length(_buff));
	this->buff = _buff;
	this->pkt_len = _pkt_len;
	this->timeout_flag = _timeout_flag;
	this->seq_number = _seq_number;
	this->ip_len = _ip_len;
}

pkt_task::~pkt_task()
{
}

std::vector<int> old_already_timeout_icmp_seq_list;
std::vector<int> old_already_complete_icmp_seq_list;
std::queue<pkt_task> task_queue;


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

#define MAX_WAIT 30

int parse_pkt(char buf[], int pkt_len){
    struct ip *ip;
    struct icmp_pkt *icmp;
    int ttl_add = 1;
    static int cnt = 0;
	static int now_task_seq_should_be = 1;
	static int max_wait = MAX_WAIT;

    ip = (struct ip *)buf;
    int ip_len = ip->ip_hl << 2;
    icmp = (struct icmp_pkt *)(buf + ip_len);

	// ip check
	if (pkt_len == -1) {
		//expire
	}
	else {
		if (ip->ip_p != IPPROTO_ICMP)
			return 0;
		else if ((pkt_len - ip_len) < 8) {
			fprintf(stderr, "malformed packet\n");
			return 0;
		}
	}

	// icmp check
	if (icmp->type == ECHO_REPLY && icmp->id == getpid()) {

	}
	else if (icmp->type == TIME_EXEC) {
		icmp = (struct icmp_pkt *)((char*)icmp + ip_len + 8);
		if (icmp->id != getpid())
			return 0;
		icmp->type = TIME_EXEC;
	}




	//fprintf(stderr, "expire %s\n", inet_ntoa(ip->ip_src));

	

	static std::vector<std::vector<pkt_task>> trace_table;
	static int trace_max = 500;
	static bool initialize_flag = true;
	if (initialize_flag) {
		trace_table.resize(trace_max);
		initialize_flag = false;
		for (int i = 0; i < trace_max; i++)
		{
			std::vector<pkt_task> a;
			trace_table.push_back(a);
		}
	}
	//trace buff resize
	if (now_task_seq_should_be >= trace_max) {
		//fprintf(stderr, "seq buffer full\n");
		int old_trace_max = trace_max;
		trace_max *= 2;
		trace_table.resize(trace_max);
		for (int i = old_trace_max; i < trace_max; i++)
		{
			std::vector<pkt_task> a;
			trace_table.push_back(a);
		}
	}

	//print_pkt_info(ip, icmp);
	int current_icmp_seq = icmp->seq;
	bool timeout_flag = pkt_len == -1 && errno == EAGAIN;
	std::vector<char> buf_tmp;
	buf_tmp.assign(buf,buf+PACK_BUFF_SIZE);
	pkt_task current_task(buf_tmp, pkt_len, timeout_flag, current_icmp_seq, ip_len);
	trace_table[current_icmp_seq].push_back(current_task);

	//recover
	if (trace_table[now_task_seq_should_be].size() != 0) {

		//fprintf(stderr, "\nrecover icmp_seq = %d task_seq = %d cnt = %d sucessfully\n", current_icmp_seq, now_task_seq_should_be, cnt);

		if (trace_table[now_task_seq_should_be].size() > cnt) {
			ip = (struct ip *) trace_table[now_task_seq_should_be][cnt].buff.data();
			ip_len = trace_table[now_task_seq_should_be][cnt].ip_len;
			icmp = (struct icmp_pkt *)(trace_table[now_task_seq_should_be][cnt].buff.data() + ip_len);
			pkt_len = trace_table[now_task_seq_should_be][cnt].pkt_len;
			current_icmp_seq = trace_table[now_task_seq_should_be][cnt].seq_number;
			timeout_flag = trace_table[now_task_seq_should_be][cnt].timeout_flag;
		}
		else
		{
			//fprintf(stderr, "wait next pkt....\n");
			return 0;
		}
	}
	else
	{
		//fprintf(stderr, "wait next node.... current get %d\n",current_icmp_seq);
		return 0;
	}

	//// ip check
	//if (pkt_len == -1) {}
	//else {
	//	if (ip->ip_p != IPPROTO_ICMP)
	//		return 0;
	//	else if ((pkt_len - ip_len) < 8) {
	//		fprintf(stderr, "malformed packet\n");
	//		return 0;
	//	}
	//}

	//// icmp check
	//if (icmp->type == ECHO_REPLY && icmp->id == getpid()) {
	//	    if(cnt == 2)
	//	        ttl_add = 30;
	//}
	//else if (icmp->type == TIME_EXEC) {
	//	icmp = (struct icmp_pkt *)((char*)icmp + ip_len + 8);
	//	if (icmp->id != getpid())
	//		return 0;
	//	icmp->type = TIME_EXEC;
	//}

	if (icmp->type == ECHO_REPLY && icmp->id == getpid()) {
		    if(cnt == 2)
		        ttl_add = 30;
	}

	//check old timeout list
	bool old_already_timeout_icmp_seq = false;
	for (std::vector<int>::iterator itr=old_already_timeout_icmp_seq_list.begin(); itr!=old_already_timeout_icmp_seq_list.end(); itr++)
	{
		if (current_icmp_seq == *itr) {
			old_already_timeout_icmp_seq = true;
		}
	}

	//check old complete list
	bool old_already_complete_icmp_seq = false;
	for (std::vector<int>::iterator itr = old_already_complete_icmp_seq_list.begin(); itr != old_already_complete_icmp_seq_list.end(); itr++)
	{
		if (current_icmp_seq == *itr && cnt) {
			old_already_complete_icmp_seq = true;
		}
	}

	if (old_already_complete_icmp_seq) {
		//ignore
	}
	else
	{
		if (cnt == 0)
		{
			if (pkt_len == -1 && errno == EAGAIN && !old_already_timeout_icmp_seq)
			{
				fprintf(stderr, "%2d\t%s\t%6s    ", current_icmp_seq, inet_ntoa(ip->ip_src),"*");
				//old_already_timeout_icmp_seq_list.push_back(current_icmp_seq);
			}
			else {
				fprintf(stderr, "%2d\t%s\t%6lld ms ", current_icmp_seq, inet_ntoa(ip->ip_src), timediff(&timestamp));
			}
		}
		else {
			if (pkt_len == -1 && errno == EAGAIN && !old_already_timeout_icmp_seq)
			{
				fprintf(stderr, "%6s   %c", "*","\t\n"[cnt == 2]);
				//old_already_timeout_icmp_seq_list.push_back(current_icmp_seq);
			}
			else {
				fprintf(stderr, "%6lld ms%c", timediff(&timestamp), "\t\n"[cnt==2]);
			}
		}		
	}
	//if (cnt == 2) {
	//	old_already_complete_icmp_seq_list.push_back(current_icmp_seq);
	//}

	if (cnt++ == 2) {
       cnt = 0;
	   now_task_seq_should_be++;
	   //fprintf(stderr,"next: %d\n",now_task_seq_should_be);
	}
	else {
        ttl_add = 0;
	}


    return ttl_add;
}