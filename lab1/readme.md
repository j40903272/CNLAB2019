# To-do list
* timestamp display casting
    * long long int -> double
* timeout handling
    * print * in log
* report
    
---
# Workflow
和投影片大致相同, 步驟有標記在traceroute.cpp的註解裡面
1. 建立Socket
    * sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP) 開啟ICMP protocal的socket
    * inet_aton(hostname, &sock.sin_addr) 設定目標位置
    * setsockopt(sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) 設定TTL
2. 建立ICMP封包
3. 發送 & 接收封包
    * sendto(sock, &icmp_pkt, sizeof(icmp_pkt), 0, (struct sockaddr *)&send, sizeof(send))
    * recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr *)&recv, &fromlen))
4. 解析封包
    * 我在寫的時候遇到的回傳封包type==TIME_EXEC的時候, 封包格式會和傳出去的不同, 需要注意
5. 輸出結果

