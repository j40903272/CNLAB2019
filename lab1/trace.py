from socket import *
import socket
import os
import sys
import struct
import time
import select
import binascii

ICMP_ECHO_REQUEST = 8
MAX_HOPS = 30
TIMEOUT = 2.0
TRIES = 3

def checksum(str_):
    # In this function we make the checksum of our packet 
    str_ = bytearray(str_)
    csum = 0
    countTo = (len(str_) // 2) * 2

    for count in range(0, countTo, 2):
        thisVal = str_[count+1] * 256 + str_[count]
        csum = csum + thisVal
        csum = csum & 0xffffffff

    if countTo < len(str_):
        csum = csum + str_[-1]
        csum = csum & 0xffffffff

    csum = (csum >> 16) + (csum & 0xffff)
    csum = csum + (csum >> 16)
    answer = ~csum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer

def build_packet():
    myChecksum = 0
    myID = os.getpid() & 0xFFFF

    # Make a dummy header with a 0 checksum.
    # struct -- Interpret strings as packed binary data
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, myID, 1)
    #header = struct.pack("!HHHHH", ICMP_ECHO_REQUEST, 0, myChecksum, pid, 1)
    
    data = struct.pack("d", time.time())

    # Calculate the checksum on the data and the dummy header.
    # Append checksum to the header.
    myChecksum = checksum(header + data) 
    myChecksum = htons(myChecksum)

    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, myID, 1)
    packet = header + data
    return packet

def get_route(hostname):
    timeLeft = TIMEOUT
    ip_hist = []
    arrive = 0
    cnt = 0
    for ttl in range(1,MAX_HOPS):
        for tries in range(TRIES):
            destAddr = socket.gethostbyname(hostname)
            
            icmp = socket.getprotobyname("icmp")
            mySocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
            
            mySocket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, struct.pack('I', ttl))
            mySocket.settimeout(TIMEOUT)
            try:
                d = build_packet()
                mySocket.sendto(d, (hostname, 0))

                t = time.time()

                recvPacket, addr = mySocket.recvfrom(1024)

                timeReceived = time.time()

                
                icmpHeader = recvPacket[20:28]
                request_type, code, checksum, packetID, sequence = struct.unpack("bbHHh", icmpHeader)
                
                if request_type == 0:
                    bytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                    if(tries == 0):
                        print ("%s %.3f ms" % (addr[0], (timeReceived-t)*1000)),
                    
                    else:
                        print ("%.3f ms" % ((timeReceived-t)*1000)),
                    arrive = 1

                elif request_type == 11:
                    bytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                    
                    if(tries == 0):
                        print ("%s, %.3f ms" % (addr[0], ((timeReceived-t)*1000))),
                    else:
                        print ("%.3f ms " % ((timeReceived-t)*1000)),

                    

            except socket.timeout:
                print "*",
                continue

            finally:
                mySocket.close()
        print("")

        if arrive == 1:
            return;
# print("-------------------")
# get_route('google.com')
# print("-------------------------")
get_route('www.nasa.gov')



