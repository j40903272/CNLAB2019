import numpy as np
import json
import math

class entropy_detector():

    def mean_calculator(self,_list):
        total = 0
        total_alpha = 0
        for index in range(len(_list)):
          total += _list[index][0] * _list[index][1]
          total_alpha += _list[index][0]
        return total/float(total_alpha)
    
    def std_deviation_calculator(self,_list):
        total = 0
        E = self.mean_calculator(_list)
        for index in range(len(_list)):     
          total += (_list[index][1]-E)*(_list[index][1]-E) 
        total /= float(len(_list))
        return math.sqrt(total)
          
    def __init__(self):
        self.flowstats = {}
        self.detected_flags = {}
        self.byte_threshold = 500
        self.packet_threshold = 5
        
        # my new
        self.eth_packet_count = {}
        self.hold_number = 3
        self.init_H = 1
        self.lambda_threshold_multiplicative_factor = 1      
        
        self.hold_list = []
        for index in range(self.hold_number) :
          self.hold_list.append([math.pow(2,index),self.init_H])
        
        self.EH = self.mean_calculator(self.hold_list)
        self.sigma_std_deviation = self.std_deviation_calculator(self.hold_list)        
#        self.delta_threshold = self.lambda_threshold_multiplicative_factor * self.sigma_std_deviation
        self.delta_threshold = 1
        print("init delta_threshold", self.delta_threshold)      
              
    def detect(self, msg):
        print("entropy detect")
        # print(json.dumps(msg.to_jsondict()))
        
        for stats in msg.body:
          if stats.priority != 0:
#            print(stats.packet_count)
#            print(stats.match['eth_dst'])
            count = stats.packet_count
            mac = stats.match['eth_dst']
            if self.eth_packet_count.has_key(mac) :
              old_count = self.eth_packet_count[mac][1]
              self.eth_packet_count[mac] = [old_count,count,count-old_count,0.0]
            else :
              self.eth_packet_count[mac] = [0,count,count-0,0.0]
        
        #print(self.eth_packet_count)
              
        total_count = 0
        for each_mac in self.eth_packet_count :
          delta_x = self.eth_packet_count[each_mac][2]
          if delta_x > 0 :
            total_count += delta_x
        
        #print(total_count)
        
        if total_count > 0 :        
          H = 0.0    
          for each_mac in self.eth_packet_count :
            delta_x = self.eth_packet_count[each_mac][2]
            if delta_x > 0 :
              p = delta_x/float(total_count)
              self.eth_packet_count[each_mac][3] = p
              #print(p)
              H += -p * math.log(p)
     
          N = len(self.eth_packet_count)
          H = H / (math.log(N)+1)
          #print(H) 
          for index in range(len(self.hold_list)):
            if index < len(self.hold_list) - 1: 
              self.hold_list[index][1] = self.hold_list[index+1][1]        
          self.hold_list[-1][1] = H        
          if self.EH - H > self.delta_threshold:
            # ddos
            self.detected_flags = 1
          else:
            self.EH = self.mean_calculator(self.hold_list)
            self.sigma_std_deviation = self.std_deviation_calculator(self.hold_list)        
            self.delta_threshold = self.lambda_threshold_multiplicative_factor * self.sigma_std_deviation
            self.detected_flags = 0
        
        # for stats in msg.body:
        #     if not stats.cookie in self.flowstats:
        #         self.flowstats[stats.cookie] = {
        #             'packet_count': [stats.packet_count],
        #             'byte_count': [stats.byte_count]
        #         }
        #         self.detected_flags[stats.cookie] = 0
        #     else :
        #         self.flowstats[stats.cookie]["byte_count"].append(stats.byte_count)
        #         self.flowstats[stats.cookie]["packet_count"].append(stats.packet_count)
        #         self.flowstats[stats.cookie]["byte_count"] = self.flowstats[stats.cookie]["byte_count"][-60:]
        #         self.flowstats[stats.cookie]["packet_count"] = self.flowstats[stats.cookie]["packet_count"][-60:]


        #         check_result_bytes = self._detect(self.byte_threshold,
        #                                                  self.flowstats[stats.cookie]['byte_count'])
        #         check_result_packets = self._detect(self.packet_threshold,
        #                                            self.flowstats[stats.cookie]['packet_count'])

        #         if check_result_bytes == 1 or check_result_packets == 1:
        #             #print 'DDoS detected!!', "bytes / packets:", check_result_bytes, '/', check_result_packets
        #             self.detected_flags[stats.cookie] = 1

                

    def _detect(self, threshold, data):
        difference_list = [data[i] - data[i-1] for i in range(1, len(data))]
        if len(difference_list) == 0:
            return 0

        average_difference = np.mean(difference_list)
        std = np.std(difference_list)
        
        for item in difference_list:
            #print(item - average_difference > 3 * std, item > threshold, std >= 0)
            if item - average_difference > 3 * std and item > threshold and std >= 0:
                return 1
        return 0