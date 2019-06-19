import numpy as np

class basic_detector():

    def __init__(self):
        self.flowstats = {}
        self.detected_flags = {}
        self.byte_threshold = 5000000
        self.packet_threshold = 100000

                
    def detect(self, msg):
        #print("basic detect")
        for stats in msg:
            dst = stats.match["eth_dst"]
            if not stats.cookie in self.flowstats:
                self.flowstats[stats.cookie] = {
                    'packet_count': [stats.packet_count],
                    'byte_count': [stats.byte_count]
                }
                self.detected_flags[stats.cookie] = 0
            else:
                self.flowstats[stats.cookie]["byte_count"].append(stats.byte_count)
                self.flowstats[stats.cookie]["packet_count"].append(stats.packet_count)
                self.flowstats[stats.cookie]["byte_count"] = self.flowstats[stats.cookie]["byte_count"][-60:]
                self.flowstats[stats.cookie]["packet_count"] = self.flowstats[stats.cookie]["packet_count"][-60:]


                check_result_bytes = self._detect(self.byte_threshold,
                                                         self.flowstats[stats.cookie]['byte_count'], dst)
                check_result_packets = self._detect(self.packet_threshold,
                                                   self.flowstats[stats.cookie]['packet_count'], dst)

                if check_result_bytes == 1 or check_result_packets == 1:
                    #print 'DDoS detected!!', "bytes / packets:", check_result_bytes, '/', check_result_packets
                    self.detected_flags[stats.cookie] = 1
                else:
                    self.detected_flags[stats.cookie] = 0

                

    def _detect(self, threshold, data, dst):
        difference_list = [data[i] - data[i-1] for i in range(1, len(data))]
        #print difference_list
        if len(difference_list) == 0:
            return 0

        average_difference = np.mean(difference_list)
        std = np.std(difference_list)
        cnt = 0
        
        for item in difference_list:
            #print(item - average_difference > 3 * std, item > threshold, std >= 0)
            if item > threshold:
                return 1
            if item - average_difference > 3 * std and item > threshold//10:
                cnt += 1
                if cnt >= 2: 
                    return 1
        return 0