import numpy as np

class group_detector():

    def __init__(self):
        self.flowstats = {}
        self.detected_flags = {}
        self.byte_threshold = 500
        self.packet_threshold = 5

                
    def detect(self, msg):
        for stats in msg.body:
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
                                                         self.flowstats[stats.cookie]['byte_count'])
                check_result_packets = self._detect(self.packet_threshold,
                                                   self.flowstats[stats.cookie]['packet_count'])

                if check_result_bytes == 1 or check_result_packets == 1:
                    #print 'DDoS detected!!', "bytes / packets:", check_result_bytes, '/', check_result_packets
                    self.detected_flags[stats.cookie] = 1

                

    def _detect(self, threshold, data):
    	group_size = 10
    	group_list = [0 for i in range(len(data)/group_size)]
		for group in range(len(data)/group_size):
			for cnt in range(group_size):
				group_list[group] += data[group*group_size+cnt]

		difference_list = [group_list[i] - group_list[i-1] for i in range(1, len(group_list))]
        if len(difference_list) == 0:
            return 0

        average_difference = np.mean(difference_list)
        std = np.std(difference_list)
        
        for item in difference_list:
            print(item - average_difference > 3 * std, item > threshold*group_size, std >= 0)
            if item - average_difference > 3 * std and item > threshold*group_size and std >= 0:
                return 1
        return 0