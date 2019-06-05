import numpy as np

class basic_detector():

    def __init__(self):
        self.flowstats = {}
        self.detected_flags = {}
        self.byte_threshold = 500
        self.packet_threshold = 5
        self.max_record_length = 60
        

    def detect(self, msg):
        dst_group = {}
        self.detected_flags = {}

        for stats in msg.body:
            if not stats.cookie in self.flowstats:
                self.flowstats[stats.cookie] = {
                    'packet_count': [stats.packet_count],
                    'byte_count': [stats.byte_count]
                }
            else:
                self.flowstats[stats.cookie]["byte_count"].append(stats.byte_count)
                self.flowstats[stats.cookie]["packet_count"].append(stats.packet_count)
                self.flowstats[stats.cookie]["byte_count"] = self.flowstats[stats.cookie]["byte_count"][-self.max_record_length:]
                self.flowstats[stats.cookie]["packet_count"] = self.flowstats[stats.cookie]["packet_count"][-self.max_record_length:]


            dst = stats.match["eth_dst"]
            if dst not in dst_group:
                dst_group = set([stats.cookie])
                self.detected_flags[dst] = 0
            else:
                dst_group[dst].add(stats.cookie)



        for dst in dst_group:
            byte_count = np.array([ self.pad(self.flowstats[cookie]["byte_count"]) for cookie in dst])
            byte_sum = byte_count.sum(axis=0)
            packet_count = np.array([ self.pad(self.flowstats[cookie]["packet_count"]) for cookie in dst])
            packet_sum = packet_count.sum(axis=0)

            check_result_bytes = self._detect(self.byte_threshold, byte_sum)
            check_result_packets = self._detect(self.packet_threshold, packet_sum)

            if check_result_bytes == 1 or check_result_packets == 1:
                #print 'DDoS detected!!', "bytes / packets:", check_result_bytes, '/', check_result_packets
                self.detected_flags[dst] = 1

    def pad(self, record):
        l = len(record)
        return [0]*(self.max_record_length-l) + record


    def _detect(self, threshold, data):
        difference_list = [data[i] - data[i-1] for i in range(1, len(data))]
        if len(difference_list) == 0:
            return 0

        average_difference = np.mean(difference_list)
        std = np.std(difference_list)
        
        for item in difference_list:
            print(item - average_difference > 3 * std, item > threshold, std >= 0)
            if item - average_difference > 3 * std and item > threshold and std >= 0:
                return 1
        return 0