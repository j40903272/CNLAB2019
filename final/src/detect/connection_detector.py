class connection_detector():

    def __init__(self):
        self.flowstats = set()
        self.detected_flags = {}
        self.connection_threshold = 50
        self.old_dst_group = {}

                
    def detect(self, msg):
        print("connection detect")
        dst_group = {}

        for stats in msg.body:
            dst = (stats.match["eth_dst"], stats.match["dpid"])
            self.detected_flags[dst] = 0
            if dst not in dst_group:
                dst_group[dst] = 1
            else:
                dst_group[dst] += 1

        victim_dst = set()
        for dst in dst_group:
            current_connection_count = dst_group[dst]
            old_connection_cnt = 0 if dst not in self.old_dst_group else self.old_dst_group[dst]
            if (current_connection_count - old_connection_cnt) > self.connection_threshold:
                #victim_dst.add(dst)
                self.detected_flags[dst] = 1

        self.old_dst_group = dst_group

        # for stats in msg.body:
        #     dst = stats.match["eth_dst"]
        #     if dst in victim_dst:
        #         self.detected_flags[stats.cookie] = 1

    # To Do
    # connection success rate

                