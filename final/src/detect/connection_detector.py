class connection_detector():

    def __init__(self):
        self.flowstats = set()
        self.detected_flags = {}
        self.connection_threshold = 50

                
    def detect(self, msg):
        if len(msg.body) > self.connection_threshold:
            suspicious = True
        for stats in msg.body:
            if not stats.cookie in self.flowstats:
                self.flowstats.add(stats.cookie)
                self.detected_flags[stats.cookie] = suspicious

    # To Do
    # connection success rate

                