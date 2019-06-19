class packetIn_detector():
	def __init__(self):
		self.history = {}
		self.detected_flags = {}
		self.threshold = 100

	def detect(self, packetIn):
		print "PacketIn detector"
		for addr in packetIn:
			old = 0 if addr not in self.history else self.history[addr]
			val = packetIn[addr] - old
			if val > self.threshold:
				self.detected_flags[addr] = 1
			else:
				self.detected_flags[addr] = 0
		self.history = packetIn.copy()