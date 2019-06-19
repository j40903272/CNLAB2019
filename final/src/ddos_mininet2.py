from mininet.topo import Topo

class DDosTopo(Topo):
    def __init__(self):
        Topo.__init__(self)
        h1 = self.addHost("h1")
        h2 = self.addHost("h2")
        h3 = self.addHost("h3")
        h4 = self.addHost("h4")
        h5 = self.addHost("h5")
        h6 = self.addHost("h6")
        h7 = self.addHost("h7")
        h8 = self.addHost("h8")
        h9 = self.addHost("h9")
        h10 = self.addHost("h10")
        h11 = self.addHost("h11")
        h12 = self.addHost("h12")
        h13 = self.addHost("h13")
        h14 = self.addHost("h14")
        h15 = self.addHost("h15")
        h16 = self.addHost("h16")

        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        
        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(h3, s1)
        self.addLink(h4, s1)
        self.addLink(h5, s1)
        self.addLink(h6, s1)
        self.addLink(h7, s1)
        self.addLink(h8, s1)
        self.addLink(h9, s2)
        self.addLink(h10, s2)
        self.addLink(h11, s2)
        self.addLink(h12, s2)
        self.addLink(h13, s2)
        self.addLink(h14, s2)
        self.addLink(h15, s2)
        self.addLink(h16, s2)

        self.addLink(s1, s2)
        

topos = {'ddostopo':(lambda: DDosTopo())}


# sudo mn --custom ddos_mininet.py --topo=ddostopo --mac --switch=ovsk,protocols=OpenFlow13 --controller remote
