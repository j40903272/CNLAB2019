from mininet.topo import Topo

class DDosTopo(Topo):
    def __init__(self):
        Topo.__init__(self)
        h1 = self.addHost("h1")
        h2 = self.addHost("h2")
        h3 = self.addHost("h3")
        h4 = self.addHost("h4")

        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        
        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(h3, s2)
        self.addLink(h4, s2)

        self.addLink(s1, s2)
        

topos = {'ddostopo':(lambda: DDosTopo())}


# sudo mn --custom ddos_mininet.py --topo=ddostopo --mac --switch=ovsk,protocols=OpenFlow13 --controller remote
