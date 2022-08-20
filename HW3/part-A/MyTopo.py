from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Node
from mininet.log import setLogLevel, info
from mininet.cli import CLI

class LinuxRouter( Node ):
    "A Node with IP forwarding enabled."

    def config( self, **params ):
        super( LinuxRouter, self).config( **params )
        # Enable forwarding on the router
        self.cmd( 'sysctl net.ipv4.ip_forward=1' )

    def terminate( self ):
        self.cmd( 'sysctl net.ipv4.ip_forward=0' )
        super( LinuxRouter, self ).terminate()


class NetworkTopo( Topo ):

    def build( self, **_opts ):

        r1 = self.addNode( 'r1', cls=LinuxRouter, ip='10.0.1.1/24')
        r2 = self.addNode( 'r2', cls=LinuxRouter, ip='10.0.2.1/24')
        r3 = self.addNode( 'r3', cls=LinuxRouter, ip='10.0.6.1/24')
        r4 = self.addNode( 'r4', cls=LinuxRouter, ip='10.0.4.1/24')
        
        

        h1 = self.addHost( 'h1', ip='10.0.1.2/24', defaultRoute='via 10.0.1.1' )
        h2 = self.addHost( 'h2', ip='10.0.4.2/24', defaultRoute='via 10.0.4.1' )

        self.addLink( h1, r1, intfName2='r1-eth1', params2={ 'ip' : '10.0.1.1/24' })
        
        self.addLink(r1, r2, intfName1 = 'r1-eth2', params1={'ip' : '10.0.2.2/24'}, intfName2 = 'r2-eth2', params2={'ip' : '10.0.2.1/24'})
        
        self.addLink(h2, r4, intfName2='r4-eth1', params2={ 'ip' : '10.0.4.1/24' })
        
        self.addLink(r2, r4, intfName1 = 'r2-eth1', params1={'ip' : '10.0.3.1/24'}, intfName2 = 'r4-eth2', params2={'ip' : '10.0.3.2/24'})
        
        self.addLink(r1, r3, intfName1 = 'r1-eth3', params1={'ip' : '10.0.6.1/24'}, intfName2 = 'r3-eth2', params2={'ip' : '10.0.6.2/24'})
        
        self.addLink(r3, r4, intfName1 = 'r3-eth1', params1={'ip' : '10.0.5.1/24'}, intfName2 = 'r4-eth3', params2={'ip' : '10.0.5.2/24'})
        
        

def run():
    "Test linux router"
    topo = NetworkTopo()
    net = Mininet( topo=topo )  
    net.start()
    
    
    info(net['r1'].cmd("ip route add 10.0.4.0/24 via 10.0.2.1 dev r1-eth2"))
    info(net['r1'].cmd("ip route add 10.0.3.0/24 via 10.0.2.1 dev r1-eth2"))
    info(net['r2'].cmd("ip route add 10.0.4.0/24 via 10.0.3.2 dev r2-eth1"))
    info(net['r2'].cmd("ip route add 10.0.1.0/24 via 10.0.2.2 dev r2-eth2"))
    
    info(net['r2'].cmd("ip route add 10.0.5.0/24 via 10.0.3.2 dev r2-eth1"))
    info(net['r2'].cmd("ip route add 10.0.6.0/24 via 10.0.2.2 dev r2-eth2"))
    
    info(net['r4'].cmd("ip route add 10.0.1.0/24 via 10.0.3.1 dev r4-eth2"))
    info(net['r4'].cmd("ip route add 10.0.2.0/24 via 10.0.3.1 dev r4-eth2"))
    
    info(net['r1'].cmd("ip route add 10.0.4.0/24 via 10.0.6.2 dev r1-eth3"))
    info(net['r1'].cmd("ip route add 10.0.5.0/24 via 10.0.6.2 dev r1-eth3"))
    info(net['r3'].cmd("ip route add 10.0.4.0/24 via 10.0.5.2 dev r3-eth1"))
    info(net['r3'].cmd("ip route add 10.0.1.0/24 via 10.0.6.1 dev r3-eth2"))
    
    info(net['r3'].cmd("ip route add 10.0.3.0/24 via 10.0.5.2 dev r3-eth1"))
    info(net['r3'].cmd("ip route add 10.0.2.0/24 via 10.0.6.1 dev r3-eth2"))
    
    info(net['r4'].cmd("ip route add 10.0.1.0/24 via 10.0.5.1 dev r4-eth3"))
    info(net['r4'].cmd("ip route add 10.0.6.0/24 via 10.0.5.1 dev r4-eth3"))

    
    
    info('Routing Table on Router:\n')
    print net[ 'r1' ].cmd( 'route' )
    print net[ 'r2' ].cmd( 'route' )
    print net[ 'r3' ].cmd( 'route' )
    print net[ 'r4' ].cmd( 'route' )
    
    CLI( net )
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    run()