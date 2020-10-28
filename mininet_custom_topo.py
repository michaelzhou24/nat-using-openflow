'''
Custom topology for cs417 sample
'''

from mininet.topo import Topo
from mininet.node import Node, OVSKernelSwitch

class LinuxRouter( Node ):

    def config( self, **params ):
        super( LinuxRouter, self).config( **params )
        self.cmd( 'sysctl net.ipv4.ip_forward=1' )

    def terminate( self ):
        self.cmd( 'sysctl net.ipv4.ip_forward=0' )
        super( LinuxRouter, self ).terminate()

class CustomNATTopo(Topo):
    def __init__(self):
        Topo.__init__(self)

        # NAT switch
        nat = self.addSwitch('s1', cls=OVSKernelSwitch, protocols='OpenFlow12')

        # Gateway
        gateway = self.addNode('r1', cls=LinuxRouter, ip='7.7.7.1')
        self.addLink(nat, gateway)

        # Internal hosts
        for id in [1, 2, 3, 4]:
            host = self.addHost('int%d' % id, ip='192.168.0.%d/16' % id,
                                mac='00:00:00:00:01:%02d' % id,
                                defaultRoute='via 192.168.0.254')
            self.addLink(host, nat)

        # External hosts
        for id in [1, 2, 3, 4]:
            host = self.addHost('ext%d' % id, ip='4.4.%d.2/24' % id,
                                mac='00:00:00:00:02:%02d' % id,
                                defaultRoute='via 4.4.%d.1' % id)
            self.addLink(host, gateway,
                         params1={'ip': '4.4.%d.2/24' % id},
                         params2={'ip': '4.4.%d.1/24' % id})

topos = {'cs417_sample':(lambda: CustomNATTopo())}
