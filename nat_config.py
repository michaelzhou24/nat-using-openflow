# Configuration file for NAT controller

# Gateway settings: which IP and switch port should be used to connect to external IPs
nat_gateway_ip = '7.7.7.1'

# Address used by the switch for the external side of NAT
nat_external_ip = '7.7.7.7'
nat_external_mac = 'a2:00:00:11:22:33'

# Address used by the switch for the internal side of NAT
nat_internal_ip = '192.168.0.254'
nat_internal_net = '192.168.0.0/16'
nat_internal_mac = 'a2:00:00:11:22:44'

