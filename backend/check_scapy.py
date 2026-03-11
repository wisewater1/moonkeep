from scapy.all import *
try:
    from scapy.all import ICMPv6ND_NA, DHCP6_Solicit
    print("IPv6 imports OK")
except ImportError as e:
    print(f"IPv6 imports FAILED: {e}")
