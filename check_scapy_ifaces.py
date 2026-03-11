from scapy.all import conf, get_if_list, get_working_if
print("Working Interface:", get_working_if())
print("Available Interfaces:", get_if_list())
print("Full Details:")
for iface in conf.ifaces.values():
    print(f"Name: {iface.name}, Description: {iface.description}, IP: {iface.ip}, MAC: {iface.mac}")
