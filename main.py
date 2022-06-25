import scapy.all as scapy
from mac_vendor_lookup import MacLookup


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list, unanswered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)
    clients_list = []
    for element in answered_list:
        clients_list.append({"ip" : element[1].psrc,
                             "mac" : element[1].hwsrc,
                             "vendor" : MacLookup().lookup(element[1].hwsrc)})

    return clients_list, [element[1].pdst for element in unanswered_list]


def print_result(clients_list):
    for client in clients_list:
        print(client['ip'], client['mac'], client["vendor"])


print("IP\t\t\t\tMAC address\t\t\t\tVendor\n" + "-"*60)
clients_list, unanswered_list = scan("192.168.0.1/24")
print_result(clients_list)
while unanswered_list:
    clients_list, unanswered_list = scan(unanswered_list)
    print_result(clients_list)


