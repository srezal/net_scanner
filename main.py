import scapy.all as scapy
from mac_vendor_lookup import MacLookup
import subprocess
import optparse
import re


def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-i", "--interface", dest="interface", help="Interface")
    (options, arguments) = parser.parse_args()
    if not options.interface:
        parser.error("[-] Specify an Interface, use --help for more info")
    return options


def get_own_ip():
    own_ip = re.search(r"\d+.\d+.\d+.\d+", subprocess.check_output(["ifconfig", options.interface]).decode())
    return own_ip.group(0)


def scan(ip):
    MacLookup().update_vendors()
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list, unanswered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)
    clients_list = []
    for element in answered_list:
        try:
            vendor = MacLookup().lookup(element[1].hwsrc)
        except KeyError:
            vendor = "UNDEFINED (Maybe APPLE)"
        clients_list.append({"ip" : element[1].psrc,
                             "mac" : element[1].hwsrc,
                             "vendor" : vendor})

    return clients_list, [element[1].pdst for element in unanswered_list]


def print_result(clients_list):
    for client in clients_list:
        print(client['ip'], client['mac'], client["vendor"])


options = get_arguments()
own_ip = get_own_ip()
print("IP\t\t\t\tMAC address\t\t\t\tVendor\n" + "-"*60)
clients_list, unanswered_list = scan(f"{own_ip}/24")
print_result(clients_list)
while unanswered_list:
    clients_list, unanswered_list = scan(unanswered_list)
    print_result(clients_list)


