
import ipaddress

host = '192.1vfyuuvfenknfei'

try:
    if '/' in host:
        network = ipaddress.ip_network(host)
        targets = network.hosts()
    else:
        targets = [ipaddress.ip_address(host)]

    for ip in targets:
        print(ip)

except ValueError:
    print("Invalid IP address or CIDR.")
