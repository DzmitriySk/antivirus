import nmap
import socket
import subprocess
import re

def get_gateway():
    try:
        route_result = subprocess.check_output("route print", shell=True).decode('latin1')
        gateway = re.search(r'0\.0\.0\.0\s+0\.0\.0\.0\s+([0-9\.]+)', route_result).group(1)
    except Exception as e:
        print(f"Error: {e}")
        gateway = None
    return gateway

def get_local_ip():
    local_ip = socket.gethostbyname(socket.gethostname())
    return local_ip

def get_mac_and_ips(local_ip, gateway):
    nm = nmap.PortScanner()
    local_ip_prefix = ".".join(local_ip.split('.')[:-1])
    scan_result = nm.scan(hosts=f'{local_ip_prefix}.0/24', arguments='-sn')

    devices = []
    for ip, data in scan_result['scan'].items():
        if 'mac' in data:
            mac = data['mac']
        else:
            mac = 'MAC not found'
        devices.append((ip, mac))
    return devices

def scan():
    local_ip = get_local_ip()
    gateway = get_gateway()
    devices = get_mac_and_ips(local_ip, gateway)

    print(f"Local IP: {local_ip}")
    print(f"Gateway: {gateway}")
    print("Devices in network:")
    for device in devices:
        print(f"IP: {device[0]}, MAC: {device[1]}")

if __name__ == "__main__":
    scan()
