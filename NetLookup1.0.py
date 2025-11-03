import scapy.all as scapy
import ipaddress
import sys
import netifaces
import requests
import threading
import time
import queue

# This set will store MACs we've already found to avoid duplicate printing
found_macs = set()

# The thread-safe queue to hold devices for vendor lookup
lookup_queue = queue.Queue()


def get_network_range():

    #Finds the active network range and interface name.

    try:
        gws = netifaces.gateways()
        default_gw_info = gws['default'][netifaces.AF_INET]
        gw_ip = default_gw_info[0]
        iface_name = default_gw_info[1]
        if_addrs = netifaces.ifaddresses(iface_name)
        ipv4_info = if_addrs[netifaces.AF_INET][0]
        my_ip = ipv4_info['addr']
        netmask = ipv4_info['netmask']
        host_interface = ipaddress.IPv4Interface(f"{my_ip}/{netmask}")
        network_range = str(host_interface.network)

        print(f"[+] Found gateway {gw_ip} on interface {iface_name}")
        print(f"[+] Network range is: {network_range}")
        return network_range, iface_name

    except Exception as e:
        print(f"[!] Error auto-detecting network range: {e}.")
        print("[!] Using default '192.168.1.1/24' on 'eth0'")
        return "192.168.1.1/24", "eth0"


def get_vendor(mac):

    #Helper function to get the vendor from the API.

    try:
        response = requests.get(f"https://api.macvendors.com/{mac}", timeout=3)
        if response.status_code == 200:
            return response.text
        elif response.status_code == 404:
            return "Unknown (Not Found)"
        else:
            # This is the fixed f-string!
            return f"Unknown (API Status {response.status_code})"
    except requests.exceptions.Timeout:
        return "Unknown (Timeout)"
    except requests.exceptions.RequestException:
        return "Unknown (API Error)"


def vendor_lookup_worker():

    #This function runs in its own thread.
    #It waits for items to appear in the queue and processes them.
    while True:
        try:
            # Wait for an item to be in the queue
            ip, mac = lookup_queue.get()

            # We use 'None' as a "sentinel" to tell the thread to stop
            if ip is None:
                break

            vendor = get_vendor(mac)
            print(f"{ip}\t\t{mac}\t\t{vendor}")

            # Signal that this task is complete
            lookup_queue.task_done()

        except Exception as e:
            print(f"[!] Error in worker thread: {e}", file=sys.stderr)
            lookup_queue.task_done()


def process_packet(packet):

    #This is the "callback" function for the sniffer.
    #Its ONLY job is to add new devices to the queue.

    if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
        ip_address = packet[scapy.ARP].psrc
        mac_address = packet[scapy.ARP].hwsrc

        # Check if we've already found this MAC
        if mac_address not in found_macs:
            found_macs.add(mac_address)
            # Add the device to the queue for the worker to process
            lookup_queue.put((ip_address, mac_address))


def scan_and_print_live(ip_range, iface_name):

    #Starts the sniffer and worker threads, then sends the ARP packets.

    print("\n-----SCANNING (Results will appear as they are found)-----")
    print("IP Address\t\tMAC Address\t\tManufacturer")
    print("-----------------------------------------------------------")

    # 1. Start the worker thread
    worker = threading.Thread(target=vendor_lookup_worker, daemon=True)
    worker.start()

    # 2. Define the sniffer thread
    sniffer_thread = threading.Thread(
        target=scapy.sniff,
        kwargs={
            'iface': iface_name,
            'filter': "arp",
            'prn': process_packet,
            'store': False,
            'timeout': 5  # Sniff for 5 seconds total
        },
        daemon=True
    )

    sniffer_thread.start()
    print("[+] Sniffer thread started. Sending packets...")

    # 3. Define and send the packets
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast_frame = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast_frame / arp_request
    scapy.sendp(arp_request_broadcast, iface=iface_name, verbose=False)

    print("[+] Packets sent. Waiting 5 seconds for replies...")

    # 4. Wait for the sniffer to time out
    sniffer_thread.join()

    print("[+] Sniffer finished. Waiting for all lookups to complete...")

    # 5. Wait for the queue to be empty
    lookup_queue.join()

    # 6. Stop the worker thread
    lookup_queue.put((None, None))
    worker.join(timeout=1.0)

    print("-----SCAN COMPLETE-----")


if __name__ == "__main__":
    if scapy.os.getuid() != 0:
        print("[!] This script must be run as root (use 'sudo').")
        sys.exit(1)

    target_range, interface = get_network_range()
    scan_and_print_live(target_range, interface)