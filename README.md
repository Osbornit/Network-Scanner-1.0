# Python ARP Network Scanner

A command-line tool for scanning the local network to discover connected devices. It sends ARP requests and listens for replies, then looks up the hardware manufacturer for each device's MAC address.

Results are printed live as they are discovered and processed.

## Features

* **Auto-Detection**: Automatically finds your local network range (e.g., `192.168.1.1/24`)
* **Live Results**: Uses multithreading to perform slow vendor lookups without blocking the scan. Devices appear as they are found
* **Vendor Lookup**: Fetches the device manufacturer (e.g., "Apple, Inc.", "Samsung Electronics") from the `api.macvendors.com` API
* **Duplicate Prevention**: Keeps track of found MAC addresses to avoid printing the same device multiple times

## How It Works

1. The script first determines the local network range and interface by finding the default gateway
2. It starts a sniffer thread to listen for ARP packets
3. It starts a worker thread that monitors a queue for devices to look up
4. The main thread sends a broadcast ARP request ("who-has") to every possible IP on the network
5. As devices send ARP replies ("is-at"), the sniffer thread's callback function (`process_packet`) adds the new `(IP, MAC)` pair to the queue
6. The worker thread picks up the `(IP, MAC)` pair, performs the (slower) web request to get the vendor, and then prints the complete line of information

This threaded queue model ensures the network scan itself is fast and not bottlenecked by slow API requests.

## Requirements

* Python 3.x
* `pip` (Python package installer)
* **Root / Administrator Privileges**: This script uses raw sockets to send and receive packets, which requires elevated permissions

## Installation

1. Clone this repository or download the `network_scanner.py` file
2. Open a terminal in the project's directory
3. Install the required Python packages:

```bash
pip install -r requirements.txt
```

## Usage

The script must be run as root (or with `sudo`) to function correctly.

```bash
# On Linux/macOS
sudo python3 network_scanner.py

# On Windows (in an Administrator terminal)
python network_scanner.py
```

## Example Output

```
[+] Found gateway 192.168.1.1 on interface en0
[+] Network range is: 192.168.1.0/24

-----SCANNING (Results will appear as they are found)-----
IP Address		MAC Address		Manufacturer
-----------------------------------------------------------
[+] Sniffer thread started. Sending packets...
[+] Packets sent. Waiting 5 seconds for replies...
192.168.1.1		00:3a:9d:f4:1a:b1		ASUSTek COMPUTER INC.
192.168.1.104		c4:8e:8f:2b:9c:0a		Google, Inc.
192.168.1.121		f8:e0:79:a3:b0:c2		Apple, Inc.
[+] Sniffer finished. Waiting for all lookups to complete...
192.168.1.115		b8:27:eb:4d:5f:e6		Raspberry Pi Foundation
-----SCAN COMPLETE-----
```

## Troubleshooting

### Permission Denied
If you encounter a permission error, make sure you're running the script with administrator/root privileges using `sudo` (Linux/macOS) or an Administrator command prompt (Windows).

### No Devices Found
* Ensure you're connected to a network
* Check that your firewall isn't blocking ARP packets
* Try running the script multiple times as some devices may not respond immediately

### Vendor Lookup Fails
The vendor lookup relies on the `api.macvendors.com` API. If lookups fail:
* Check your internet connection
* The API may be rate-limited or temporarily unavailable
* Devices will still be listed with their IP and MAC addresses

## License

This project is open source and available under the MIT License.

## Disclaimer

This tool is intended for network administration and educational purposes only. Only scan networks you own or have explicit permission to scan. Unauthorized network scanning may be illegal in your jurisdiction.