import requests
import matplotlib.pyplot as plt
from scapy.all import Dot11, RadioTap, sniff
from interface_func import monitor_mode, managed_mode, set_channel


interface = 'wlp0s20f3'


# This function uses the free macvendors API to identify the manufacturer of the mac address
def MAC_address_lookup(mac_address):
    url = f"https://api.macvendors.com/{mac_address}"

    try:
        response = requests.get(url)
        if response.status_code == 200:
            vendor = response.text
            return vendor
        else:
            return "Unknown"

    except Exception as e:
        print(f"An error occurred: {e}")

# Collects data on all the devices on the same channel
def collect_device_data(interface, channel, data_dict):

    monitor_mode(interface)
    set_channel(interface, channel)

    def packet_callback(packet):

        if packet.haslayer(Dot11):
            # Check if the packet is a data frame and is sent to the specified device, data frames received
            if packet.addr1 in data_dict and packet.type == 2:
                data_dict[packet.addr1][1] =  data_dict[packet.addr1][1] + 1

            # Check if the packet is a data frame and is sent by the specified device, data frames sent
            if packet.addr2 in data_dict.keys() and packet.type == 2:
                data_dict[packet.addr2][2] =  data_dict[packet.addr2][2] + 1

            # Check if the packet is a probe request frame sent by the specified device, probe requests sent
            if packet.subtype == 4 and packet.addr2 in data_dict:
                data_dict[packet.addr2][3] =  data_dict[packet.addr2][3] + 1

            # Total packets
            if packet.addr1 in data_dict:
                data_dict[packet.addr1][4] =  data_dict[packet.addr1][4] + 1
            if packet.addr2 in data_dict:
                data_dict[packet.addr2][4] =  data_dict[packet.addr2][4] + 1

    sniff(iface=interface + 'mon', prn=packet_callback, timeout=60)

    managed_mode(interface)


# Measures the number of bytes per second of a specific device (MAC address)
def measure_packets_per_second(interface, device_mac, channel, duration):
    
    monitor_mode(interface)
    set_channel(interface, channel)
    
    bytes_per_s = []
    count_bytes = 0

    def packet_callback(packet):
        nonlocal count_bytes

        if packet.haslayer(Dot11):

            if packet.addr2 == device_mac and packet.type == 2:
                count_bytes += len(packet)


    for i in range(duration):
        sniff(iface=interface + 'mon', prn=packet_callback, timeout=1)
        bytes_per_s.append(count_bytes)
        count_bytes = 0

    managed_mode(interface)

    return bytes_per_s

#bytes_per_s = measure_packets_per_second(interface, "b0:c5:54:64:60:8b", '1', 60)
#print(bytes_per_s)


#time_values = range(1, len(bytes_per_s) + 1)

# Create a bar chart
#plt.bar(time_values, bytes_per_s, color='blue', edgecolor='black')

#plt.xlabel("Time (seconds)")
#plt.ylabel("Bytes per second")
#plt.title("Bytes Per Second Over Time")
#plt.show()