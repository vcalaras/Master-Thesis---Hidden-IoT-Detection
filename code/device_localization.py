from statistics import mean
from scapy.all import RadioTap, sniff, Dot11, sendp, Dot11Deauth
from interface_func import monitor_mode, managed_mode, set_channel

interface = "wlp0s20f3"


def localize_device(interface, device_mac_address, channel, ap_mac_address):
    signal_table = []

    def packet_handler_signal_strenght(packet):
        nonlocal signal_table
        if RadioTap in packet and Dot11 in packet:
            wifi_packet = packet[Dot11]
            radio_tap = packet[RadioTap]

            source_mac = wifi_packet.addr2


            if source_mac == device_mac_address:
                signal_strength = radio_tap.dBm_AntSignal
                signal_table.append(signal_strength)
                if(len(signal_table) == 10):
                    print("Signal Strengh is " + str(mean(signal_table)))
                    signal_table = []


    monitor_mode(interface)

    set_channel(interface, channel)

    #while(True):
    #send_deauth_requests(interface, device_mac_address, ap_mac_address)
        # Sniff Wi-Fi packets and process them with the callback function
    sniff(iface=interface + "mon", prn=packet_handler_signal_strenght)
        #,timeout = 10) 

    managed_mode(interface)


def send_deauth_requests(interface, device_mac_address, ap_mac_address):
    deauth_req = RadioTap() / Dot11(type=0, subtype=12, addr1=device_mac_address, addr2=ap_mac_address, addr3=ap_mac_address) / Dot11Deauth(reason=7)
    sendp(deauth_req, iface=interface + "mon", inter=0.1, count=10, verbose=1)


print("Signal Strength:")
localize_device(interface, "8a:56:4e:bb:14:ed", "1", "f4:06:8d:b7:75:f9")