from scapy.all import RadioTap, sniff, Dot11
import device_detector
import subprocess

interface = "wlp0s20f3"


def localize_device(device_mac_address, channel):

    def packet_handler_signal_strenght(packet):
        if RadioTap in packet and Dot11 in packet:
            wifi_packet = packet[Dot11]
            radio_tap = packet[RadioTap]

            source_mac = wifi_packet.addr2

            if source_mac == device_mac_address:
                signal_strength = radio_tap.dBm_AntSignal
                print(signal_strength)


    device_detector.monitor_mode(interface)

    try:
        subprocess.run(["sudo", "iw", "dev", interface + "mon", "set", "channel", channel])
    except subprocess.CalledProcessError as e:
        print("Error changing channels")

    # Sniff Wi-Fi packets and process them with the callback function
    sniff(iface=interface + "mon", prn=packet_handler_signal_strenght)

    device_detector.managed_mode(interface)


print("Signal Strength:")
localize_device("8a:56:4e:bb:14:ed", "6")