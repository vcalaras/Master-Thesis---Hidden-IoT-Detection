import subprocess
import time

interface = "wlp0s20f3"

# Returns a list containing every MAC address of every access point (AP) detected
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
    return AP_MAC_addr





if __name__ == "__main__":

    # Enable monitor mode
    try:
        subprocess.run(["sudo", "airmon-ng", "start", interface], check=True)
    except subprocess.CalledProcessError as e:
        print("Error enabling monitor mode:", e)
        exit(1)

    target_APs = scan_access_points(interface)
    print(target_APs)

    # Delete the airmon-ng csv file
    try:
        subprocess.run(["sudo", "rm", "output-01.csv"])
    except subprocess.CalledProcessError as e:
        print("Error deleting csv file")
        exit(1)


    # Disable monitor mode
    try:
        subprocess.run(["sudo", "airmon-ng", "stop", interface+"mon"], check=True)
    except subprocess.CalledProcessError as e:
        print("Error disabling monitor mode:", e)