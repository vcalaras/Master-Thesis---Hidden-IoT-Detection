import subprocess
import time

# Set the the wifi interface to monitor mode
def monitor_mode(wifi_interface):
     # Kill network processes before putting the interface in monitor mode
    try:
        subprocess.run(["sudo", "airmon-ng", "check", '"kill'], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError as e:
        print("Error killing network processes:", e)
        exit(1)

    # Enable monitor mode
    # Sometimes there is an error, so we retry again
    while(True):
        try:
            subprocess.run(["sudo", "airmon-ng", "start", wifi_interface], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            break
        except subprocess.CalledProcessError as e:
            print("Error enabling monitor mode:", e)
            time.sleep(1)


# Set the wifi interface back to managed mode
def managed_mode(wifi_interface):
     # Disable monitor mode
    try:
        subprocess.run(["sudo", "airmon-ng", "stop", wifi_interface+"mon"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError as e:
        print("Error disabling monitor mode:", e)
        exit(1)
    
    # Restore the network manager (will enable back wifi)
    try:
        subprocess.run(["sudo", "service", "NetworkManager", "start"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError as e:
        print("Eror restoring the Network Manager:", e)
        exit(1)


def set_channel(interface, channel):
    try:
        subprocess.run(["sudo", "iw", "dev", interface + "mon", "set", "channel", channel])
    except subprocess.CalledProcessError as e:
        print("Error changing channels")