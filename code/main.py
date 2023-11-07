import device_detector
import device_identification
import time

interface = "wlp0s20f3"

def main():
    devices_types = []
    devices_addr = []
    devices_chns = []

    target_APs = device_detector.scan_access_points(interface)
    print("Access Point addresses found:")
    print(target_APs)

    count = 0
    for AP in target_APs:

        devices = device_detector.scan_devices(AP[0], AP[1], interface)

        devices_addr = devices_addr + devices

        for d in devices:
            devices_chns.append(AP[1])
        

        count = count + 1
        print(str(count) + " measurements out of " + str(len(target_APs)) + " done")

        # Gives waits for the interface to be proprely put back in managed mode before starting it again (avoids crashing and freezing)
        time.sleep(2)
        
    
    # Wait for the internet to come back
    time.sleep(5)

    for mac in devices_addr:
        devices_types.append(device_identification.MAC_address_lookup(mac))

    print(devices_addr)
    print(devices_types)
    print(devices_chns)


if __name__ == "__main__":
    main()