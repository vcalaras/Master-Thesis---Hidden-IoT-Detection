import device_detector
import device_identification
import time

interface = "wlp0s20f3"

def main():
    device_detector.monitor_mode(interface)

    devices_types = []
    devices_addr = []

    target_APs = device_detector.scan_access_points(interface)
    print(target_APs)

    count = 0
    for AP in target_APs:
        devices_addr = devices_addr + device_detector.scan_devices(AP[0], AP[1])
        count = count + 1
        print(AP[0])
        print(str(count) + " out of " + str(len(target_APs)) + " done")
        
    print(devices_addr)
    
    device_detector.managed_mode(interface)
    # Wait for the internet to come back
    time.sleep(5)

    for mac in devices_addr:
        devices_types.append(device_identification.MAC_address_lookup(mac))

    print(devices_types)



if __name__ == "__main__":
    main()