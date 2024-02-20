import device_detector
import device_identification
import time

interface = "wlp0s20f3"

def main():
    devices_types = []
    devices_addr = []
    devices_chns = []
    data_packets = []

    #target_APs = device_detector.scan_access_points(interface)
    #print("Access Point addresses found:")
    #print(target_APs)

    target_APs = [('F4:06:8D:B7:75:F9', '1')]
    count = 0
    for AP in target_APs:

        devices = device_detector.scan_devices(AP[0], AP[1], interface)

        devices_addr = devices_addr + devices

        for d in devices:
            devices_chns.append(AP[1])
        

        count = count + 1
        print(str(count) + " measurements out of " + str(len(target_APs)) + " done")
        
    
    # Wait for the internet to come back
    time.sleep(5)

    device_data_dict = {}

    for mac in devices_addr:
        device_data_dict[mac] = []
        device_data_dict[mac].append({"Manufacturer": device_identification.MAC_address_lookup(mac)})
        time.sleep(1)
        


    for i in range(len(devices_addr)):
        device_data = device_identification.collect_device_data(interface, devices_addr[i], devices_chns[i])
        device_data_dict[devices_addr[i]].append(device_data)


    print(device_data_dict)


if __name__ == "__main__":
    main()