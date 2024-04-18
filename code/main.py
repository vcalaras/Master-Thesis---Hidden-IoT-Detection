import device_detector
import device_identification
import time

interface = "wlp0s20f3"

def main():
    devices_addr = []
    devices_chns = []
    access_points = []

    #target_APs_and_Chs = device_detector.scan_access_points(interface)
    #print("Access Point addresses found:")
    #print(target_APs_and_Chs)

    target_APs_and_Chs = [('F4:06:8D:B7:75:F9', '1')]
    count = 0
    for AP in target_APs_and_Chs:

        devices = device_detector.scan_devices(AP[0], AP[1], interface)

        devices_addr = devices_addr + devices

        for d in devices:
            devices_chns.append(AP[1])
        
        for d in devices:
            access_points.append(AP[0].lower())
        

        count = count + 1
        print(str(count) + " measurements out of " + str(len(target_APs_and_Chs)) + " done")
        
        time.sleep(1)

    # Remove access points MAC addresses from devices
    devices_addr = [x for x in devices_addr if x not in access_points]

    # Wait for the internet to come back
    time.sleep(5)


    print("Checking OUIs...")
    # Initialise the dictionary for the data, the key is the device address, the value is a list representing [name of the manufacturer, data frames received, data frames sent, probe request sent, total frames, 
    # signal strength
    device_data_dict = {}
    for addr in devices_addr:
        device_data_dict[addr] = [device_identification.MAC_address_lookup(addr), 0, 0, 0, 0, 0]
        time.sleep(2) # cannot do multiple fast API calls so need to wait a bit

    print("Collecting data....")
    # Collect data for the dictionary
    for ch in set(devices_chns):
        device_identification.collect_device_data(interface, ch, device_data_dict)


    print(device_data_dict)
    print(access_points)
    print(devices)


if __name__ == "__main__":
    main()