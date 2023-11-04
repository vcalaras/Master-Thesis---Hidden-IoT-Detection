import requests


# This function uses the free macvendors API to identify the manufacturer of the mac address
def MAC_address_lookup(mac_address):
    url = f"https://api.macvendors.com/{mac_address}"

    try:
        response = requests.get(url)
        if response.status_code == 200:
            vendor = response.text
            return vendor
        else:
            return "Unknown"

    except Exception as e:
        print(f"An error occurred: {e}")

