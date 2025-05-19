from scapy.all import sniff, Dot11, Dot11Beacon, Dot11ProbeResp, Dot11Elt, Dot11Auth
from scapy.layers.eap import EAPOL
from scapy.layers.dot11 import RadioTap  # Ensure RadioTap is imported if used

def packet_handler(pkt):
    if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
        ssid = "N/A"
        for element in pkt.getlayer(Dot11Elt, ID=0):
            ssid = element.info.decode(errors='ignore')
            break

        bssid = pkt[Dot11].addr2
        channel = "N/A"
        if pkt.haslayer(RadioTap):
            channel = pkt[RadioTap].ChannelFrequency
        elif 'ChannelFrequency' in pkt:
            channel = pkt.ChannelFrequency

        security = "Open"
        if pkt.haslayer(Dot11Auth):
            security = "WEP?"
        elif pkt.haslayer(EAPOL): # Check for EAPOL layer, common in WPA/WPA2
            security = "WPA/WPA2?" # Further analysis needed within EAPOL
        elif pkt.haslayer('RSN') or pkt.haslayer('WPA2'): # Look for RSN or WPA2 layers
            security = "WPA/WPA2"
        elif pkt.haslayer('WPA3'):
            security = "WPA3"

        print(f"SSID: {ssid}, BSSID: {bssid}, Channel: {channel}, Security: {security}")

try:
    sniff(iface="wlan0mon", prn=packet_handler, timeout=10, store=0)
except PermissionError:
    print("Error: You need root privileges to run this script.")
except OSError as e:
    print(f"Error: Could not open interface wlan0mon. Make sure it's in monitor mode. ({e})")
except Exception as e:
    print(f"An unexpected error occurred: {e}")