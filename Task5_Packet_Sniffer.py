from scapy.all import sniff, IP, TCP, UDP, ICMP

def packet_callback(packet):
    # Check if the packet has an IP layer
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto

        # Determine the protocol
        if proto == 6:  # TCP
            protocol = "TCP"
            payload = packet[TCP].payload
        elif proto == 17:  # UDP
            protocol = "UDP"
            payload = packet[UDP].payload
        elif proto == 1:  # ICMP
            protocol = "ICMP"
            payload = packet[ICMP].payload
        else:
            protocol = "Other"
            payload = packet[IP].payload

        # Print packet details
        print(f"Source IP: {ip_src} -> Destination IP: {ip_dst} | Protocol: {protocol}")

        # Print payload if available
        if payload:
            print(f"Payload: {payload}\n")

def start_sniffing(interface):
    print(f"Starting packet sniffing on interface: {interface}")
    sniff(iface=interface, prn=packet_callback, store=False)

if __name__ == "__main__":
    # Specify the correct network interface to sniff on (e.g., "Wi-Fi" or "Ethernet")
    interface = "Wi-Fi"  # Change this to your network interface name
    start_sniffing(interface)
