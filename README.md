import pcap
import dpkt

def packet_sniffer(interface, num_packets):
    """
    Sniffs network packets on the specified interface and displays relevant information.

    Parameters:
        interface (str): Name of the network interface to sniff packets from.
        num_packets (int): Number of packets to capture.

    Returns:
        None
    """
    # Open the network interface for sniffing
    pc = pcap.pcap(name=interface)
    pc.setnonblock(True)

    # Capture and analyze packets
    packet_count = 0
    for ts, pkt in pc:
        try:
            # Parse the packet
            eth = dpkt.ethernet.Ethernet(pkt)

            # Extract relevant information
            src_ip = dpkt.utils.inet_to_str(eth.src)
            dst_ip = dpkt.utils.inet_to_str(eth.dst)
            protocol = eth.data.__class__.__name__
            payload = eth.data.data

            # Display packet information
            print(f"Packet #{packet_count + 1}")
            print(f"Source IP: {src_ip}")
            print(f"Destination IP: {dst_ip}")
            print(f"Protocol: {protocol}")
            print(f"Payload: {payload.hex()}")  # Display payload data in hexadecimal format

            # Increment packet count
            packet_count += 1

            # Check if the desired number of packets has been captured
            if packet_count >= num_packets:
                break

        except Exception as e:
            print(f"Error processing packet: {e}")

    print("Packet sniffing complete.")

def main():
    # Network interface to sniff packets from (e.g., "eth0", "en0")
    interface = "eth0"
    
    # Number of packets to capture
    num_packets = 10
    
    # Start packet sniffing
    packet_sniffer(interface, num_packets)

if __name__ == "__main__":
    main()
