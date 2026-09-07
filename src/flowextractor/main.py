from scapy.utils import RawPcapReader

def read_pcap(file_path):
    packets = []
    for pkt_data, pkt_metadata in RawPcapReader(file_path):
        packets.append(pkt_data)
    return packets

def filter_ssh_packets(packets):
    ssh_packets = []
    for pkt in packets:
        if pkt.haslayer('TCP') and (pkt['TCP'].dport == 22 or pkt['TCP'].sport == 22):
            ssh_packets.append(pkt)
    return ssh_packets

def main():
    print("Hello from flowextractor!")


if __name__ == "__main__":
    main()
