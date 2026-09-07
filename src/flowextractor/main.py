from scapy.utils import RawPcapReader
import argparse

def read_pcap(file_path):
    packets = []
    for pkt_data, pkt_metadata in RawPcapReader(file_path):
        packets.append(pkt_data)
    return packets

def filter_ssh_packets(packets):
    ssh_packets = []
    for pkt in packets:
        if pkt['TCP'].dport == 22 or pkt['TCP'].sport == 22:
            ssh_packets.append(pkt)
    return ssh_packets

def main():
    arg_parser = argparse.ArgumentParser(description="Extract flows from a pcap file and record packets.")
    arg_parser.add_argument("pcap_file", type=str, help="Path to the pcap file to read")

    args = arg_parser.parse_args()

    packets = read_pcap(args.pcap_file)
    ssh_packets = filter_ssh_packets(packets)
    print(f"Total packets read: {len(packets)}")
    print(f"SSH packets found: {len(ssh_packets)}")

if __name__ == "__main__":
    main()
