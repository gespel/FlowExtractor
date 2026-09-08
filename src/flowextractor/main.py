from scapy.utils import PcapReader
from scapy.layers.inet import IP, TCP, UDP
import argparse
from flowextractor.flow import FlowTableManager

def read_pcap(file_path):
    with PcapReader(file_path) as reader:
        return list(reader)

def filter_ssh_packets(packets):
    ssh_packets = []
    for pkt in packets:
        if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
            continue

        tcp = pkt[TCP]
        if tcp.sport == 22 or tcp.dport == 22:
            ssh_packets.append(pkt)
    return ssh_packets

def main():
    arg_parser = argparse.ArgumentParser(description="Extract flows from a pcap file and record packets.")
    arg_parser.add_argument("pcap_file", type=str, help="Path to the pcap file to read")

    args = arg_parser.parse_args()

    packets = read_pcap(args.pcap_file)

    flow_manager = FlowTableManager()
    for pkt in packets:
        flow_manager.add_packet(pkt)

    print(f"Total packets read: {len(packets)}")
    print(f"Total flows identified: {flow_manager.get_number_of_flows()}")
    flow_manager.print_flow_table()

if __name__ == "__main__":
    main()
