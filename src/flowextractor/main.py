from scapy.utils import RawPcapReader

def read_pcap(file_path):
    packets = []
    for pkt_data, pkt_metadata in RawPcapReader(file_path):
        packets.append(pkt_data)
    return packets

def main():
    print("Hello from flowextractor!")


if __name__ == "__main__":
    main()
