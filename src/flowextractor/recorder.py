from scapy.all import sniff, Packet
import datetime

class PacketRecorder:
    def __init__(self):
        self.packets = []

    def save_packets_to_file(self, file_path: str):
        if self.packets:
            wrpcap(file_path, self.packets, append=True)
            print(f"Saved {len(self.packets)} packets to {file_path}")
        else:
            print("No packets to save.")

    def record(self, length: int = 120):
        self.packets = sniff(count=length)
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.save_packets_to_file(f"recorded_packets_{timestamp}.pcap")