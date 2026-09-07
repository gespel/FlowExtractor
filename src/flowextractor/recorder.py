from scapy.all import *
import datetime
import argparse

class PacketRecorder:
    def __init__(self):
        self.packets = []

    def save_packets_to_file(self, file_path: str):
        if self.packets:
            wrpcap(file_path, self.packets, append=True)
            print(f"Saved {len(self.packets)} packets to {file_path}")
        else:
            print("No packets to save.")

    def record(self, length: int):
        self.packets = sniff(timeout=length)
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.save_packets_to_file(f"recorded_packets_{timestamp}.pcap")

def main():
    arg_parser = argparse.ArgumentParser(description="Record packets for a specified duration.")
    arg_parser.add_argument("--record_length", type=int, default=120, help="Length of time to record packets in seconds (default: 120)")
    args = arg_parser.parse_args()

    recorder = PacketRecorder()
    recorder.record(length=args.record_length)

if __name__ == "__main__":
    main()