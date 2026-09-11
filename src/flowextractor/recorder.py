from scapy.all import *
import datetime
import argparse
import os
import subprocess
import sys
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class PacketRecorder:
    def __init__(self):
        self.packets = []

    def save_packets_to_file(self, file_path: str):
        if self.packets:
            wrpcap(file_path, self.packets, append=True)
            logger.info(f"Saved {len(self.packets)} packets to {file_path}")
            subprocess.run(["chmod", "777", file_path])
        else:
            logger.info("No packets to save.")

    def record(self, length: int):
        if length == None:
            logger.info("Recording packets indefinitely...")
            while True:
                self.packets = sniff(timeout=3)
                timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                self.save_packets_to_file(f"recorded_packets_{timestamp}.pcap")
        else:
            self.packets = sniff(timeout=length)
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            self.save_packets_to_file(f"recorded_packets_{timestamp}.pcap")


def main():
    if os.geteuid() != 0:
        logger.info("This script requires root privileges. Re-running with sudo...")
        subprocess.run(["sudo", ".venv/bin/python3", "-m", "src.flowextractor.recorder"] + sys.argv[1:])
        return
    arg_parser = argparse.ArgumentParser(description="Record packets for a specified duration.")
    arg_parser.add_argument("--record_length", type=int, help="Length of time to record packets in seconds")
    args = arg_parser.parse_args()

    recorder = PacketRecorder()
    recorder.record(length=args.record_length)

if __name__ == "__main__":
    main()