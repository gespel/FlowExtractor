from scapy.layers.inet import IP, TCP, UDP
import pandas as pd

def calculate_packet_hash(packet):
    if not packet.haslayer(IP) or (not packet.haslayer(TCP) and not packet.haslayer(UDP)):
        print("Packet does not have the required layers (IP, TCP/UDP). Skipping hash calculation.")
        return None

    ip_layer = packet[IP]
    layer_4 = packet[TCP] if packet.haslayer(TCP) else packet[UDP]

    src_ip = ip_layer.src
    dst_ip = ip_layer.dst
    #src_port = layer_4.sport
    dst_port = layer_4.dport

    flow_string = f"{src_ip}{dst_ip}{dst_port}"
    hash_value = hash(flow_string)

    return hash_value

class FlowTableManager:
    def __init__(self):
        self.flow_table = {}

    def add_packet(self, packet):
        flow_hash = calculate_packet_hash(packet)
        if flow_hash is None:
            return

        if flow_hash not in self.flow_table:
            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            layer_4 = packet[TCP] if packet.haslayer(TCP) else packet[UDP]
            dst_port = layer_4.dport
            src_port = layer_4.sport
            self.flow_table[flow_hash] = Flow(flow_hash, src_ip, dst_ip, src_port, dst_port)

        self.flow_table[flow_hash].add_packet(packet)

    def add_packets(self, packets):
        for packet in packets:
            self.add_packet(packet)

    def get_number_of_flows(self):
        return len(self.flow_table)

    def print_flow_table(self):
        nr_single_packet_flows = 0
        for flow_hash, flow in self.flow_table.items():
            if flow.number_of_packets > 1:
                print(f"=============\nFlow Hash: {flow_hash:x}"
                    f"\n\tNumber of Packets: {flow.number_of_packets}"
                    f"\n\tSource IP: {flow.src_ip}"
                    f"\n\tDestination IP: {flow.dst_ip}"
                    f"\n\tSource Port: {flow.src_port}"
                    f"\n\tDestination Port: {flow.dst_port}"
                    f"\n\tAverage Packet Size: {flow.avg_packet_size:.2f} bytes"
                    f"\n\tMinimum Packet Size: {flow.min_packet_size} bytes"
                    f"\n\tMaximum Packet Size: {flow.max_packet_size} bytes"
                    f"\n\tTotal Bytes: {flow.total_bytes} bytes"
                    f"\n\tInter-Arrival Time (IAT) Min: {flow.iat_min:.6f} seconds"
                    f"\n\tInter-Arrival Time (IAT) Max: {flow.iat_max:.6f} seconds"
                    f"\n\tInter-Arrival Time (IAT) Mean: {flow.iat_mean:.6f} seconds")
            else:
                nr_single_packet_flows += 1
        print(f"Number of single-packet flows: {nr_single_packet_flows}")

    def print_flow_table_summary(self):
        total_flows = len(self.flow_table)
        single_packet_flows = sum(1 for flow in self.flow_table.values() if flow.number_of_packets == 1)
        multi_packet_flows = total_flows - single_packet_flows
        ssh_flows = [flow for flow in self.flow_table.values() if (flow.dst_port == 22 or flow.src_port == 22)]
        print(f"Total number of flows: {total_flows}")
        print(f"Number of single-packet flows: {single_packet_flows}")
        print(f"Number of multi-packet flows: {multi_packet_flows}")
        print(f"Number of SSH flows: {len(ssh_flows)}")
        for flow in ssh_flows:
            print(f"\tSSH Flow Hash: {flow.flow_hash:x} - Source IP: {flow.src_ip}, Destination IP: {flow.dst_ip}, Source Port: {flow.src_port}, Destination Port: {flow.dst_port}")

    def write_flow_vectors_to_csv(self, file_path):
        flow_vectors = []
        for flow_hash, flow in self.flow_table.items():
            if flow.number_of_packets > 1:
                feature_vector = flow.build_feature_vector()
                flow_vectors.append([flow_hash] + feature_vector)

        df = pd.DataFrame(flow_vectors, columns=[
            "Flow Hash",
            "Source IP",
            "Destination IP",
            "Source Port",
            "Destination Port",
            "Number of Packets",
            "Average Packet Size",
            "Minimum Packet Size",
            "Maximum Packet Size",
            "Total Bytes",
            "IAT Min",
            "IAT Max",
            "IAT Mean"
        ])
        df.to_csv(file_path, index=False)
        print(f"Flow vectors written to {file_path}")

class Flow:
    def __init__(self, flow_hash=None, src_ip=None, dst_ip=None, src_port=None, dst_port=None):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.number_of_packets = 0
        self.avg_packet_size = 0
        self.min_packet_size = float('inf')
        self.max_packet_size = 0
        self.total_bytes = 0
        self.iat_min = float('inf')
        self.iat_max = 0
        self.iat_mean = 0
        self.flow_hash = flow_hash
        self.last_packet_time = None

    def add_packet(self, packet):
        self.number_of_packets += 1

        packet_size = len(packet)
        self.total_bytes += packet_size
        self.avg_packet_size = self.total_bytes / self.number_of_packets
        self.min_packet_size = min(self.min_packet_size, packet_size)
        self.max_packet_size = max(self.max_packet_size, packet_size)

        if self.last_packet_time is not None:
            iat = packet.time - self.last_packet_time
            self.iat_min = min(self.iat_min, iat)
            self.iat_max = max(self.iat_max, iat)
            if self.number_of_packets > 2:
                self.iat_mean = ((self.iat_mean * (self.number_of_packets - 1)) + iat) / self.number_of_packets
            else:
                self.iat_mean = iat
        else:
            self.iat_min = float('inf')
            self.iat_max = 0
            self.iat_mean = 0
            self.last_packet_time = packet.time

    def build_feature_vector(self):
        out_vector = [
            self.src_ip,
            self.dst_ip,
            self.src_port,
            self.dst_port,
            self.number_of_packets,
            self.avg_packet_size,
            self.min_packet_size,
            self.max_packet_size,
            self.total_bytes,
            self.iat_min if self.iat_min != float('inf') else 0,
            self.iat_max,
            self.iat_mean
        ]
        return out_vector
