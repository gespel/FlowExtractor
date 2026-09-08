from scapy.layers.inet import IP, TCP, UDP

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
            self.flow_table[flow_hash] = Flow()

        self.flow_table[flow_hash].add_packet(packet)

    def get_number_of_flows(self):
        return len(self.flow_table)

    def print_flow_table(self):
        for flow_hash, flow in self.flow_table.items():
            print(f"Flow Hash: {flow_hash:x}, Number of Packets: {flow.number_of_packets}")

class Flow:
    def __init__(self):
        self.number_of_packets = 0

    def add_packet(self, packet):
        self.number_of_packets += 1