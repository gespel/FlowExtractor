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
            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            layer_4 = packet[TCP] if packet.haslayer(TCP) else packet[UDP]
            dst_port = layer_4.dport
            src_port = layer_4.sport
            self.flow_table[flow_hash] = Flow(src_ip, dst_ip, src_port, dst_port)

        self.flow_table[flow_hash].add_packet(packet)

    def get_number_of_flows(self):
        return len(self.flow_table)

    def print_flow_table(self):
        for flow_hash, flow in self.flow_table.items():
            print(f"=============\nFlow Hash: {flow_hash:x}"
                  f"\n\tNumber of Packets: {flow.number_of_packets}"
                  f"\n\tSource IP: {flow.src_ip}"
                  f"\n\tDestination IP: {flow.dst_ip}"
                  f"\n\tSource Port: {flow.src_port}"
                  f"\n\tDestination Port: {flow.dst_port}\n")

class Flow:
    def __init__(self, src_ip=None, dst_ip=None, src_port=None, dst_port=None):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.number_of_packets = 0

    def add_packet(self, packet):
        self.number_of_packets += 1