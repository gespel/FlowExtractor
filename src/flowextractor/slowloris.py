def label_slowloris_flows(flows, attacker_ip):
    for flow in flows:
        if flow.src_ip == attacker_ip or flow.dst_ip == attacker_ip:
            flow.label = "malicious"
            flow.attack_type = "slowloris_dos"
        else:
            flow.label = "benign"