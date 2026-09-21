import datetime
import json
import re
import subprocess

BENIGN, MALICIOUS, UNKNOWN, NOT_APPLICABLE = "benign", "malicious", "unknown", "n/a"
FAIL_THRESHOLD = 3

_FAILED_RE = re.compile(r"Failed password for.* from (\S+)")
_ACCEPTED_RE = re.compile(r"Accepted \w+ for.* from (\S+)")


def _sshd_auth_stats(since, until):
    cmd = ["journalctl", "-u", "sshd", "-o", "json",
           "--since", since.strftime("%Y-%m-%d %H:%M:%S"),
           "--until", until.strftime("%Y-%m-%d %H:%M:%S")]
    try:
        output = subprocess.run(cmd, capture_output=True, text=True, timeout=10, check=True).stdout
    except (subprocess.SubprocessError, OSError):
        return {}

    stats = {}
    for line in output.splitlines():
        message = json.loads(line).get("MESSAGE") if line.strip() else None
        if not isinstance(message, str):
            continue
        if match := _FAILED_RE.search(message):
            stats.setdefault(match.group(1), [0, False])[0] += 1
        elif match := _ACCEPTED_RE.search(message):
            stats.setdefault(match.group(1), [0, False])[1] = True
    return stats


def label_ssh_flows(flows, padding_seconds=5):
    ssh_flows = [f for f in flows if 22 in (f.src_port, f.dst_port) and f.first_packet_time]
    if not ssh_flows:
        return

    since = datetime.datetime.fromtimestamp(min(f.first_packet_time for f in ssh_flows) - padding_seconds)
    until = datetime.datetime.fromtimestamp(max(f.last_seen_time for f in ssh_flows) + padding_seconds)
    stats = _sshd_auth_stats(since, until)

    for flow in ssh_flows:
        peer_ip = flow.src_ip if flow.dst_port == 22 else flow.dst_ip
        failed, accepted = stats.get(peer_ip, (0, False))
        if accepted and failed < FAIL_THRESHOLD and flow.label != MALICIOUS:
            flow.label = BENIGN
        elif failed >= FAIL_THRESHOLD or (failed and not accepted):
            flow.label = MALICIOUS
            flow.attack_type = "ssh_brute_force"
        elif flow.label != MALICIOUS:
            flow.label = UNKNOWN
