from typing import List
from .utils import ports_to_segments
from .iptables import try_append_iptables_rule


def try_append_iptables_port_forward_udp(namespace, in_eth, src_port, dst_port):
    try_append_iptables_rule("nat", f"{namespace}-PREROUTING", ["-p", "udp", "-i", in_eth, "--dport", str(src_port), "-j", "DNAT", "--to-destination", f"127.0.0.1:{dst_port}"])
    try_append_iptables_rule("filter", f"{namespace}-FORWARD", ["-p", "udp", "--dport", str(src_port), "-j", "ACCEPT"])


def try_append_iptables_multiple_port_forward_udp(namespace, in_eth, src_ports: List[int], dst_port):
    port_segs = ports_to_segments(src_ports)

    for seg in port_segs:
        begin_port, end_port = seg
        if end_port != begin_port:
            real_port = "{}:{}".format(begin_port, end_port)
        else:
            real_port = begin_port

        try_append_iptables_port_forward_udp(namespace, in_eth, real_port, dst_port)
