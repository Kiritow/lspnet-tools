from typing import List
from .iptables import try_append_iptables_rule


def try_append_iptables_port_forward_udp(namespace, in_eth, src_port, dst_port):
    try_append_iptables_rule("nat", f"{namespace}-PREROUTING", ["-p", "udp", "-i", in_eth, "--dport", str(src_port), "-j", "DNAT", "--to-destination", f"127.0.0.1:{dst_port}"])
    try_append_iptables_rule("filter", f"{namespace}-FORWARD", ["-p", "udp", "--dport", str(src_port), "-j", "ACCEPT"])


def try_append_iptables_multiple_port_forward_udp(namespace, in_eth, src_ports: List[int], dst_port):
    sorted_src_ports = sorted(set([int(x) for x in src_ports]))
    
    begin_port = 0
    end_port = 0
    for port in sorted_src_ports:
        if not begin_port:
            begin_port = port
            end_port = port
            continue
        
        if port - end_port > 1:
            # not-continuous
            if end_port != begin_port:
                real_port = "{}:{}".format(begin_port, end_port)
            else:
                real_port = begin_port

            try_append_iptables_port_forward_udp(namespace, in_eth, real_port, dst_port)
            begin_port = port
            end_port = port
            continue

        # continous
        end_port = port

    if begin_port:
        if begin_port != end_port:
            real_port = "{}:{}".format(begin_port, end_port)
        else:
            real_port = begin_port
        
        try_append_iptables_port_forward_udp(namespace, in_eth, real_port, dst_port)
