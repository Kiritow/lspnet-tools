import os
from common.device import dump_wireguard_state
from common.key_manager import KeyManager
from common.ping import check_direct_ping, get_peer_ip


def get_wg_rxtx(network_namespace, device_name):
    interface_state = dump_wireguard_state(network_namespace, device_name)
    peer_public, peer_state = list(interface_state["peers"].items())[0]
    return peer_state['rx'], peer_state['tx']


if __name__ == "__main__":
    REPORT_DOMAIN = os.getenv('REPORT_DOMAIN')
    REPORT_TOKEN = os.getenv('REPORT_TOKEN')
    REPORT_INTERFACE = os.getenv('REPORT_INTERFACE')
    REPORT_INTERFACE_REAL = os.getenv('REPORT_INTERFACE_REAL')
    REPORT_IP = os.getenv('REPORT_IP') or ''
    REPORT_NAMESPACE = os.getenv('REPORT_NAMESPACE') or ''

    if not REPORT_DOMAIN or not REPORT_TOKEN or not REPORT_INTERFACE or not REPORT_INTERFACE_REAL:
        print('missing env vars')
        exit(1)

    if not REPORT_IP:
        REPORT_IP = get_peer_ip(REPORT_NAMESPACE, REPORT_INTERFACE_REAL)
        print('using REPORT_IP={}'.format(REPORT_IP))

    ping_us = check_direct_ping(REPORT_NAMESPACE, REPORT_IP)
    if ping_us < 0:
        ping_us = None

    rx, tx = get_wg_rxtx(REPORT_NAMESPACE, REPORT_INTERFACE_REAL)

    m = KeyManager(REPORT_DOMAIN, REPORT_TOKEN)
    m.report_stat(REPORT_INTERFACE, ping_us, rx, tx)
