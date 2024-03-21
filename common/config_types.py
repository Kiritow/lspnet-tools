import ipaddress
from dataclasses import dataclass
from typing import Union, List

from .get_logger import get_logger


logger = get_logger('app')


@dataclass
class NamespaceConnectConfig:
    namespace: str
    network: str


@dataclass
class DummyInterfaceConfig:
    name: str
    address: str
    mtu: int
    
    def get_first_address(self):
        vnetwork = ipaddress.ip_network(self.address)
        vaddrs = list(vnetwork.hosts())
        return str(vaddrs[0])


@dataclass
class CommonOSPFConfig:
    area: int = 0
    cost: int = 0
    auth: str = ''
    type: str = ''
    pingcost: int = 0


@dataclass
class BFDConfig:
    intervalMs: int = 0
    txMs: int = 0
    rxMs: int = 0
    idleMs: int = 0
    multiplier: int = 0


@dataclass
class ConnectorPhantunClientConfig:
    local_address: str
    local_port: int
    remote: str
    tun_name: str
    tun_local: str
    tun_peer: str


@dataclass
class ConnectorPhantunServerConfig:
    local: int
    tun_name: str
    tun_local: str
    tun_peer: str
    remote: str = ''

    def dynamic_inject(self, interface_item: 'InterfaceConfig'):
        if self.remote == '#dynamic':
            self.remote = '127.0.0.1:{}'.format(interface_item.listen)
            logger.info('resolved dynamic config: {}'.format(self.remote))


@dataclass
class ForwarderConfig:
    type: str
    ports: List[int] = None


@dataclass
class NetworkMappingConfig:
    from_addr: str
    to_addr: str
    queue_number: int
    queue_size: int


@dataclass
class InterfaceConfig:
    short_name: str = ''
    name: str = ''
    private: str = ''
    public: str = ''
    mtu: int = 0
    address: str = ''
    listen: int = 0
    peer: str = ''
    allowed: str = ''
    endpoint: str = ''
    keepalive: int = 0
    autorefresh: bool = False  # DDNS
    enable_ospf: bool = False
    ospf_config: CommonOSPFConfig = None
    enable_bfd: bool = False
    bfd_config: BFDConfig = None
    enable_report: bool = False
    multiports: List[int] = None
    connector: Union[ConnectorPhantunClientConfig, ConnectorPhantunClientConfig] = None
    forwarders: List[ForwarderConfig] = None  # Experimental

    def validate(self):
        if self.autorefresh and not self.endpoint:
            logger.error('autorefresh cannot be enabled without endpoint specified!')
            return False
        if not self.address:
            logger.error('interface address should not be empty!')
            return False
        return True


@dataclass
class ParserOptions:
    online_mode: bool = True
    use_cache: bool = False
    save_cache: bool = False
    skip_error_validate: bool = False
    skip_bird: bool = False
