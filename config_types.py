from dataclasses import dataclass
from typing import Union
from get_logger import get_logger


logger = get_logger('app')


@dataclass
class CommonOSPFConfig:
    area: int = 0
    cost: int = 0
    auth: str = ''
    type: str = ''


@dataclass
class ConnectorPhantunClientConfig:
    local: str
    remote: str
    tun_name: str
    tun_local: str
    tun_peer: str


@dataclass
class ConnectorPhantunServerConfig:
    local: str
    tun_name: str
    tun_local: str
    tun_peer: str
    remote: str = ''

    def dynamic_inject(self, interface_item: 'InterfaceConfig'):
        if self.remote == '#dynamic':
            self.remote = '127.0.0.1:{}'.format(interface_item.listen)
            logger.info('resolved dynamic config: {}'.format(self.remote))


@dataclass
class InterfaceConfig:
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
    autoconnect: bool = False
    enable_ospf: bool = False
    ospf_config: CommonOSPFConfig = None
    connector: Union[ConnectorPhantunClientConfig, ConnectorPhantunClientConfig] = None

    def validate(self):
        if self.autoconnect and not self.endpoint:
            logger.error('autoconnect cannot be enabled without endpoint specified!')
            return False
        return True