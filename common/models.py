from pydantic import BaseModel
from typing import Optional

class RemoteConfigDummy(BaseModel):
    name: str
    addressCIDR: str
    mtu: int
    
    
class RemoteConfigOSPF(BaseModel):
    area: int = 0
    cost: int = 0
    auth: str = ''


class RemoteConfigNode(BaseModel):
    ip: str
    external: bool
    ddns: bool
    exitNode: bool
    vethCIDR: Optional[str] = None
    allowedTCPPorts: list[str]
    allowedUDPPorts: list[str]
    dummy: Optional[list[RemoteConfigDummy]] = None
    ospf: Optional[RemoteConfigOSPF] = None


class RemoteConfigPeers(BaseModel):
    id: int
    publicKey: str
    listenPort: int
    mtu: int
    addressCIDR: str
    peerPublicKey: str
    keepalive: int
    endpoint: str
    extra: str    


class RemoteConfigPeerExtraOSPF(BaseModel):
    cost: int
    ping: bool
    offset: int
    auth: Optional[str] = None


class LocalGostWorkerStore(BaseModel):
    unit_name: str
    multilisten: list[int]
    dst_port: int
