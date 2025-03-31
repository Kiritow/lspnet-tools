from dataclasses import dataclass


@dataclass
class WireGuardPeerState:
    preshared: str
    endpoint: str
    allow: str
    handshake: int
    rx: int
    tx: int
    keepalive: int


@dataclass
class WireGuardState:
    private: str
    public: str
    listen: int
    fwmark: int
    peers: dict[str, WireGuardPeerState]


@dataclass
class InterfaceState:
    name: str
    address: str
    mtu: int
