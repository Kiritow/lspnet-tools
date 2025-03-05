from base_db import BaseSQLiteDatabase
from models import WireGuardKeySchema, WireGuardPeerSchema


def init_config_store(db: BaseSQLiteDatabase):
    db.execute("create table if not exists wgkey (namespace, name, public_key, private_key, unique (namespace, name))", ())
    db.execute("create table if not exists wgpeer (namespace, name, public_key, is_static_key, endpoint, is_static_endpoint, unique (namespace, name))", ())


class ConfigStore:
    def __init__(self, filename: str):
        self.db = BaseSQLiteDatabase(filename)
        init_config_store(self.db)

    def get_wireguard_key(self, namespace: str, name: str):
        result = self.db.queryone("select * from wgkey where namespace = ? and name = ?", (namespace, name))
        if not result:
            return None
        return WireGuardKeySchema.model_validate((dict(result)))

    def save_wireguard_key(self, namespace: str, name: str, public_key: str, private_key: str):
        self.db.execute("replace into wgkey values (?, ?, ?, ?)", (namespace, name, public_key, private_key))

    def get_all_wg_peers(self, namespace: str):
        result = self.db.query("select * from wgpeer where namespace = ?", (namespace,))
        return [WireGuardPeerSchema.model_validate(dict(r)) for r in result]

    def get_wg_peer(self, namespace: str, name: str):
        result = self.db.queryone("select * from wgpeer where namespace = ? and name = ?", (namespace, name))
        if not result:
            return None
        return WireGuardPeerSchema.model_validate(dict(result))

    def save_wg_peer(self, namespace: str, name: str, public_key: str, is_static_key: int, endpoint: str, is_static_endpoint: int):
        self.db.execute("replace into wgpeer values (?, ?, ?, ?, ?, ?)", (namespace, name, public_key, is_static_key, endpoint, is_static_endpoint))
