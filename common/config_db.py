import time
from typing import Any, Optional
from .base_db import BaseSQLiteDatabase


def init_config_store(db: BaseSQLiteDatabase):
    db.execute("create table if not exists nodeconfig (key, value, unique (key))", ())
    db.execute("create table if not exists simplekv (key, value, expires, unique (key))", ())
    db.execute("create table if not exists wgkey (private, public, unique (public))", ())


class ConfigStore:
    def __init__(self, filename: str):
        self.db = BaseSQLiteDatabase(filename)
        init_config_store(self.db)
        
    def get_node_config(self, key: str):
        result = self.db.queryone("select value from nodeconfig where key=?", (key,))
        if result:
            return result[0]
        return None
    
    def set_node_config(self, key: str, value: Any):
        self.db.upsert("nodeconfig", {"key": key, "value": value}, ["value"])
    
    def get_kv(self, key: str):
        result = self.db.queryone("select value, expires from simplekv where key=?", (key,))
        if not result:
            return None
        if result[1] and isinstance(result[1], int) and result[1] > time.time():
            # expired. delete
            self.db.execute("delete from simplekv where key=?", (key,))
            return None
        return result[0]

    def set_kv(self, key: str, value: Any, ttl: Optional[int] = None):
        if ttl:
            expires = int(time.time() + ttl)
            self.db.upsert("simplekv", {"key": key, "value": value, "expires": expires}, ["value", "expires"])
        else:
            self.db.upsert("simplekv", {"key": key, "value": value, "expires": None}, ["value", "expires"])

    def delete_kv(self, key: str):
        self.db.execute("delete from simplekv where key=?", (key,))

    def create_wg_key(self, private: str, public: str):
        self.db.insert("wgkey", {"private": private, "public": public})

    def get_all_wg_keys(self) -> list[tuple[str, str]]:
        result = self.db.query("select * from wgkey", ())
        return [(row['private'], row['public']) for row in result]
