from typing import Any
from .base_db import BaseSQLiteDatabase


def init_config_store(db: BaseSQLiteDatabase):
    db.execute("create table if not exists nodeconfig (key, value, unique (key))", ())


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
