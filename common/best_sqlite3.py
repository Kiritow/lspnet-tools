import importlib
import sys

sys.modules["_sqlite3"] = importlib.import_module("pysqlite3._sqlite3")
