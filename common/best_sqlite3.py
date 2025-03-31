import sys
from pysqlite3 import dbapi2 as sqlite3

sys.modules["sqlite3"] = sqlite3
