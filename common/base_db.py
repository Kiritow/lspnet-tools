import sqlite3
from contextlib import contextmanager
from typing import Any, Optional, Sequence
import logging


class BaseSQLiteTransaction:
    def __init__(self, conn: Optional[sqlite3.Connection] = None, logger: Optional[logging.Logger] = None) -> None:
        self.conn = conn
        self.logger = logger

    def commit(self, ignore_inner_commit: bool = False):
        if self.conn:
            self.logger.debug("commit") if self.logger else None
            self.conn.commit()
        elif not ignore_inner_commit:
            raise Exception("Cannot commit on inner transaction")


class BaseSQLiteDatabase:
    def __init__(self, filename: str, logger: Optional[logging.Logger] = None) -> None:
        self.conn = sqlite3.connect(filename, autocommit=False)
        self.conn.row_factory = sqlite3.Row
        self.cursor = self.conn.cursor()
        self.logger = logger
        self._flag_commit = True

    @contextmanager
    def begin(self):
        if self._flag_commit:
            self._flag_commit = False
            self.logger.debug("begin") if self.logger else None
            try:
                yield BaseSQLiteTransaction(self.conn, self.logger)
            finally:
                self.logger.debug("rollback") if self.logger else None
                self.conn.rollback()
                self._flag_commit = True
        else:
            # inner transaction
            yield BaseSQLiteTransaction(None, self.logger)

    def query(self, sql: str, params: Optional[Sequence[Any]] = None) -> list[sqlite3.Row]:
        with self.begin() as t:
            self.logger.debug(sql) if self.logger else None
            self.logger.debug(params) if self.logger and params else None
            self.cursor.execute(sql, params if params else ())
            result = self.cursor.fetchall()
            t.commit(True)
            return result

    def queryone(self, sql: str, params: Optional[Sequence[Any]] = None) -> sqlite3.Row | None:
        with self.begin() as t:
            self.logger.debug(sql) if self.logger else None
            self.logger.debug(params) if self.logger and params else None
            self.cursor.execute(sql, params if params else ())
            result = self.cursor.fetchone()
            t.commit(True)
            return result

    def execute(self, sql: str, params: Optional[Sequence[Any]] = None) -> int:
        with self.begin() as t:
            self.logger.debug(sql) if self.logger else None
            self.logger.debug(params) if self.logger and params else None
            self.cursor.execute(sql, params if params else ())
            t.commit(True)
            return self.cursor.rowcount

    def insert(self, table_name: str, data: dict[str, Any]) -> int:
        sql_fields = list(data.keys())
        sql_values = [data[k] for k in sql_fields]
        return self.execute("insert into {}({}) values ({})".format(table_name, ','.join(sql_fields), ','.join(['?'] * len(sql_fields))), sql_values)

    def insert_ignore(self, table_name: str, data: dict[str, Any]) -> int:
        sql_fields = list(data.keys())
        sql_values = [data[k] for k in sql_fields]
        return self.execute("insert into {}({}) values ({}) on conflict do nothing".format(table_name, ','.join(sql_fields), ','.join(['?'] * len(sql_fields))), sql_values)

    def upsert(self, table_name: str, data: dict[str, Any], update_fields: list[str]) -> int:
        sql_fields = list(data.keys())
        update_sql_fields = ["{}=?".format(f) for f in update_fields]

        sql_values = [data[k] for k in sql_fields] + [data[k] for k in update_fields]
        return self.execute("insert into {}({}) values ({}) on conflict do update set {}".format(table_name, ','.join(sql_fields), ','.join(['?'] * len(sql_fields)), ','.join(update_sql_fields)), sql_values)
