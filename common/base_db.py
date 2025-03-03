import sqlite3
from contextlib import contextmanager
from typing import Any, Sequence


class BaseConfigStore:
    def __init__(self, filename: str) -> None:
        self.conn = sqlite3.connect(filename, autocommit=False)
        self.conn.row_factory = sqlite3.Row
        self.cursor = self.conn.cursor()
        self._flag_commit = True

    def __enter__(self):
        if not self._flag_commit:
            raise RuntimeError('nested with statement is not allowed')

        self._flag_commit = False
        return self

    def __exit__(self, exc_type, exc_val, exc_tb): # type: ignore
        if exc_type is None and exc_val is None and exc_tb is None:
            self.conn.commit()
        else:
            self.conn.rollback()
        self._flag_commit = True
    
    @contextmanager
    def _begin(self):
        if self._flag_commit:
            # out most with statement
            with self:
                yield self
        else:
            # inner with statement
            yield self

    def query(self, sql: str, params: Sequence[Any]) -> list[sqlite3.Row]:
        with self._begin():
            self.cursor.execute(sql, params)
            return self.cursor.fetchall()

    def queryone(self, sql: str, params: Sequence[Any]) -> sqlite3.Row | None:
        with self._begin():
            self.cursor.execute(sql, params)
            return self.cursor.fetchone()

    def execute(self, sql: str, params: Sequence[Any]) -> None:
        with self._begin():
            self.cursor.execute(sql, params)
