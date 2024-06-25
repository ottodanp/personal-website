from functools import wraps

from psycopg2 import connect
from psycopg2.extensions import cursor, connection


def commit_on_success(func):
    @wraps(func)
    def wrapper(self, *args, **kwargs):
        try:
            result = func(self, *args, **kwargs)
            self._conn.commit()
            return result
        except Exception as e:
            self._conn.rollback()
            raise e

    return wrapper


class BaseHandler(cursor):
    _conn: connection

    def __init__(self, dbname: str, user: str, password: str, host: str, port: str):
        self._conn = connect(database=dbname, user=user, password=password, host=host, port=port)
        super().__init__(self._conn)

    def __del__(self):
        self._conn.close()
        super().close()
