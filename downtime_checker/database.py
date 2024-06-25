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


class DatabaseHandler(cursor):
    _conn: connection

    def __init__(self, dbname: str, user: str, password: str, host: str, port: str):
        self._conn = connect(database=dbname, user=user, password=password, host=host, port=port)
        super().__init__(self._conn)

    def __del__(self):
        self._conn.close()
        super().close()

    @commit_on_success
    def insert_endpoint(self, url: str) -> None:
        self.execute("INSERT INTO endpoints (url) VALUES (%s)", (url,))

    @commit_on_success
    def insert_check_result(self, endpoint_id: int, status_code: int, response_time: float) -> None:
        self.execute("INSERT INTO check_results (endpoint_id, status_code, response_time) VALUES (%s, %s, %s)",
                     (endpoint_id, status_code, response_time))

    def get_average_response_time(self, endpoint_id: int) -> float:
        self.execute("SELECT AVG(response_time) FROM check_results WHERE endpoint_id = %s", (endpoint_id,))
        return self.fetchone()[0]
