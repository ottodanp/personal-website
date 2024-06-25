from typing import Tuple, Any

from database_util import BaseHandler


class DatabaseHandler(BaseHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_ip_details(self, ip_address: str) -> Tuple[Any, ...]:
        self.execute("SELECT * FROM actors WHERE host = %s", (ip_address,))
        host_id = self.fetchone()[0]
        self.execute("SELECT count(*) FROM requests WHERE actor_id = %s", (host_id,))
        request_count = self.fetchone()[0]
        return host_id, ip_address, request_count
