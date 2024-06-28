from typing import Tuple, Any

from database_util import BaseHandler


class IpNotFound(Exception):
    def __init__(self):
        super().__init__("IP address not found in database")


class DatabaseHandler(BaseHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_ip_details(self, ip_address: str) -> Tuple[Any, ...]:
        self.execute("SELECT actor_id FROM actors WHERE host = %s", (ip_address,))
        result = self.fetchone()
        if not result or len(result) == 0:
            raise IpNotFound()
        host_id = result[0]
        self.execute("SELECT count(*) FROM requests WHERE actor_id = %s", (host_id,))
        result = self.fetchone()
        if not result or len(result) == 0:
            raise IpNotFound()
        request_count = result[0]
        return host_id, ip_address, request_count
