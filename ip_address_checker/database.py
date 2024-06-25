from typing import Tuple, Any

from database_util import BaseHandler


class DatabaseHandler(BaseHandler):
    def get_ip_details(self, ip_address: str) -> Tuple[Any, ...]:
        self.execute("SELECT * FROM ip_details WHERE ip_address = %s", (ip_address,))
        return self.fetchone()
