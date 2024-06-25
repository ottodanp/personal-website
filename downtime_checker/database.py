from database_util import BaseHandler, commit_on_success


class DatabaseHandler(BaseHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

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
