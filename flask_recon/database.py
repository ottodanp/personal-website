from datetime import datetime
from hashlib import sha256
from json import dumps, loads
from typing import Optional, List, Tuple, Dict, Union, Any
from uuid import uuid4

from database_util import BaseHandler, commit_on_success
from flask_recon.structures import IncomingRequest, RemoteHost, RequestMethod


class DatabaseHandler(BaseHandler):
    def actor_exists(self, remote_host: RemoteHost) -> bool:
        self.execute("SELECT EXISTS(SELECT actor_id FROM actors WHERE host = %s)", (remote_host.address,))
        return self.fetchone()[0]

    @commit_on_success
    def insert_actor(self, remote_host: RemoteHost, flagged: bool = False) -> None:
        self.execute("INSERT INTO actors (host, flagged) VALUES (%s, %s)", (remote_host.address, flagged,))

    def get_actor_average_threat_level(self, actor_id: int) -> int:
        self.execute("SELECT threat_level FROM requests WHERE actor_id = %s", (actor_id,))
        result = self.fetchall()
        if not result:
            return 0
        levels = [row[0] for row in result]
        return sum(levels) // len(levels) if levels else 0

    def get_actor_id(self, remote_host: RemoteHost) -> int:
        self.execute("SELECT actor_id FROM actors WHERE host = %s", (remote_host.address,))
        result = self.fetchone()
        if not result:
            return -1
        return result[0]

    def address_is_authorised(self, remote_host: RemoteHost) -> bool:
        self.execute("SELECT address FROM authorized_addresses WHERE host = %s", (remote_host.address,))
        return True if self.fetchone() else False

    @commit_on_success
    def update_request_threat_level(self, request_id: int, threat_level: int) -> None:
        self.execute("UPDATE requests SET threat_level = %s WHERE request_id = %s", (threat_level, request_id))

    @commit_on_success
    def update_actor_threat_level(self, actor_id: int) -> None:
        threat_level = self.get_actor_average_threat_level(actor_id)
        self.execute("UPDATE actors SET threat_level = %s WHERE actor_id = %s", (threat_level, actor_id))

    @commit_on_success
    def insert_request(self, request: IncomingRequest) -> None:
        if not self.actor_exists(request.host):
            self.insert_actor(request.host)

        request.determine_threat_level()
        actor_id = self.get_actor_id(request.host)
        self.execute("SELECT NOW()")
        timestamp = self.fetchone()[0]
        # using a parameterized query automatically escapes the input and prevents SQL injection
        self.execute(
            "INSERT INTO requests (actor_id, timestamp, method, path, body, headers, query_string, port, acceptable, threat_level) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
            (actor_id, timestamp, request.method.value, request.uri, dumps(request.body),
             dumps(request.headers), request.query_string, request.local_port, request.is_acceptable,
             request.threat_level))

    def get_request(self, request_id: int) -> Optional[IncomingRequest]:
        self.execute("SELECT * FROM requests WHERE request_id = %s", (request_id,))
        row = self.fetchone()
        if row is None:
            return

        self.execute("SELECT host FROM actors WHERE actor_id = %s", (row[1],))
        result = self.fetchone()
        if not result:
            return IncomingRequest(row[8]).from_components(
                host="Unknown",
                timestamp=row[0],
                request_method=RequestMethod.GET,
                request_body={},
                request_headers={},
                query_string="",
                request_uri="",
                request_id=-1,
                threat_level=0,
            )
        host = RemoteHost(result[0])
        return IncomingRequest(row[6]).from_components(
            host=host.address,
            timestamp=row[2],
            request_method=row[3],
            request_body=loads(row[5]),
            request_headers=loads(row[6]),
            query_string=row[7],
            request_uri=row[4],
            request_id=row[0],
            threat_level=row[10],
        )

    def get_honeypot(self, file: str) -> Optional[str]:
        self.execute("SELECT dummy_contents FROM honeypots WHERE file_name = %s", (file,))
        return self.fetchone()[0] if self.rowcount > 0 else None

    def honeypot_exists(self, file: str) -> bool:
        self.execute("SELECT EXISTS(SELECT honeypot_id FROM honeypots WHERE file_name = %s)", (file,))
        return self.fetchone()[0]

    @commit_on_success
    def insert_honeypot(self, file: str, contents: str) -> None:
        if self.honeypot_exists(file):
            return

        self.execute("INSERT INTO honeypots (file_name, dummy_contents) VALUES (%s, %s)", (file, contents))

    def count_endpoint(self, endpoint: str) -> int:
        self.execute("SELECT COUNT(*) FROM requests WHERE path = %s", (endpoint,))
        return self.fetchone()[0]

    def count_requests(self, host: RemoteHost) -> Tuple[int, int]:
        actor_id = self.get_actor_id(host)
        self.execute("SELECT COUNT(*) FROM requests WHERE actor_id = %s AND acceptable = TRUE", (actor_id,))
        valid = self.fetchone()[0]
        self.execute("SELECT COUNT(*) FROM requests WHERE actor_id = %s AND acceptable = FALSE", (actor_id,))
        invalid = self.fetchone()[0]
        return valid, invalid

    def get_all_endpoints(self) -> List[Tuple[str, int]]:
        self.execute("SELECT path FROM requests")
        r = []
        e = set()
        for row in self.fetchall():
            endpoint = row[0]
            if endpoint in e:
                continue
            e.add(endpoint)
            r.append((endpoint, self.count_endpoint(endpoint)))
        return sorted(r, key=lambda x: x[1], reverse=True)

    def count_requests_from_actor(self, actor_id: str, endpoint: str) -> int:
        self.execute("SELECT COUNT(*) FROM requests WHERE actor_id = %s AND path = %s", (actor_id, endpoint))
        return self.fetchone()[0]

    def get_hosts_by_endpoint(self, endpoint: str) -> List[Tuple[Dict[str, Union[str, int]], int]]:
        self.execute("SELECT actor_id FROM requests WHERE path = %s", (endpoint,))
        actors = self.fetchall()
        e = set()
        r = []
        for row in actors:
            self.execute("SELECT host, threat_level FROM actors WHERE actor_id = %s", (row[0],))
            host, threat_level = self.fetchone()
            if host in e:
                continue
            e.add(host)
            r.append(
                ({"address": host, "threat_level": threat_level}, self.count_requests_from_actor(row[0], endpoint)))
        return sorted(r, key=lambda x: x[1], reverse=True)

    def get_remote_hosts(self) -> List[Tuple[str, int, int, int, int]]:
        self.execute("SELECT actor_id, host, threat_level FROM actors")
        r = []
        for row in self.fetchall():
            host = RemoteHost(row[1])
            threat_level = self.get_actor_average_threat_level(row[0])
            valid, invalid = self.count_requests(host)
            total = valid + invalid
            r.append((host.address, valid, invalid, total, threat_level))
        return sorted(r, key=lambda x: x[3], reverse=True)

    def get_requests(self, endpoint: Optional[str] = None, host: Optional[RemoteHost] = None) -> List[IncomingRequest]:
        if host is None and endpoint is None:
            self.execute(
                "SELECT actor_id, timestamp, method, body, headers, query_string, port, acceptable, path, request_id FROM requests")
        if host is None and endpoint is not None:
            self.execute(
                "SELECT actor_id, timestamp, method, body, headers, query_string, port, acceptable, path, request_id FROM requests WHERE path = %s",
                (endpoint,))
        if host is not None and endpoint is None:
            self.execute(
                "SELECT actor_id, timestamp, method, body, headers, query_string, port, acceptable, path, request_id FROM requests WHERE actor_id = %s",
                (self.get_actor_id(host),))
        if host is not None and endpoint is not None:
            self.execute(
                "SELECT actor_id, timestamp, method, body, headers, query_string, port, acceptable, path, request_id FROM requests WHERE path = %s AND actor_id = %s",
                (endpoint, self.get_actor_id(host)))

        requests = self.fetchall()
        r = []
        for row in requests:
            if host is None:
                self.execute("SELECT host FROM actors WHERE actor_id = %s", (row[0],))
                host = RemoteHost(self.fetchone()[0])
            incoming_request = IncomingRequest(row[6]).from_components(
                host=host.address,
                timestamp=row[1],
                request_method=row[2],
                request_body=loads(row[3]),
                request_headers=loads(row[4]),
                query_string=row[5],
                request_uri=row[8],
                request_id=row[-1],
                threat_level=row[7],
            )
            incoming_request.determine_threat_level()
            r.append(incoming_request)
        return sorted(r, key=lambda x: x.timestamp, reverse=True)

    def connect_target_exists(self, url: str) -> bool:
        self.execute("SELECT EXISTS(SELECT connect_target_id FROM connect_targets WHERE url = %s)", (url,))
        return self.fetchone()[0]

    @commit_on_success
    def insert_connect_target(self, url: str, body: str) -> None:
        if self.connect_target_exists(url):
            return

        self.execute("INSERT INTO connect_targets (url, body) VALUES (%s, %s)", (url, body))

    def get_connect_target(self, url: str) -> str:
        self.execute("SELECT body FROM connect_targets WHERE url = %s", (url,))
        return self.fetchone()[0]

    def search(self, actor_id: Optional[int] = None,
               uri: Optional[str] = None,
               method: Optional[str] = None,
               threat_level: Optional[int] = None,
               acceptable: Optional[bool] = None,
               host: Optional[str] = None,
               headers: Optional[str] = None,
               query_string: Optional[str] = None,
               body: Optional[str] = None,
               all_must_match: bool = False,
               case_sensitive: bool = False,
               ) -> List[IncomingRequest]:
        query = ("SELECT actor_id, timestamp, method, body, headers, query_string, port, acceptable, path, request_id "
                 "FROM requests")
        conditions = []
        variables = []
        if actor_id:
            conditions.append("actor_id = %s")
            variables.append(actor_id)
        if uri:
            conditions.append(f"path {'LIKE' if case_sensitive else 'ILIKE'} %s")
            variables.append(f"%{uri}%")
        if method:
            conditions.append(f"method {'LIKE' if case_sensitive else 'ILIKE'} %s")
            variables.append(f"%{method}%")
        if threat_level:
            conditions.append("threat_level = %s")
            variables.append(threat_level)
        if acceptable is not None:
            conditions.append("acceptable = %s")
            variables.append(acceptable)
        if host:
            conditions.append(
                f"actor_id IN (SELECT actor_id FROM actors WHERE host {'LIKE' if not case_sensitive else 'ILIKE'} %s)")
            variables.append(f"%{host}%")
        if headers:
            conditions.append(f"headers {'LIKE' if case_sensitive else 'ILIKE'} %s")
            variables.append(f"%{headers}%")
        if query_string:
            conditions.append(f"query_string {'LIKE' if case_sensitive else 'ILIKE'} %s")
            variables.append(f"%{query_string}%")
        if body:
            conditions.append(f"body {'LIKE' if case_sensitive else 'ILIKE'} %s")
            variables.append(f"%{body}%")

        if conditions:
            separator = " AND " if all_must_match else " OR "
            query += " WHERE " + separator.join(conditions)

        self.execute(query, variables)
        requests = self.fetchall()
        r = []
        for row in requests:
            self.execute("SELECT host FROM actors WHERE actor_id = %s", (row[0],))
            host = RemoteHost(self.fetchone()[0])
            incoming_request = (IncomingRequest(row[6])
            .from_components(
                request_method=row[2], request_body=loads(row[3]), threat_level=row[7], request_headers=loads(row[4]),
                timestamp=row[1], query_string=row[5], request_uri=row[8], request_id=row[-1], host=host.address)
            )
            incoming_request.determine_threat_level()
            r.append(incoming_request)
        return sorted(r, key=lambda x: x.timestamp, reverse=True)

    # stats
    def get_request_count(self) -> int:
        self.execute("SELECT COUNT(request_id) FROM requests")
        return self.fetchone()[0]

    def get_actor_count(self) -> int:
        self.execute("SELECT COUNT(actor_id) FROM actors")
        return self.fetchone()[0]

    def get_endpoint_count(self) -> int:
        self.execute("SELECT COUNT(DISTINCT path) FROM requests")
        return self.fetchone()[0]

    def get_last_request_time(self) -> datetime:
        self.execute("SELECT timestamp FROM requests ORDER BY timestamp DESC LIMIT 1")
        return self.fetchone()[0]

    def get_last_actor(self) -> Tuple[str, str]:
        self.execute("SELECT actor_id, host FROM actors ORDER BY actor_id DESC LIMIT 1")
        actor_id, host = self.fetchone()
        self.execute("SELECT timestamp FROM requests WHERE actor_id = %s ORDER BY timestamp DESC LIMIT 1", (actor_id,))
        result = self.fetchone()
        if not result:
            return host, "Unknown"
        return host, result[0]

    def get_last_endpoint(self) -> Tuple[Any, ...]:
        self.execute("""
            SELECT "requests"."method", "unique_paths"."path", "requests"."threat_level"
            FROM (
                SELECT "path", COUNT(*) AS "count"
                FROM "requests"
                GROUP BY "path"
                HAVING COUNT(*) = 1
            ) AS unique_paths
            JOIN "requests" ON "unique_paths"."path" = "requests"."path"
            ORDER BY "requests"."request_id" DESC
            LIMIT 1;
        """)
        return self.fetchone()

    def get_average_time_between_requests(self) -> float:
        self.execute("""
            SELECT AVG("time_diff")
            FROM (
                SELECT "timestamp" - LAG("timestamp", 1) OVER (ORDER BY "timestamp") AS "time_diff"
                FROM "requests"
            ) AS "time_diffs"
            WHERE "time_diff" IS NOT NULL;
        """)
        return self.fetchone()[0]

    @commit_on_success
    def generate_admin_key(self) -> str:
        key = str(uuid4())
        self.execute("INSERT INTO admin_keys (key) VALUES (%s)", (key,))
        return key

    @commit_on_success
    def generate_admin_session_token(self, admin_username: str) -> str:
        self.execute("SELECT admin_id FROM admins WHERE username = %s", (admin_username,))
        admin_id = self.fetchone()[0]
        token = str(uuid4())
        self.execute("INSERT INTO admin_sessions (token, admin_id) VALUES (%s, %s)", (token, admin_id))
        return token

    def validate_session_token(self, token: str) -> bool:
        self.execute("SELECT EXISTS(SELECT token FROM admin_sessions WHERE token = %s)", (token,))
        return self.fetchone()[0]

    @commit_on_success
    def validate_and_delete_registration_key(self, key: str) -> bool:
        self.execute("SELECT EXISTS(SELECT key FROM admin_keys WHERE key = %s)", (key,))
        if not self.fetchone()[0]:
            return False
        self.execute("DELETE FROM admin_keys WHERE key = %s", (key,))
        return True

    @commit_on_success
    def add_admin(self, username: str, password: str):
        self.execute("INSERT INTO admins (username, password) VALUES (%s, %s)",
                     (username, self.hash_password(password)))

    def validate_admin_credentials(self, username: str, password: str) -> bool:
        self.execute("SELECT EXISTS(SELECT username FROM admins WHERE username = %s AND password = %s)",
                     (username, self.hash_password(password)))
        return self.fetchone()[0]

    def username_exists(self, username: str) -> bool:
        self.execute("SELECT EXISTS(SELECT username FROM admins WHERE username = %s)", (username,))
        return self.fetchone()[0]

    @staticmethod
    def hash_password(password: str) -> str:
        return sha256(password.encode()).hexdigest()
