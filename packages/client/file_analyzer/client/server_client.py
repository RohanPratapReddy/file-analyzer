"""
The client side of the hosting server -- connect with a session token.

The server hands out a session token; a :class:`ServerClient` presents it as a
bearer credential to the server's HTTP control plane and drives every endpoint:
list/host/download databases, run read-only queries, trigger backups, read
Postgres logs, and enumerate the servers hosting a repo. It is standard-library
only (``urllib``) so the client works anywhere the package imports, with no
containment guard (connecting is not a runnable analysis surface).
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode

from ..tokens import PathLike


class ServerError(RuntimeError):
    """Raised when the server returns a non-2xx response."""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(f"HTTP {status}: {message}")
        self.status = status
        self.message = message


class ServerClient:
    """A thin HTTP client for a :class:`~file_analyzer.server.server.DatabaseServer`."""

    def __init__(
        self, base_url: str, token: Optional[str] = None, *, timeout: float = 30.0
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout = float(timeout)

    # -- low-level ------------------------------------------------------
    def _request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Dict[str, Any]] = None,
        raw_body: Optional[bytes] = None,
        raw_response: bool = False,
    ) -> Any:
        url = self.base_url + path
        if params:
            url += "?" + urlencode(params)
        headers = {}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        data: Optional[bytes] = None
        if json_body is not None:
            data = json.dumps(json_body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        elif raw_body is not None:
            data = raw_body
            headers["Content-Type"] = "application/octet-stream"
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                payload = resp.read()
                if raw_response:
                    return payload
                return json.loads(payload.decode("utf-8")) if payload else {}
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", "replace")
            try:
                message = json.loads(body).get("error", body)
            except ValueError:
                message = body
            raise ServerError(exc.code, message) from exc

    # -- endpoints ------------------------------------------------------
    def health(self) -> Dict[str, Any]:
        return self._request("GET", "/health")

    def session(self) -> Dict[str, Any]:
        return self._request("GET", "/session")

    def databases(self) -> List[Dict[str, Any]]:
        return self._request("GET", "/databases").get("databases", [])

    def servers(self) -> List[Dict[str, Any]]:
        return self._request("GET", "/servers").get("servers", [])

    def host_path(self, source_path: PathLike, db_name: str) -> Dict[str, Any]:
        """Ask the server to host a database file it can already see on disk."""
        return self._request(
            "POST",
            "/databases",
            json_body={"source_path": str(source_path), "db_name": db_name},
        ).get("hosted", {})

    def upload(self, source_path: PathLike, db_name: str) -> Dict[str, Any]:
        """Upload a local database file to the server to host."""
        data = Path(source_path).read_bytes()
        return self._request(
            "POST",
            "/databases/upload",
            params={"db_name": db_name},
            raw_body=data,
        ).get("hosted", {})

    def download(self, storage_key: str, dest: PathLike) -> Path:
        """Download a hosted database's bytes to ``dest``."""
        data = self._request(
            "GET", f"/databases/{storage_key}/download", raw_response=True
        )
        dest = Path(dest)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
        return dest

    def query(self, storage_key: str, sql: str, *, limit: int = 100) -> Dict[str, Any]:
        """Run a single read-only SELECT/WITH against a hosted database."""
        return self._request(
            "POST",
            "/query",
            json_body={"storage_key": storage_key, "sql": sql, "limit": limit},
        )

    def backup(self, storage_key: Optional[str] = None) -> Dict[str, Any]:
        """Trigger a backup now (one database, or all if ``storage_key`` is None)."""
        body = {"storage_key": storage_key} if storage_key else {}
        return self._request("POST", "/backup", json_body=body)

    def backups(self, storage_key: Optional[str] = None) -> List[Dict[str, Any]]:
        params = {"storage_key": storage_key} if storage_key else None
        return self._request("GET", "/backups", params=params).get("backups", [])

    def postgres_logs(self, lines: int = 100) -> Dict[str, Any]:
        return self._request("GET", "/pglogs", params={"lines": lines})
