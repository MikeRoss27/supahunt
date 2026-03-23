"""
SupaHunt — Base Module
Shared HTTP session management, retry logic, rate limiting, and helpers.
All exploit/enum modules inherit from this.
"""

import time
import json
import base64
import secrets
import requests
import urllib3
from typing import Optional, Any
from threading import Lock
from functools import wraps

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class RateLimiter:
    """Token-bucket rate limiter for API calls."""

    def __init__(self, requests_per_second: float = 10.0):
        self.rps = requests_per_second
        self.min_interval = 1.0 / requests_per_second
        self._last_request = 0.0
        self._lock = Lock()

    def wait(self):
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_request
            if elapsed < self.min_interval:
                time.sleep(self.min_interval - elapsed)
            self._last_request = time.monotonic()


class RetryConfig:
    """Retry configuration for HTTP requests."""

    def __init__(self, max_retries: int = 3, backoff_factor: float = 1.0,
                 retry_on: tuple = (429, 500, 502, 503, 504)):
        self.max_retries = max_retries
        self.backoff_factor = backoff_factor
        self.retry_on = retry_on


class BaseModule:
    """
    Base class for all SupaHunt modules.
    Provides: HTTP session, auth headers, rate limiting, retry, logging.
    """

    def __init__(self, target, console=None, timeout: int = 15,
                 proxy: str = None, rate_limit: float = 10.0,
                 retry: RetryConfig = None):
        self.target = target
        self.console = console
        self.timeout = timeout
        self._rate_limiter = RateLimiter(rate_limit)
        self._retry = retry or RetryConfig()

        self.session = requests.Session()
        self.session.verify = False
        self.session.headers["User-Agent"] = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        )
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}

        # Request counters
        self._request_count = 0
        self._error_count = 0

    # ──── Logging ────

    def log(self, msg: str, style: str = ""):
        if self.console:
            self.console.print(msg, style=style)

    def log_success(self, msg: str):
        self.log(f"  [bold green][+][/] {msg}")

    def log_fail(self, msg: str):
        self.log(f"  [red][-][/] {msg}")

    def log_info(self, msg: str):
        self.log(f"  [cyan][*][/] {msg}")

    def log_warn(self, msg: str):
        self.log(f"  [yellow][!][/] {msg}")

    def log_critical(self, msg: str):
        self.log(f"  [bold red][!!!][/] {msg}")

    # ──── Headers ────

    def _anon_headers(self) -> dict:
        """Headers with anon key only (no user auth)."""
        return {
            "apikey": self.target.anon_key,
            "Authorization": f"Bearer {self.target.anon_key}",
            "Content-Type": "application/json",
        }

    def _auth_headers(self, token: str) -> dict:
        """Headers with user bearer token."""
        return {
            "apikey": self.target.anon_key,
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }

    def _headers(self, token: str = None) -> dict:
        """Smart header builder: uses token if provided, else anon key."""
        if token:
            return self._auth_headers(token)
        return self._anon_headers()

    # ──── HTTP with retry + rate limit ────

    def _request(self, method: str, url: str, token: str = None,
                 headers: dict = None, json_data: Any = None,
                 data: Any = None, content_type: str = None,
                 prefer: str = None, extra_headers: dict = None,
                 timeout: int = None) -> Optional[requests.Response]:
        """
        Core HTTP request with rate limiting and retry.
        Returns Response or None on total failure.
        """
        if headers is None:
            headers = self._headers(token)
        if prefer:
            headers["Prefer"] = prefer
        if content_type:
            headers["Content-Type"] = content_type
        if extra_headers:
            headers.update(extra_headers)

        _timeout = timeout or self.timeout

        for attempt in range(self._retry.max_retries + 1):
            self._rate_limiter.wait()
            self._request_count += 1

            try:
                r = self.session.request(
                    method, url,
                    headers=headers,
                    json=json_data,
                    data=data,
                    timeout=_timeout,
                )

                # Rate limited — back off and retry
                if r.status_code in self._retry.retry_on and attempt < self._retry.max_retries:
                    wait = self._retry.backoff_factor * (2 ** attempt)
                    if r.status_code == 429:
                        # Respect Retry-After header
                        retry_after = r.headers.get("Retry-After")
                        if retry_after:
                            try:
                                wait = max(wait, float(retry_after))
                            except ValueError:
                                pass
                    self.log_warn(f"HTTP {r.status_code} on {url}, retry in {wait:.1f}s")
                    time.sleep(wait)
                    continue

                return r

            except requests.exceptions.Timeout:
                self._error_count += 1
                if attempt < self._retry.max_retries:
                    time.sleep(self._retry.backoff_factor * (2 ** attempt))
                    continue
            except requests.exceptions.ConnectionError:
                self._error_count += 1
                if attempt < self._retry.max_retries:
                    time.sleep(self._retry.backoff_factor * (2 ** attempt))
                    continue
            except Exception:
                self._error_count += 1
                return None

        return None

    # ──── Convenience HTTP methods ────

    def get(self, url: str, token: str = None, **kwargs) -> Optional[requests.Response]:
        return self._request("GET", url, token=token, **kwargs)

    def post(self, url: str, token: str = None, json_data: Any = None,
             **kwargs) -> Optional[requests.Response]:
        return self._request("POST", url, token=token, json_data=json_data, **kwargs)

    def patch(self, url: str, token: str = None, json_data: Any = None,
              **kwargs) -> Optional[requests.Response]:
        return self._request("PATCH", url, token=token, json_data=json_data, **kwargs)

    def delete(self, url: str, token: str = None, **kwargs) -> Optional[requests.Response]:
        return self._request("DELETE", url, token=token, **kwargs)

    def put(self, url: str, token: str = None, json_data: Any = None,
            **kwargs) -> Optional[requests.Response]:
        return self._request("PUT", url, token=token, json_data=json_data, **kwargs)

    # ──── Supabase-specific helpers ────

    def rest_url(self, path: str) -> str:
        """Build REST API URL: /rest/v1/{path}"""
        return f"{self.target.rest_url}/{path}"

    def rpc_url(self, function_name: str) -> str:
        """Build RPC URL: /rest/v1/rpc/{name}"""
        return f"{self.target.rest_url}/rpc/{function_name}"

    def graphql_url(self) -> str:
        return self.target.graphql_url

    def storage_url(self, path: str = "") -> str:
        return f"{self.target.storage_url}/{path}" if path else self.target.storage_url

    def call_rpc(self, name: str, params: dict = None, token: str = None) -> dict:
        """Call an RPC function, return structured result."""
        r = self.post(self.rpc_url(name), token=token, json_data=params or {})
        if r is None:
            return {"status": 0, "success": False, "data": "connection error"}
        return {
            "status": r.status_code,
            "success": r.status_code in (200, 204),
            "data": r.text[:2000],
        }

    def graphql_query(self, query: str, token: str = None) -> dict:
        """Execute a GraphQL query/mutation."""
        r = self.post(self.graphql_url(), token=token, json_data={"query": query})
        if r is None:
            return {"errors": [{"message": "connection error"}]}
        try:
            return r.json()
        except Exception:
            return {"errors": [{"message": r.text[:500]}]}

    def graphql_mutation(self, mutation: str, token: str = None) -> dict:
        """Alias for graphql_query (mutations use same endpoint)."""
        return self.graphql_query(mutation, token)

    # ──── JWT helpers ────

    @staticmethod
    def decode_jwt(token: str) -> dict:
        """Decode JWT payload without verification."""
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return {}
            payload = parts[1]
            payload += "=" * (4 - len(payload) % 4)
            return json.loads(base64.urlsafe_b64decode(payload))
        except Exception:
            return {}

    @staticmethod
    def is_supabase_key(token: str) -> Optional[dict]:
        """Validate if a JWT is a Supabase key. Returns claims or None."""
        payload = BaseModule.decode_jwt(token)
        if payload.get("iss", "").startswith("supabase"):
            return payload
        return None

    # ──── Stats ────

    @property
    def stats(self) -> dict:
        return {
            "requests": self._request_count,
            "errors": self._error_count,
        }
