"""
SupaHunt — Discovery Module
Auto-detect Supabase instances from any target URL.
Extracts anon keys, project refs, API endpoints from JS bundles, HTML, headers.
"""

import re
import json
import base64
import requests
from urllib.parse import urlparse, urljoin
from typing import Optional


class SupabaseTarget:
    """Represents a discovered Supabase backend."""

    def __init__(self):
        self.app_url: str = ""
        self.supabase_url: str = ""
        self.anon_key: str = ""
        self.project_ref: str = ""
        self.service_role_key: str = ""
        self.rest_url: str = ""
        self.graphql_url: str = ""
        self.auth_url: str = ""
        self.realtime_url: str = ""
        self.storage_url: str = ""
        self.auth_settings: dict = {}
        self.headers_info: dict = {}

    @property
    def api_headers(self) -> dict:
        h = {
            "apikey": self.anon_key,
            "Content-Type": "application/json",
        }
        return h

    def auth_headers(self, token: str) -> dict:
        h = self.api_headers.copy()
        h["Authorization"] = f"Bearer {token}"
        return h

    def to_dict(self) -> dict:
        return {
            "app_url": self.app_url,
            "supabase_url": self.supabase_url,
            "anon_key": self.anon_key,
            "project_ref": self.project_ref,
            "rest_url": self.rest_url,
            "graphql_url": self.graphql_url,
            "auth_url": self.auth_url,
            "realtime_url": self.realtime_url,
            "storage_url": self.storage_url,
            "auth_settings": self.auth_settings,
        }


# --- Regex patterns for Supabase artifact extraction ---

SUPABASE_URL_PATTERNS = [
    r'https?://([a-z0-9]{20,})\.supabase\.co',
    r'NEXT_PUBLIC_SUPABASE_URL["\s:=]+["\']?(https?://[^"\'\s,;]+)',
    r'SUPABASE_URL["\s:=]+["\']?(https?://[^"\'\s,;]+)',
    r'supabaseUrl["\s:=]+["\']?(https?://[^"\'\s,;]+)',
    r'VITE_SUPABASE_URL["\s:=]+["\']?(https?://[^"\'\s,;]+)',
    r'REACT_APP_SUPABASE_URL["\s:=]+["\']?(https?://[^"\'\s,;]+)',
]

ANON_KEY_PATTERNS = [
    r'NEXT_PUBLIC_SUPABASE_ANON_KEY["\s:=]+["\']?(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)',
    r'SUPABASE_ANON_KEY["\s:=]+["\']?(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)',
    r'supabaseAnonKey["\s:=]+["\']?(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)',
    r'VITE_SUPABASE_ANON_KEY["\s:=]+["\']?(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)',
    r'REACT_APP_SUPABASE_ANON_KEY["\s:=]+["\']?(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)',
    # Generic JWT that looks like a Supabase key
    r'["\']?(eyJ[A-Za-z0-9_-]{30,}\.eyJ[A-Za-z0-9_-]{50,}\.[A-Za-z0-9_-]{30,})',
]

SERVICE_ROLE_PATTERNS = [
    r'SUPABASE_SERVICE_ROLE_KEY["\s:=]+["\']?(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)',
    r'service_role["\s:=]+["\']?(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)',
]

JS_CHUNK_PATTERNS = [
    r'src="(/_next/static/[^"]+\.js)"',
    r'src="(/static/js/[^"]+\.js)"',
    r'src="(/assets/[^"]+\.js)"',
    r'src="(/js/[^"]+\.js)"',
    r'href="(/_next/static/css/[^"]+\.css)"',
]


def decode_jwt_payload(token: str) -> dict:
    """Decode JWT payload without verification."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return {}
        payload = parts[1]
        # Add padding
        payload += "=" * (4 - len(payload) % 4)
        decoded = base64.urlsafe_b64decode(payload)
        return json.loads(decoded)
    except Exception:
        return {}


def validate_supabase_key(key: str) -> Optional[dict]:
    """Check if a JWT is a valid Supabase key and return its claims."""
    payload = decode_jwt_payload(key)
    if not payload:
        return None
    if payload.get("iss", "").startswith("supabase"):
        return payload
    return None


def extract_project_ref(url: str) -> str:
    """Extract Supabase project ref from URL."""
    m = re.search(r'https?://([a-z0-9]{20,})\.supabase\.co', url)
    return m.group(1) if m else ""


class Discovery:
    """Discover Supabase instances from a target URL."""

    def __init__(self, console=None, timeout: int = 15, proxy: str = None):
        self.console = console
        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = False
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}
        self.session.headers["User-Agent"] = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        )

    def log(self, msg: str, style: str = ""):
        if self.console:
            self.console.print(msg, style=style)

    def _fetch(self, url: str) -> Optional[requests.Response]:
        try:
            r = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            return r
        except Exception:
            return None

    def _search_text(self, text: str, patterns: list) -> list:
        results = []
        for pat in patterns:
            for m in re.finditer(pat, text):
                val = m.group(1) if m.lastindex else m.group(0)
                if val not in results:
                    results.append(val)
        return results

    def discover(self, url: str) -> SupabaseTarget:
        """
        Main discovery flow:
        1. Fetch main page HTML
        2. Extract inline Supabase config
        3. Crawl JS bundles for keys
        4. Validate keys + build target
        5. Fetch auth settings
        """
        target = SupabaseTarget()
        target.app_url = url.rstrip("/")
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        self.log(f"\n[*] Fetching {url}", style="bold cyan")
        resp = self._fetch(url)
        if not resp:
            self.log("[!] Failed to fetch target", style="bold red")
            return target

        # Collect response headers
        target.headers_info = dict(resp.headers)
        html = resp.text

        # --- Phase 1: Extract from HTML ---
        self.log("[*] Phase 1: Scanning HTML for Supabase artifacts...", style="cyan")

        supabase_urls = self._search_text(html, SUPABASE_URL_PATTERNS)
        anon_keys = self._search_text(html, ANON_KEY_PATTERNS)
        service_keys = self._search_text(html, SERVICE_ROLE_PATTERNS)

        # --- Phase 2: Crawl JS bundles ---
        self.log("[*] Phase 2: Crawling JS bundles...", style="cyan")
        js_paths = []
        for pat in JS_CHUNK_PATTERNS:
            js_paths.extend(re.findall(pat, html))

        # Also look for __NEXT_DATA__ script
        next_data = re.search(r'<script id="__NEXT_DATA__"[^>]*>(.*?)</script>', html, re.S)
        if next_data:
            self.log("  [+] Found __NEXT_DATA__ script", style="green")
            supabase_urls.extend(self._search_text(next_data.group(1), SUPABASE_URL_PATTERNS))
            anon_keys.extend(self._search_text(next_data.group(1), ANON_KEY_PATTERNS))

        # Fetch build manifest for Next.js
        for manifest_path in ["/_next/static/buildManifest.js", "/build-manifest.json",
                              "/_buildManifest.js"]:
            mr = self._fetch(urljoin(base, manifest_path))
            if mr and mr.status_code == 200:
                for pat in JS_CHUNK_PATTERNS:
                    js_paths.extend(re.findall(pat, mr.text))
                # Also look for chunk paths in manifest
                chunk_paths = re.findall(r'"(/_next/static/chunks/[^"]+\.js)"', mr.text)
                js_paths.extend(chunk_paths)

        # Deduplicate and fetch JS files
        js_paths = list(set(js_paths))
        self.log(f"  [*] Found {len(js_paths)} JS bundles to scan", style="cyan")

        for js_path in js_paths[:50]:  # Limit to 50 bundles
            js_url = urljoin(base, js_path)
            jr = self._fetch(js_url)
            if jr and jr.status_code == 200:
                supabase_urls.extend(self._search_text(jr.text, SUPABASE_URL_PATTERNS))
                anon_keys.extend(self._search_text(jr.text, ANON_KEY_PATTERNS))
                service_keys.extend(self._search_text(jr.text, SERVICE_ROLE_PATTERNS))

        # --- Phase 3: Validate and deduplicate ---
        self.log("[*] Phase 3: Validating discovered artifacts...", style="cyan")

        # Validate anon keys
        valid_anon_keys = []
        for key in set(anon_keys):
            payload = validate_supabase_key(key)
            if payload:
                valid_anon_keys.append((key, payload))
                ref = payload.get("ref", "")
                if ref:
                    supabase_urls.append(f"https://{ref}.supabase.co")

        # Validate service role keys
        valid_service_keys = []
        for key in set(service_keys):
            payload = validate_supabase_key(key)
            if payload and payload.get("role") == "service_role":
                valid_service_keys.append((key, payload))
                self.log("  [!!!] SERVICE ROLE KEY FOUND!", style="bold red on white")

        # Resolve Supabase URL
        supabase_urls = list(set(supabase_urls))
        for su in supabase_urls:
            if ".supabase.co" in su:
                target.supabase_url = su.rstrip("/")
                target.project_ref = extract_project_ref(su)
                break

        if not target.supabase_url and valid_anon_keys:
            ref = valid_anon_keys[0][1].get("ref", "")
            if ref:
                target.supabase_url = f"https://{ref}.supabase.co"
                target.project_ref = ref

        if valid_anon_keys:
            target.anon_key = valid_anon_keys[0][0]
        if valid_service_keys:
            target.service_role_key = valid_service_keys[0][0]

        # Build endpoint URLs
        if target.supabase_url:
            target.rest_url = f"{target.supabase_url}/rest/v1"
            target.graphql_url = f"{target.supabase_url}/graphql/v1"
            target.auth_url = f"{target.supabase_url}/auth/v1"
            target.realtime_url = f"{target.supabase_url}/realtime/v1"
            target.storage_url = f"{target.supabase_url}/storage/v1"

        # --- Phase 4: Fetch auth settings ---
        if target.auth_url and target.anon_key:
            self.log("[*] Phase 4: Fetching auth settings...", style="cyan")
            target.auth_settings = self._fetch_auth_settings(target)

        return target

    def _fetch_auth_settings(self, target: SupabaseTarget) -> dict:
        """Fetch GoTrue auth settings — reveals signup, providers, autoconfirm."""
        try:
            r = self.session.get(
                f"{target.auth_url}/settings",
                headers={"apikey": target.anon_key},
                timeout=self.timeout,
            )
            if r.status_code == 200:
                return r.json()
        except Exception:
            pass
        return {}

    def discover_from_config(self, supabase_url: str, anon_key: str) -> SupabaseTarget:
        """Build target from known config (skip discovery)."""
        target = SupabaseTarget()
        target.supabase_url = supabase_url.rstrip("/")
        target.anon_key = anon_key
        target.project_ref = extract_project_ref(supabase_url)
        target.rest_url = f"{target.supabase_url}/rest/v1"
        target.graphql_url = f"{target.supabase_url}/graphql/v1"
        target.auth_url = f"{target.supabase_url}/auth/v1"
        target.realtime_url = f"{target.supabase_url}/realtime/v1"
        target.storage_url = f"{target.supabase_url}/storage/v1"
        target.auth_settings = self._fetch_auth_settings(target)
        return target
