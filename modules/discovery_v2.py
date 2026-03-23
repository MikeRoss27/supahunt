"""
SupaHunt — Discovery v2 Module
Enhanced target reconnaissance with:
- Source map detection (.map files)
- API route probing (/api/env, /api/debug, /api/admin/*)
- Multi-project Supabase detection
- Secret extraction from JS bundles
- robots.txt / sitemap.xml analysis
- Webpack/Vite chunk deep scanning
"""

import re
import json
import base64
from urllib.parse import urlparse, urljoin
from typing import Optional, List
from concurrent.futures import ThreadPoolExecutor, as_completed
from .base import BaseModule
from .discovery import SupabaseTarget, decode_jwt_payload, validate_supabase_key


# Extended regex patterns
SUPABASE_URL_PATTERNS = [
    r'https?://([a-z0-9]{20,})\.supabase\.co',
    r'NEXT_PUBLIC_SUPABASE_URL["\s:=]+["\']?(https?://[^"\'\s,;]+)',
    r'SUPABASE_URL["\s:=]+["\']?(https?://[^"\'\s,;]+)',
    r'supabaseUrl["\s:=]+["\']?(https?://[^"\'\s,;]+)',
    r'VITE_SUPABASE_URL["\s:=]+["\']?(https?://[^"\'\s,;]+)',
    r'REACT_APP_SUPABASE_URL["\s:=]+["\']?(https?://[^"\'\s,;]+)',
    r'EXPO_PUBLIC_SUPABASE_URL["\s:=]+["\']?(https?://[^"\'\s,;]+)',
    r'NUXT_PUBLIC_SUPABASE_URL["\s:=]+["\']?(https?://[^"\'\s,;]+)',
    r'PUBLIC_SUPABASE_URL["\s:=]+["\']?(https?://[^"\'\s,;]+)',
]

ANON_KEY_PATTERNS = [
    r'NEXT_PUBLIC_SUPABASE_ANON_KEY["\s:=]+["\']?(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)',
    r'SUPABASE_ANON_KEY["\s:=]+["\']?(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)',
    r'supabaseAnonKey["\s:=]+["\']?(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)',
    r'VITE_SUPABASE_ANON_KEY["\s:=]+["\']?(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)',
    r'REACT_APP_SUPABASE_ANON_KEY["\s:=]+["\']?(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)',
    r'EXPO_PUBLIC_SUPABASE_ANON_KEY["\s:=]+["\']?(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)',
    r'["\']?(eyJ[A-Za-z0-9_-]{30,}\.eyJ[A-Za-z0-9_-]{50,}\.[A-Za-z0-9_-]{30,})',
]

SERVICE_ROLE_PATTERNS = [
    r'SUPABASE_SERVICE_ROLE_KEY["\s:=]+["\']?(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)',
    r'service_role["\s:=]+["\']?(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)',
    r'SERVICE_KEY["\s:=]+["\']?(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)',
]

# Secrets and sensitive patterns in JS bundles
SECRET_PATTERNS = [
    (r'STRIPE_SECRET_KEY["\s:=]+["\']?(sk_(?:live|test)_[A-Za-z0-9]+)', "Stripe Secret Key"),
    (r'STRIPE_PUBLISHABLE_KEY["\s:=]+["\']?(pk_(?:live|test)_[A-Za-z0-9]+)', "Stripe Publishable Key"),
    (r'OPENAI_API_KEY["\s:=]+["\']?(sk-[A-Za-z0-9]+)', "OpenAI API Key"),
    (r'DISCORD_(?:BOT_)?TOKEN["\s:=]+["\']?([A-Za-z0-9_.]+)', "Discord Token"),
    (r'DISCORD_CLIENT_SECRET["\s:=]+["\']?([A-Za-z0-9_-]+)', "Discord Client Secret"),
    (r'AWS_SECRET_ACCESS_KEY["\s:=]+["\']?([A-Za-z0-9/+=]+)', "AWS Secret Key"),
    (r'SENDGRID_API_KEY["\s:=]+["\']?(SG\.[A-Za-z0-9_-]+)', "SendGrid API Key"),
    (r'TWILIO_AUTH_TOKEN["\s:=]+["\']?([a-f0-9]{32})', "Twilio Auth Token"),
    (r'BUNNY_(?:CDN_)?(?:API_)?KEY["\s:=]+["\']?([A-Za-z0-9-]+)', "BunnyCDN Key"),
    (r'DATABASE_URL["\s:=]+["\']?(postgres(?:ql)?://[^"\'\s]+)', "Database URL"),
    (r'REDIS_URL["\s:=]+["\']?(redis://[^"\'\s]+)', "Redis URL"),
    (r'HMAC_SECRET["\s:=]+["\']?([A-Za-z0-9_-]{16,})', "HMAC Secret"),
    (r'JWT_SECRET["\s:=]+["\']?([A-Za-z0-9_-]{16,})', "JWT Secret"),
    (r'TOKEN_SECRET["\s:=]+["\']?([A-Za-z0-9_-]{16,})', "Token Secret"),
    (r'API_SECRET["\s:=]+["\']?([A-Za-z0-9_-]{16,})', "API Secret"),
    (r'WEBHOOK_SECRET["\s:=]+["\']?([A-Za-z0-9_-]{16,})', "Webhook Secret"),
    (r'ENCRYPTION_KEY["\s:=]+["\']?([A-Za-z0-9_-]{16,})', "Encryption Key"),
    (r'X[-_]API[-_]KEY["\s:=]+["\']?([A-Za-z0-9_-]{16,})', "X-API-Key"),
]

# API routes to probe for sensitive endpoints
API_PROBE_ROUTES = [
    # Debug/info endpoints
    "/api/env", "/api/debug", "/api/config", "/api/info",
    "/api/health", "/api/status", "/api/version", "/_debug",
    "/api/test", "/api/ping",
    # Admin endpoints
    "/api/admin", "/api/admin/users", "/api/admin/stats",
    "/api/admin/config", "/api/admin/logs", "/api/admin/dashboard",
    "/api/admin/settings", "/api/admin/system",
    # Internal endpoints
    "/api/internal", "/api/internal/stats", "/api/internal/health",
    "/api/cron", "/api/webhook", "/api/webhooks",
    # Next.js specific
    "/_next/data", "/api/auth/session", "/api/auth/providers",
    # Common API routes
    "/api/users", "/api/movies", "/api/search", "/api/content",
    "/api/media", "/api/video", "/api/stream",
    "/api/subscription", "/api/payment", "/api/billing",
    "/api/notifications", "/api/analytics",
    # GraphQL
    "/graphql", "/api/graphql",
    # Swagger/OpenAPI
    "/swagger.json", "/openapi.json", "/api-docs",
    "/swagger/v1/swagger.json",
]

JS_CHUNK_PATTERNS = [
    r'src="(/_next/static/[^"]+\.js)"',
    r'src="(/static/js/[^"]+\.js)"',
    r'src="(/assets/[^"]+\.js)"',
    r'src="(/js/[^"]+\.js)"',
    r'"(/_next/static/chunks/[^"]+\.js)"',
    r'"(/build/[^"]+\.js)"',
    r'src="(/dist/[^"]+\.js)"',
]


class DiscoveryV2(BaseModule):
    """
    Enhanced Supabase instance discovery.
    Extends base discovery with deep JS analysis, source maps, API probing.
    """

    def __init__(self, target=None, console=None, timeout: int = 15,
                 proxy: str = None, **kwargs):
        # Create a minimal target for BaseModule if none provided
        if target is None:
            target = type('obj', (object,), {
                'anon_key': '', 'supabase_url': '', 'rest_url': '',
                'graphql_url': '', 'auth_url': '', 'storage_url': '',
            })()
        super().__init__(target, console=console, timeout=timeout,
                         proxy=proxy, **kwargs)

    def discover(self, url: str, deep: bool = True) -> dict:
        """
        Full discovery pipeline.
        Returns dict with target, secrets, api_routes, source_maps, extra_projects.
        """
        result = {
            "target": SupabaseTarget(),
            "secrets_found": [],
            "api_routes": [],
            "source_maps": [],
            "extra_supabase_projects": [],
            "headers_security": {},
        }

        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        result["target"].app_url = url.rstrip("/")

        # Phase 1: Fetch main page
        self.log_info(f"Phase 1: Fetching {url}")
        resp = self.get(url, headers={"Accept": "text/html"})
        if not resp:
            self.log_fail("Could not fetch target")
            return result

        html = resp.text
        result["target"].headers_info = dict(resp.headers)
        result["headers_security"] = self._analyze_security_headers(resp.headers)

        # Phase 2: Extract from HTML + __NEXT_DATA__
        self.log_info("Phase 2: Scanning HTML for Supabase artifacts")
        all_text = html
        next_data = re.search(
            r'<script id="__NEXT_DATA__"[^>]*>(.*?)</script>', html, re.S
        )
        if next_data:
            all_text += "\n" + next_data.group(1)
            self.log_success("Found __NEXT_DATA__ script")

        supabase_urls = self._extract(all_text, SUPABASE_URL_PATTERNS)
        anon_keys = self._extract(all_text, ANON_KEY_PATTERNS)
        service_keys = self._extract(all_text, SERVICE_ROLE_PATTERNS)
        secrets = self._extract_secrets(all_text)

        # Phase 3: Crawl JS bundles
        self.log_info("Phase 3: Crawling JS bundles")
        js_paths = self._find_js_paths(html, base)
        self.log_info(f"Found {len(js_paths)} JS bundles")

        with ThreadPoolExecutor(max_workers=10) as pool:
            futures = {
                pool.submit(self._fetch_and_scan_js, base, path): path
                for path in js_paths[:80]
            }
            for future in as_completed(futures):
                js_result = future.result()
                if js_result:
                    supabase_urls.extend(js_result.get("urls", []))
                    anon_keys.extend(js_result.get("anon_keys", []))
                    service_keys.extend(js_result.get("service_keys", []))
                    secrets.extend(js_result.get("secrets", []))

        # Phase 4: Source map detection
        if deep:
            self.log_info("Phase 4: Scanning for source maps")
            source_maps = self._find_source_maps(base, js_paths[:30])
            result["source_maps"] = source_maps
            if source_maps:
                self.log_critical(f"Found {len(source_maps)} exposed source maps!")

        # Phase 5: Validate and build target
        self.log_info("Phase 5: Validating artifacts")
        self._build_target(result["target"], supabase_urls, anon_keys, service_keys)

        # Detect multiple Supabase projects
        all_refs = set()
        for key in set(anon_keys):
            payload = validate_supabase_key(key)
            if payload:
                ref = payload.get("ref", "")
                if ref:
                    all_refs.add(ref)

        if len(all_refs) > 1:
            self.log_critical(f"Multiple Supabase projects detected: {all_refs}")
            main_ref = result["target"].project_ref
            for ref in all_refs:
                if ref != main_ref:
                    result["extra_supabase_projects"].append({
                        "ref": ref,
                        "url": f"https://{ref}.supabase.co",
                    })

        # Phase 6: Fetch auth settings
        if result["target"].auth_url and result["target"].anon_key:
            self.log_info("Phase 6: Fetching auth settings")
            result["target"].auth_settings = self._fetch_auth_settings(
                result["target"]
            )

        # Phase 7: API route probing
        if deep:
            self.log_info("Phase 7: Probing API routes")
            result["api_routes"] = self._probe_api_routes(base)

        # Phase 8: robots.txt / sitemap
        if deep:
            self.log_info("Phase 8: Checking robots.txt and sitemap")
            robots_paths = self._check_robots_sitemap(base)
            if robots_paths:
                result["api_routes"].extend(robots_paths)

        # Collect secrets
        result["secrets_found"] = list({
            (s["type"], s["value"][:20] + "...") for s in secrets
        })
        if secrets:
            self.log_critical(f"Found {len(secrets)} secrets in JS bundles!")
            for s in secrets:
                self.log_warn(f"  {s['type']}: {s['value'][:40]}...")

        if service_keys:
            self.log_critical("SERVICE ROLE KEY FOUND IN CLIENT-SIDE CODE!")

        return result

    # ──── Extraction helpers ────

    def _extract(self, text: str, patterns: list) -> list:
        results = []
        for pat in patterns:
            for m in re.finditer(pat, text):
                val = m.group(1) if m.lastindex else m.group(0)
                if val not in results:
                    results.append(val)
        return results

    def _extract_secrets(self, text: str) -> list:
        secrets = []
        for pattern, name in SECRET_PATTERNS:
            for m in re.finditer(pattern, text):
                val = m.group(1)
                if len(val) > 8:  # Filter noise
                    secrets.append({"type": name, "value": val, "context": m.group(0)[:100]})
        return secrets

    # ──── JS Bundle Scanning ────

    def _find_js_paths(self, html: str, base_url: str) -> list:
        paths = []
        for pat in JS_CHUNK_PATTERNS:
            paths.extend(re.findall(pat, html))

        # Next.js build manifest
        for manifest in ["/_next/static/buildManifest.js", "/build-manifest.json",
                         "/_buildManifest.js"]:
            r = self.get(urljoin(base_url, manifest), headers={})
            if r and r.status_code == 200:
                chunk_paths = re.findall(r'"(/_next/static/chunks/[^"]+\.js)"', r.text)
                paths.extend(chunk_paths)
                # Also extract from sortedPages
                page_paths = re.findall(r'"(/[^"]+\.js)"', r.text)
                paths.extend(page_paths)

        return list(set(paths))

    def _fetch_and_scan_js(self, base_url: str, path: str) -> Optional[dict]:
        url = urljoin(base_url, path)
        r = self.get(url, headers={})
        if not r or r.status_code != 200:
            return None

        text = r.text
        return {
            "urls": self._extract(text, SUPABASE_URL_PATTERNS),
            "anon_keys": self._extract(text, ANON_KEY_PATTERNS),
            "service_keys": self._extract(text, SERVICE_ROLE_PATTERNS),
            "secrets": self._extract_secrets(text),
        }

    # ──── Source Map Detection ────

    def _find_source_maps(self, base_url: str, js_paths: list) -> list:
        found = []

        with ThreadPoolExecutor(max_workers=10) as pool:
            futures = {}
            for path in js_paths:
                map_url = urljoin(base_url, path + ".map")
                futures[pool.submit(self.get, map_url, None)] = map_url

                # Also check sourceMappingURL comment
                js_url = urljoin(base_url, path)
                futures[pool.submit(self._check_sourcemap_header, js_url)] = js_url

            for future in as_completed(futures):
                url = futures[future]
                r = future.result()
                if r and hasattr(r, 'status_code') and r.status_code == 200:
                    if url.endswith(".map"):
                        # Verify it's actually a source map
                        try:
                            data = r.json() if hasattr(r, 'json') else {}
                            if "sources" in data or "mappings" in data:
                                found.append({
                                    "url": url,
                                    "sources_count": len(data.get("sources", [])),
                                    "sample_sources": data.get("sources", [])[:10],
                                })
                                self.log_critical(
                                    f"Source map: {url} "
                                    f"({len(data.get('sources', []))} files)"
                                )
                        except Exception:
                            pass
                elif isinstance(r, str) and r:
                    found.append({"url": url, "type": "header_reference"})

        return found

    def _check_sourcemap_header(self, js_url: str) -> Optional[str]:
        r = self.get(js_url, headers={})
        if r and r.status_code == 200:
            sm_header = r.headers.get("SourceMap", r.headers.get("X-SourceMap", ""))
            if sm_header:
                return sm_header
            # Check last line comment
            lines = r.text.rstrip().split("\n")
            if lines:
                last = lines[-1]
                m = re.search(r'//[#@]\s*sourceMappingURL=(\S+)', last)
                if m:
                    return m.group(1)
        return None

    # ──── API Route Probing ────

    def _probe_api_routes(self, base_url: str) -> list:
        accessible = []

        with ThreadPoolExecutor(max_workers=15) as pool:
            futures = {}
            for route in API_PROBE_ROUTES:
                url = urljoin(base_url, route)
                futures[pool.submit(self.get, url, None)] = route

            for future in as_completed(futures):
                route = futures[future]
                r = future.result()
                if r and r.status_code in (200, 201, 403):
                    ct = r.headers.get("Content-Type", "")
                    size = len(r.content)

                    # Filter out generic 404/redirect pages
                    if size < 50 and r.status_code == 200:
                        continue
                    if "text/html" in ct and size > 5000 and r.status_code == 200:
                        # Likely a SPA catch-all, not a real API
                        if route.startswith("/api/"):
                            continue

                    entry = {
                        "route": route,
                        "status": r.status_code,
                        "content_type": ct,
                        "size": size,
                    }

                    # Check for sensitive data in response
                    if r.status_code == 200 and "json" in ct:
                        try:
                            data = r.json()
                            entry["has_data"] = True
                            if isinstance(data, dict):
                                entry["keys"] = list(data.keys())[:20]
                        except Exception:
                            pass

                    accessible.append(entry)
                    severity = "CRITICAL" if r.status_code == 200 and "json" in ct else "INFO"
                    if severity == "CRITICAL":
                        self.log_critical(f"API route: {route} ({r.status_code}, {size}b)")
                    else:
                        self.log_info(f"API route: {route} ({r.status_code})")

        return accessible

    # ──── Robots / Sitemap ────

    def _check_robots_sitemap(self, base_url: str) -> list:
        paths = []

        # robots.txt
        r = self.get(urljoin(base_url, "/robots.txt"), headers={})
        if r and r.status_code == 200:
            for line in r.text.split("\n"):
                line = line.strip()
                if line.startswith("Disallow:") or line.startswith("Allow:"):
                    path = line.split(":", 1)[1].strip()
                    if path and path != "/" and "/api" in path:
                        paths.append({
                            "route": path,
                            "source": "robots.txt",
                            "status": 0,
                        })

            # Look for sitemap references
            sitemaps = re.findall(r'Sitemap:\s*(\S+)', r.text, re.I)
            for sm_url in sitemaps:
                sr = self.get(sm_url, headers={})
                if sr and sr.status_code == 200:
                    urls = re.findall(r'<loc>([^<]+)</loc>', sr.text)
                    for u in urls[:50]:
                        if "/api/" in u or "/admin/" in u:
                            paths.append({
                                "route": urlparse(u).path,
                                "source": "sitemap.xml",
                                "status": 0,
                            })

        return paths

    # ──── Security Headers ────

    def _analyze_security_headers(self, headers) -> dict:
        checks = {}
        header_map = {k.lower(): v for k, v in headers.items()}

        checks["csp"] = {
            "present": "content-security-policy" in header_map,
            "value": header_map.get("content-security-policy", "")[:200],
        }
        checks["hsts"] = {
            "present": "strict-transport-security" in header_map,
            "value": header_map.get("strict-transport-security", ""),
        }
        checks["x_frame_options"] = {
            "present": "x-frame-options" in header_map,
            "value": header_map.get("x-frame-options", ""),
        }
        checks["x_content_type_options"] = {
            "present": "x-content-type-options" in header_map,
            "value": header_map.get("x-content-type-options", ""),
        }
        checks["server"] = header_map.get("server", "")
        checks["x_powered_by"] = header_map.get("x-powered-by", "")

        missing = [k for k, v in checks.items()
                   if isinstance(v, dict) and not v.get("present")]
        if missing:
            self.log_warn(f"Missing security headers: {', '.join(missing)}")

        return checks

    # ──── Target Builder ────

    def _build_target(self, target: SupabaseTarget,
                      urls: list, anon_keys: list, service_keys: list):
        """Validate and assign discovered artifacts to target."""
        # Validate anon keys
        valid_anon = []
        for key in set(anon_keys):
            payload = validate_supabase_key(key)
            if payload and payload.get("role") == "anon":
                valid_anon.append((key, payload))
                ref = payload.get("ref", "")
                if ref:
                    urls.append(f"https://{ref}.supabase.co")

        # Validate service keys
        for key in set(service_keys):
            payload = validate_supabase_key(key)
            if payload and payload.get("role") == "service_role":
                target.service_role_key = key
                ref = payload.get("ref", "")
                if ref:
                    urls.append(f"https://{ref}.supabase.co")

        # Set Supabase URL
        for u in set(urls):
            if ".supabase.co" in u:
                clean = u.rstrip("/")
                if not clean.endswith("/rest/v1") and not clean.endswith("/auth/v1"):
                    # Extract base URL
                    m = re.match(r'(https?://[a-z0-9]+\.supabase\.co)', clean)
                    if m:
                        target.supabase_url = m.group(1)
                        target.project_ref = re.search(
                            r'//([a-z0-9]+)\.supabase\.co', clean
                        ).group(1)
                        break

        if valid_anon:
            target.anon_key = valid_anon[0][0]

        # Build endpoint URLs
        if target.supabase_url:
            target.rest_url = f"{target.supabase_url}/rest/v1"
            target.graphql_url = f"{target.supabase_url}/graphql/v1"
            target.auth_url = f"{target.supabase_url}/auth/v1"
            target.realtime_url = f"{target.supabase_url}/realtime/v1"
            target.storage_url = f"{target.supabase_url}/storage/v1"

    def _fetch_auth_settings(self, target: SupabaseTarget) -> dict:
        r = self.get(
            f"{target.auth_url}/settings",
            headers={"apikey": target.anon_key},
        )
        if r and r.status_code == 200:
            try:
                return r.json()
            except Exception:
                pass
        return {}
