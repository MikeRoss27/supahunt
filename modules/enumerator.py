"""
SupaHunt — Enumerator Module
Discovers tables, columns, RPC functions, storage buckets via REST + GraphQL.
"""

import json
import requests
from typing import Optional
from concurrent.futures import ThreadPoolExecutor, as_completed


# Common Supabase table names to probe
COMMON_TABLES = [
    # Auth/Users
    "profiles", "users", "user_profiles", "accounts", "members", "roles",
    "user_roles", "permissions", "teams", "organizations", "invitations",
    # Content
    "posts", "articles", "comments", "categories", "tags", "pages",
    "media", "files", "uploads", "images", "videos", "documents",
    # E-commerce
    "products", "orders", "order_items", "payments", "invoices",
    "subscriptions", "plans", "prices", "coupons", "customers",
    "transactions", "wallets", "credits",
    # Social
    "messages", "conversations", "notifications", "follows", "likes",
    "reactions", "bookmarks", "favorites", "reviews", "ratings",
    "reports", "blocks", "friends", "contacts",
    # System
    "settings", "system_settings", "config", "configurations",
    "logs", "audit_logs", "admin_logs", "auth_logs", "event_logs",
    "sessions", "active_sessions", "tokens", "api_keys",
    "webhooks", "webhook_events", "jobs", "tasks", "queues",
    # Ads/Marketing
    "campaigns", "ad_campaigns", "advertisers", "ad_events",
    "ad_creatives", "ad_pricing", "analytics",
    # OAuth/SSO
    "oauth_states", "oauth_tokens", "providers", "connections",
    # Misc
    "features", "feature_flags", "announcements", "feedback",
    "suggestions", "contact_messages", "newsletter",
    "blocked_ips", "ip_bans", "rate_limits",
    # Premium/Subscription
    "premium_subscriptions", "premium_plans", "premium_features",
    # Streaming
    "video_sources", "episodes", "seasons", "movies", "tv_shows",
    "streams", "channels", "playlists",
]


class TableInfo:
    def __init__(self, name: str):
        self.name = name
        self.exists = False
        self.record_count: Optional[int] = None
        self.columns: list = []
        self.sample_data: list = []
        self.select_allowed = False
        self.insert_allowed = False
        self.update_allowed = False
        self.delete_allowed = False
        self.http_status: int = 0
        self.error: str = ""

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "exists": self.exists,
            "record_count": self.record_count,
            "columns": self.columns,
            "select": self.select_allowed,
            "insert": self.insert_allowed,
            "update": self.update_allowed,
            "delete": self.delete_allowed,
        }


class RPCFunction:
    def __init__(self, name: str):
        self.name = name
        self.callable = False
        self.requires_params = False
        self.error: str = ""
        self.result = None

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "callable": self.callable,
            "requires_params": self.requires_params,
            "error": self.error,
        }


class StorageBucket:
    def __init__(self, name: str):
        self.name = name
        self.public = False
        self.file_count: int = 0
        self.files: list = []
        self.upload_allowed = False

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "public": self.public,
            "file_count": self.file_count,
            "upload_allowed": self.upload_allowed,
            "sample_files": self.files[:10],
        }


class Enumerator:
    """Enumerate Supabase resources: tables, RPCs, GraphQL, storage."""

    def __init__(self, target, console=None, timeout: int = 10, proxy: str = None,
                 threads: int = 10):
        self.target = target
        self.console = console
        self.timeout = timeout
        self.threads = threads
        self.session = requests.Session()
        self.session.verify = False
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}

    def log(self, msg: str, style: str = ""):
        if self.console:
            self.console.print(msg, style=style)

    def _headers(self, token: str = None) -> dict:
        h = {"apikey": self.target.anon_key, "Content-Type": "application/json"}
        if token:
            h["Authorization"] = f"Bearer {token}"
        else:
            h["Authorization"] = f"Bearer {self.target.anon_key}"
        return h

    # ──────────────────────────────────────────────
    # TABLE ENUMERATION
    # ──────────────────────────────────────────────

    def _probe_table(self, table_name: str, token: str = None) -> TableInfo:
        """Probe a single table for existence, record count, columns."""
        info = TableInfo(table_name)
        headers = self._headers(token)
        headers["Prefer"] = "count=exact"
        headers["Range"] = "0-0"

        try:
            r = self.session.get(
                f"{self.target.rest_url}/{table_name}?select=*&limit=1",
                headers=headers,
                timeout=self.timeout,
            )
            info.http_status = r.status_code

            if r.status_code in (200, 206):
                info.exists = True
                info.select_allowed = True

                # Parse record count from content-range
                cr = r.headers.get("content-range", "")
                if "/" in cr:
                    try:
                        info.record_count = int(cr.split("/")[1])
                    except (ValueError, IndexError):
                        pass

                # Extract columns from response
                data = r.json()
                if data and isinstance(data, list) and len(data) > 0:
                    info.columns = list(data[0].keys())
                    info.sample_data = data[:1]

            elif r.status_code == 404:
                info.exists = False
            elif r.status_code in (401, 403):
                info.exists = True  # Table exists but access denied
                info.error = r.text[:200]
            else:
                info.error = r.text[:200]

        except Exception as e:
            info.error = str(e)

        return info

    def enumerate_tables(self, custom_tables: list = None, token: str = None,
                         graphql_first: bool = True) -> list:
        """
        Enumerate tables. If GraphQL introspection works, use it to get
        the real table list. Otherwise, brute-force with common names.
        """
        tables_to_probe = []

        if graphql_first:
            self.log("[*] Attempting GraphQL introspection for table names...", style="cyan")
            gql_tables = self._graphql_get_tables(token)
            if gql_tables:
                self.log(
                    f"  [+] GraphQL revealed {len(gql_tables)} collections",
                    style="bold green",
                )
                tables_to_probe = gql_tables

        if not tables_to_probe:
            tables_to_probe = list(set(COMMON_TABLES + (custom_tables or [])))
            self.log(
                f"[*] Brute-forcing {len(tables_to_probe)} table names...",
                style="cyan",
            )

        results = []
        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            futures = {
                pool.submit(self._probe_table, t, token): t
                for t in tables_to_probe
            }
            for future in as_completed(futures):
                info = future.result()
                if info.exists:
                    results.append(info)

        results.sort(key=lambda x: (x.record_count or 0), reverse=True)
        return results

    def _graphql_get_tables(self, token: str = None) -> list:
        """Use GraphQL introspection to discover all collections (tables)."""
        query = """
        {
            __schema {
                queryType {
                    fields {
                        name
                    }
                }
            }
        }
        """
        headers = self._headers(token)
        try:
            r = self.session.post(
                self.target.graphql_url,
                headers=headers,
                json={"query": query},
                timeout=self.timeout,
            )
            if r.status_code == 200:
                data = r.json()
                fields = (
                    data.get("data", {})
                    .get("__schema", {})
                    .get("queryType", {})
                    .get("fields", [])
                )
                tables = []
                for f in fields:
                    name = f["name"]
                    if name.endswith("Collection"):
                        # Convert fooCollection → foo
                        table = name[:-10]  # len("Collection") == 10
                        tables.append(table)
                return tables
        except Exception:
            pass
        return []

    # ──────────────────────────────────────────────
    # RLS TESTING (CRUD per table)
    # ──────────────────────────────────────────────

    def test_rls(self, table: TableInfo, token: str = None) -> TableInfo:
        """Test INSERT, UPDATE, DELETE permissions on a table."""
        headers = self._headers(token)

        # INSERT test (empty object — will likely fail on NOT NULL but reveals RLS)
        try:
            r = self.session.post(
                f"{self.target.rest_url}/{table.name}",
                headers={**headers, "Prefer": "return=minimal"},
                json={},
                timeout=self.timeout,
            )
            if r.status_code in (201, 200):
                table.insert_allowed = True
            elif "row-level security" in r.text.lower():
                table.insert_allowed = False
            elif "violates not-null" in r.text.lower() or "null value" in r.text.lower():
                # RLS passed, blocked by schema constraint — INSERT is allowed
                table.insert_allowed = True
            elif r.status_code in (401, 403):
                table.insert_allowed = False
        except Exception:
            pass

        # UPDATE test (set nothing, filter impossible)
        try:
            r = self.session.patch(
                f"{self.target.rest_url}/{table.name}?id=eq.00000000-0000-0000-0000-000000000000",
                headers={**headers, "Prefer": "return=representation"},
                json={},
                timeout=self.timeout,
            )
            if r.status_code in (200, 204):
                table.update_allowed = True
            elif r.status_code in (401, 403):
                table.update_allowed = False
        except Exception:
            pass

        # DELETE test (filter impossible ID)
        try:
            r = self.session.delete(
                f"{self.target.rest_url}/{table.name}?id=eq.00000000-0000-0000-0000-000000000000",
                headers=headers,
                timeout=self.timeout,
            )
            if r.status_code in (200, 204):
                table.delete_allowed = True
            elif r.status_code in (401, 403):
                table.delete_allowed = False
        except Exception:
            pass

        return table

    # ──────────────────────────────────────────────
    # RPC FUNCTION ENUMERATION
    # ──────────────────────────────────────────────

    def enumerate_rpcs(self, token: str = None) -> list:
        """Discover RPC functions via GraphQL mutation introspection."""
        query = """
        {
            __schema {
                mutationType {
                    fields {
                        name
                        args {
                            name
                            type { name kind }
                        }
                    }
                }
            }
        }
        """
        headers = self._headers(token)
        rpcs = []

        try:
            r = self.session.post(
                self.target.graphql_url,
                headers=headers,
                json={"query": query},
                timeout=self.timeout,
            )
            if r.status_code == 200:
                data = r.json()
                fields = (
                    data.get("data", {})
                    .get("__schema", {})
                    .get("mutationType", {})
                    .get("fields", [])
                )
                for f in fields:
                    name = f["name"]
                    # Skip standard CRUD mutations
                    if any(name.startswith(p) for p in
                           ("insertInto", "updateFrom", "update", "deleteFrom")):
                        continue
                    rpc = RPCFunction(name)
                    rpc.callable = True
                    rpcs.append(rpc)
        except Exception:
            pass

        # Also probe common dangerous function names directly
        dangerous_rpcs = [
            "expire_premium_subscriptions", "cleanup_old_auth_logs",
            "cleanup_old_webhook_events", "cleanup_expired_oauth_states",
            "send_notification", "send_global_announcement",
            "add_advertiser_credit", "process_payment_credit",
            "delete_user", "ban_user", "suspend_user", "unsuspend_user",
            "grant_admin", "promote_user", "reset_password",
            "calculate_daily_premium_stats", "auto_complete_expired_campaigns",
            "create_expiration_notifications", "create_user_profile",
        ]

        for rpc_name in dangerous_rpcs:
            rpc = RPCFunction(rpc_name)
            try:
                r = self.session.post(
                    f"{self.target.rest_url}/rpc/{rpc_name}",
                    headers=headers,
                    json={},
                    timeout=self.timeout,
                )
                if r.status_code in (200, 204):
                    rpc.callable = True
                    rpc.result = r.text[:500]
                elif "permission denied" in r.text.lower():
                    rpc.callable = False
                    rpc.error = "permission denied"
                elif r.status_code == 404:
                    continue  # Function doesn't exist
                else:
                    rpc.callable = True
                    rpc.requires_params = True
                    rpc.error = r.text[:200]
                rpcs.append(rpc)
            except Exception:
                pass

        return rpcs

    # ──────────────────────────────────────────────
    # GRAPHQL INTROSPECTION
    # ──────────────────────────────────────────────

    def graphql_introspect(self, token: str = None) -> dict:
        """Full GraphQL introspection — types, mutations, queries."""
        query = """
        {
            __schema {
                types {
                    name
                    kind
                    fields {
                        name
                        type { name kind ofType { name kind } }
                    }
                }
                queryType { fields { name } }
                mutationType { fields { name } }
            }
        }
        """
        headers = self._headers(token)
        try:
            r = self.session.post(
                self.target.graphql_url,
                headers=headers,
                json={"query": query},
                timeout=30,
            )
            if r.status_code == 200:
                return r.json()
        except Exception:
            pass
        return {}

    def graphql_get_insert_schema(self, table_name: str, token: str = None) -> list:
        """Get INSERT input fields for a table via GraphQL introspection."""
        type_name = f"{table_name}InsertInput"
        query = f"""
        {{
            __type(name: "{type_name}") {{
                inputFields {{
                    name
                    type {{ name kind ofType {{ name }} }}
                }}
            }}
        }}
        """
        headers = self._headers(token)
        try:
            r = self.session.post(
                self.target.graphql_url,
                headers=headers,
                json={"query": query},
                timeout=self.timeout,
            )
            if r.status_code == 200:
                data = r.json()
                t = data.get("data", {}).get("__type")
                if t:
                    return t.get("inputFields", [])
        except Exception:
            pass
        return []

    # ──────────────────────────────────────────────
    # STORAGE BUCKET ENUMERATION
    # ──────────────────────────────────────────────

    def enumerate_storage(self, token: str = None) -> list:
        """Discover and probe storage buckets."""
        headers = self._headers(token)
        buckets = []

        # List buckets
        try:
            r = self.session.get(
                f"{self.target.storage_url}/bucket",
                headers=headers,
                timeout=self.timeout,
            )
            if r.status_code == 200:
                for b in r.json():
                    bucket = StorageBucket(b.get("name", b.get("id", "")))
                    bucket.public = b.get("public", False)

                    # List files in bucket
                    try:
                        fr = self.session.post(
                            f"{self.target.storage_url}/object/list/{bucket.name}",
                            headers=headers,
                            json={"prefix": "", "limit": 100, "offset": 0},
                            timeout=self.timeout,
                        )
                        if fr.status_code == 200:
                            files = fr.json()
                            bucket.file_count = len(files)
                            bucket.files = [
                                f.get("name", "") for f in files if f.get("name")
                            ]
                    except Exception:
                        pass

                    buckets.append(bucket)
        except Exception:
            pass

        return buckets
