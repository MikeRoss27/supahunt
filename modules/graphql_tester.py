"""
SupaHunt — GraphQL Mutation RLS Tester
Systematically tests every INSERT/UPDATE/DELETE mutation for RLS bypass.
Based on real-world testing that found 88% of mutations unprotected.
"""

import json
import uuid
import secrets
from typing import Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from .base import BaseModule


# Dummy values by GraphQL type for INSERT probing
TYPE_DEFAULTS = {
    "UUID": str(uuid.UUID(int=0)),
    "String": "supahunt_test",
    "Int": 1,
    "BigInt": 1,
    "Float": 0.0,
    "BigFloat": "0.0",
    "Boolean": False,
    "Datetime": "2099-01-01T00:00:00Z",
    "Date": "2099-01-01",
    "Time": "00:00:00",
    "JSON": "{}",
    "Cursor": None,
    "ID": None,
    "Opaque": None,
}


class MutationResult:
    """Result of testing a single mutation."""

    def __init__(self, mutation_name: str, operation: str, table: str):
        self.mutation_name = mutation_name
        self.operation = operation  # INSERT, UPDATE, DELETE
        self.table = table
        self.status = "untested"  # rls_bypass, constraint_block, rls_block, error, skipped
        self.error_message = ""
        self.affected_count = 0
        self.created_id = None  # For cleanup
        self.response_data = None

    @property
    def is_bypass(self) -> bool:
        return self.status == "rls_bypass"

    @property
    def is_constraint_only(self) -> bool:
        return self.status == "constraint_block"

    @property
    def severity(self) -> str:
        if self.status == "rls_bypass":
            return "CRITICAL" if self.operation == "INSERT" else "HIGH"
        if self.status == "constraint_block":
            return "HIGH"
        return "INFO"

    def to_dict(self) -> dict:
        return {
            "mutation": self.mutation_name,
            "operation": self.operation,
            "table": self.table,
            "status": self.status,
            "severity": self.severity,
            "error": self.error_message,
            "affected_count": self.affected_count,
            "created_id": self.created_id,
        }


class GraphQLMutationTester(BaseModule):
    """
    Systematically tests GraphQL mutations for RLS bypass.

    Strategy:
    1. Introspect schema → get all mutations + their input types
    2. For each INSERT mutation: build minimal valid object, attempt INSERT
    3. For each UPDATE mutation: attempt UPDATE with impossible filter
    4. For each DELETE mutation: attempt DELETE with impossible filter
    5. Classify results: rls_bypass / constraint_block / rls_block / error
    """

    def __init__(self, target, console=None, timeout: int = 15,
                 proxy: str = None, threads: int = 5, **kwargs):
        super().__init__(target, console=console, timeout=timeout,
                         proxy=proxy, **kwargs)
        self.threads = threads
        self._mutations_cache = None
        self._type_cache = {}

    # ──── Schema Introspection ────

    def get_all_mutations(self, token: str = None) -> list:
        """Get all mutation fields from GraphQL schema."""
        if self._mutations_cache is not None:
            return self._mutations_cache

        query = """
        {
            __schema {
                mutationType {
                    fields {
                        name
                        args {
                            name
                            type {
                                name
                                kind
                                ofType {
                                    name
                                    kind
                                    ofType {
                                        name
                                        kind
                                        ofType { name kind }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        """
        result = self.graphql_query(query, token)
        fields = (
            (result.get("data") or {})
            .get("__schema") or {}
        )
        fields = (
            (fields.get("mutationType") or {})
            .get("fields", [])
        )
        self._mutations_cache = fields
        return fields

    def classify_mutations(self, token: str = None) -> dict:
        """Classify all mutations into INSERT, UPDATE, DELETE, RPC."""
        mutations = self.get_all_mutations(token)
        classified = {"insert": [], "update": [], "delete": [], "rpc": []}

        for m in mutations:
            name = m["name"]
            if name.startswith("insertInto"):
                table = name[len("insertInto"):]
                if table.endswith("Collection"):
                    table = table[:-len("Collection")]
                classified["insert"].append({"name": name, "table": table, "args": m["args"]})
            elif name.startswith("updateFrom") or (name.startswith("update") and "Collection" in name):
                table = name.replace("updateFrom", "").replace("update", "")
                if table.endswith("Collection"):
                    table = table[:-len("Collection")]
                classified["update"].append({"name": name, "table": table, "args": m["args"]})
            elif name.startswith("deleteFrom"):
                table = name[len("deleteFrom"):]
                if table.endswith("Collection"):
                    table = table[:-len("Collection")]
                classified["delete"].append({"name": name, "table": table, "args": m["args"]})
            else:
                classified["rpc"].append({"name": name, "args": m["args"]})

        return classified

    def get_insert_input_fields(self, table_name: str, token: str = None) -> list:
        """Get the InsertInput type fields for a table."""
        cache_key = f"{table_name}_insert"
        if cache_key in self._type_cache:
            return self._type_cache[cache_key]

        type_name = f"{table_name}InsertInput"
        query = f"""
        {{
            __type(name: "{type_name}") {{
                inputFields {{
                    name
                    type {{
                        name
                        kind
                        ofType {{
                            name
                            kind
                            ofType {{ name kind }}
                        }}
                    }}
                }}
            }}
        }}
        """
        result = self.graphql_query(query, token)
        t = (result.get("data") or {}).get("__type")
        fields = t.get("inputFields", []) if t else []
        self._type_cache[cache_key] = fields
        return fields

    def get_update_input_fields(self, table_name: str, token: str = None) -> list:
        """Get the UpdateInput type fields for a table."""
        cache_key = f"{table_name}_update"
        if cache_key in self._type_cache:
            return self._type_cache[cache_key]

        type_name = f"{table_name}UpdateInput"
        query = f"""
        {{
            __type(name: "{type_name}") {{
                inputFields {{
                    name
                    type {{
                        name
                        kind
                        ofType {{ name kind }}
                    }}
                }}
            }}
        }}
        """
        result = self.graphql_query(query, token)
        t = (result.get("data") or {}).get("__type")
        fields = t.get("inputFields", []) if t else []
        self._type_cache[cache_key] = fields
        return fields

    # ──── Value Builders ────

    def _resolve_type(self, type_info: dict) -> Optional[str]:
        """Resolve a GraphQL type to its base scalar name."""
        if type_info is None:
            return None
        kind = type_info.get("kind")
        name = type_info.get("name")

        if kind == "SCALAR" or kind == "ENUM":
            return name
        if kind == "NON_NULL" or kind == "LIST":
            return self._resolve_type(type_info.get("ofType", {}))
        return name

    def _is_required(self, field: dict) -> bool:
        """Check if a field is NON_NULL (required)."""
        return field.get("type", {}).get("kind") == "NON_NULL"

    def _build_insert_object(self, fields: list) -> dict:
        """Build a minimal test object with dummy values for required fields."""
        obj = {}
        for field in fields:
            name = field["name"]
            if name in ("nodeId", "id", "created_at", "updated_at"):
                continue

            type_name = self._resolve_type(field["type"])
            required = self._is_required(field)

            if not required:
                continue

            default = TYPE_DEFAULTS.get(type_name)
            if default is None:
                # Unknown type — try string
                default = "test"

            # Use unique values for common field patterns
            if "email" in name.lower():
                default = f"supahunt_{secrets.token_hex(4)}@test.local"
            elif name == "user_id" or name == "created_by":
                default = str(uuid.UUID(int=0))
            elif "name" in name.lower() and type_name == "String":
                default = f"supahunt_test_{secrets.token_hex(3)}"
            elif "url" in name.lower():
                default = "https://supahunt.test/probe"
            elif "token" in name.lower():
                default = f"SH_TEST_{secrets.token_hex(8)}"

            obj[name] = default

        return obj

    def _format_value(self, value) -> str:
        """Format a Python value for GraphQL query string."""
        if isinstance(value, str):
            # Escape quotes in string
            escaped = value.replace("\\", "\\\\").replace('"', '\\"')
            return f'"{escaped}"'
        if isinstance(value, bool):
            return "true" if value else "false"
        if isinstance(value, (int, float)):
            return str(value)
        if value is None:
            return "null"
        return f'"{value}"'

    def _build_object_string(self, obj: dict) -> str:
        """Convert a dict to a GraphQL object literal string."""
        parts = []
        for k, v in obj.items():
            parts.append(f"{k}: {self._format_value(v)}")
        return "{ " + ", ".join(parts) + " }"

    # ──── Mutation Testing ────

    def test_insert(self, mutation_info: dict, token: str = None) -> MutationResult:
        """Test a single INSERT mutation for RLS bypass."""
        name = mutation_info["name"]
        table = mutation_info["table"]
        result = MutationResult(name, "INSERT", table)

        # Get input fields
        fields = self.get_insert_input_fields(table, token)
        if not fields:
            result.status = "error"
            result.error_message = f"Could not introspect {table}InsertInput"
            return result

        # Build test object
        obj = self._build_insert_object(fields)
        if not obj:
            result.status = "skipped"
            result.error_message = "No required fields found"
            return result

        obj_str = self._build_object_string(obj)

        mutation = f"""
        mutation {{
            {name}(objects: [{obj_str}]) {{
                affectedCount
                records {{ nodeId }}
            }}
        }}
        """

        response = self.graphql_mutation(mutation, token)
        errors = response.get("errors", [])
        data = (response.get("data") or {}).get(name, {})

        if errors:
            err_msg = errors[0].get("message", "")
            result.error_message = err_msg

            if "row-level security" in err_msg.lower() or "permission denied" in err_msg.lower():
                result.status = "rls_block"
            elif "violates" in err_msg.lower() and ("foreign key" in err_msg.lower()
                    or "check constraint" in err_msg.lower()
                    or "not-null" in err_msg.lower()
                    or "unique" in err_msg.lower()):
                # Passed RLS but blocked by DB constraint
                result.status = "constraint_block"
            elif "unknown field" in err_msg.lower() or "type mismatch" in err_msg.lower():
                result.status = "error"
            else:
                # Other error — might be constraint, might be RLS
                if "violates" in err_msg.lower():
                    result.status = "constraint_block"
                else:
                    result.status = "error"
        elif data:
            affected = data.get("affectedCount", 0)
            if affected > 0:
                result.status = "rls_bypass"
                result.affected_count = affected
                records = data.get("records", [])
                if records:
                    result.created_id = records[0].get("nodeId")
            else:
                result.status = "rls_block"
        else:
            result.status = "error"
            result.error_message = "No data in response"

        result.response_data = response
        return result

    def test_update(self, mutation_info: dict, token: str = None) -> MutationResult:
        """Test an UPDATE mutation for RLS bypass using impossible filter."""
        name = mutation_info["name"]
        table = mutation_info["table"]
        result = MutationResult(name, "UPDATE", table)

        # Get update fields to find a valid field name
        fields = self.get_update_input_fields(table, token)
        if not fields:
            # Fallback: try with empty set
            result.status = "error"
            result.error_message = "Could not introspect update fields"
            return result

        # Pick first string or non-id field for a harmless update
        set_field = None
        for f in fields:
            fname = f["name"]
            if fname in ("id", "nodeId", "created_at"):
                continue
            type_name = self._resolve_type(f["type"])
            if type_name in ("String", "Int", "Boolean", "BigFloat"):
                set_field = (fname, type_name)
                break

        if not set_field:
            result.status = "skipped"
            result.error_message = "No suitable field for update test"
            return result

        fname, ftype = set_field
        # Use a value that won't actually change anything meaningful
        dummy_val = self._format_value(TYPE_DEFAULTS.get(ftype, "test"))

        # Filter on impossible UUID so no rows are actually affected
        fake_id = "00000000-0000-0000-0000-000000000000"

        mutation = f"""
        mutation {{
            {name}(
                set: {{ {fname}: {dummy_val} }},
                filter: {{ id: {{ eq: "{fake_id}" }} }}
            ) {{
                affectedCount
            }}
        }}
        """

        response = self.graphql_mutation(mutation, token)
        errors = response.get("errors", [])
        data = (response.get("data") or {}).get(name, {})

        if errors:
            err_msg = errors[0].get("message", "")
            result.error_message = err_msg

            if "row-level security" in err_msg.lower() or "permission denied" in err_msg.lower():
                result.status = "rls_block"
            elif "unknown field" in err_msg.lower() or "unknown argument" in err_msg.lower():
                result.status = "error"
            else:
                result.status = "error"
        elif data is not None:
            # If we get data back (even with 0 affected), mutation was accepted
            result.status = "rls_bypass"
            result.affected_count = data.get("affectedCount", 0)
        else:
            result.status = "error"

        result.response_data = response
        return result

    def test_delete(self, mutation_info: dict, token: str = None) -> MutationResult:
        """Test a DELETE mutation for RLS bypass using impossible filter."""
        name = mutation_info["name"]
        table = mutation_info["table"]
        result = MutationResult(name, "DELETE", table)

        fake_id = "00000000-0000-0000-0000-000000000000"

        mutation = f"""
        mutation {{
            {name}(filter: {{ id: {{ eq: "{fake_id}" }} }}) {{
                affectedCount
            }}
        }}
        """

        response = self.graphql_mutation(mutation, token)
        errors = response.get("errors", [])
        data = (response.get("data") or {}).get(name, {})

        if errors:
            err_msg = errors[0].get("message", "")
            result.error_message = err_msg

            if "row-level security" in err_msg.lower() or "permission denied" in err_msg.lower():
                result.status = "rls_block"
            else:
                result.status = "error"
        elif data is not None:
            result.status = "rls_bypass"
            result.affected_count = data.get("affectedCount", 0)
        else:
            result.status = "error"

        result.response_data = response
        return result

    # ──── Batch Testing ────

    def test_all_mutations(self, token: str = None,
                           test_inserts: bool = True,
                           test_updates: bool = True,
                           test_deletes: bool = True,
                           progress_callback=None) -> dict:
        """
        Test all mutations in the schema.
        Returns dict with 'insert', 'update', 'delete' result lists.
        """
        classified = self.classify_mutations(token)
        results = {"insert": [], "update": [], "delete": [], "summary": {}}

        total = 0
        if test_inserts:
            total += len(classified["insert"])
        if test_updates:
            total += len(classified["update"])
        if test_deletes:
            total += len(classified["delete"])

        self.log_info(f"Testing {total} mutations "
                      f"({len(classified['insert'])} INSERT, "
                      f"{len(classified['update'])} UPDATE, "
                      f"{len(classified['delete'])} DELETE)")

        tested = 0

        # INSERT tests (sequential — they create rows)
        if test_inserts:
            self.log_info("Testing INSERT mutations...")
            for m in classified["insert"]:
                result = self.test_insert(m, token)
                results["insert"].append(result)
                tested += 1
                if progress_callback:
                    progress_callback(tested, total, result)

                if result.is_bypass:
                    self.log_critical(
                        f"INSERT bypass: {result.table} "
                        f"(affected: {result.affected_count})"
                    )
                elif result.is_constraint_only:
                    self.log_warn(
                        f"INSERT constraint-only block: {result.table} "
                        f"({result.error_message[:60]})"
                    )

        # UPDATE tests (can parallelize — they don't modify real data)
        if test_updates:
            self.log_info("Testing UPDATE mutations...")
            with ThreadPoolExecutor(max_workers=self.threads) as pool:
                futures = {
                    pool.submit(self.test_update, m, token): m
                    for m in classified["update"]
                }
                for future in as_completed(futures):
                    result = future.result()
                    results["update"].append(result)
                    tested += 1
                    if progress_callback:
                        progress_callback(tested, total, result)

                    if result.is_bypass:
                        self.log_warn(f"UPDATE accessible: {result.table}")

        # DELETE tests (can parallelize — they use impossible filter)
        if test_deletes:
            self.log_info("Testing DELETE mutations...")
            with ThreadPoolExecutor(max_workers=self.threads) as pool:
                futures = {
                    pool.submit(self.test_delete, m, token): m
                    for m in classified["delete"]
                }
                for future in as_completed(futures):
                    result = future.result()
                    results["delete"].append(result)
                    tested += 1
                    if progress_callback:
                        progress_callback(tested, total, result)

                    if result.is_bypass:
                        self.log_warn(f"DELETE accessible: {result.table}")

        # Summary
        results["summary"] = self._summarize(results)
        return results

    def _summarize(self, results: dict) -> dict:
        """Generate summary statistics."""
        summary = {
            "total_tested": 0,
            "rls_bypass": 0,
            "constraint_block": 0,
            "rls_block": 0,
            "errors": 0,
            "skipped": 0,
            "bypass_tables": [],
            "constraint_only_tables": [],
            "insert_bypass_count": 0,
            "update_bypass_count": 0,
            "delete_bypass_count": 0,
        }

        for op in ("insert", "update", "delete"):
            for r in results[op]:
                summary["total_tested"] += 1
                if r.status == "rls_bypass":
                    summary["rls_bypass"] += 1
                    summary[f"{op}_bypass_count"] += 1
                    if r.table not in summary["bypass_tables"]:
                        summary["bypass_tables"].append(r.table)
                elif r.status == "constraint_block":
                    summary["constraint_block"] += 1
                    if r.table not in summary["constraint_only_tables"]:
                        summary["constraint_only_tables"].append(r.table)
                elif r.status == "rls_block":
                    summary["rls_block"] += 1
                elif r.status == "error":
                    summary["errors"] += 1
                else:
                    summary["skipped"] += 1

        total_real = summary["total_tested"] - summary["errors"] - summary["skipped"]
        if total_real > 0:
            summary["rls_coverage_pct"] = round(
                summary["rls_block"] / total_real * 100, 1
            )
            summary["bypass_pct"] = round(
                (summary["rls_bypass"] + summary["constraint_block"]) / total_real * 100, 1
            )
        else:
            summary["rls_coverage_pct"] = 0
            summary["bypass_pct"] = 0

        return summary

    # ──── Cleanup ────

    def cleanup_created_rows(self, results: dict, token: str = None):
        """Delete rows that were created during INSERT testing."""
        created = [r for r in results.get("insert", [])
                   if r.is_bypass and r.created_id]

        if not created:
            return

        self.log_info(f"Cleaning up {len(created)} test rows...")
        for r in created:
            mutation = f"""
            mutation {{
                deleteFrom{r.table}Collection(
                    filter: {{ nodeId: {{ eq: "{r.created_id}" }} }}
                ) {{ affectedCount }}
            }}
            """
            resp = self.graphql_mutation(mutation, token)
            affected = (
                (resp.get("data") or {})
                .get(f"deleteFrom{r.table}Collection") or {}
            ).get("affectedCount", 0)
            if affected > 0:
                self.log_success(f"Cleaned up: {r.table}")
            else:
                self.log_warn(f"Could not clean: {r.table} (may need manual cleanup)")
