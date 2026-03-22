"""
SupaHunt — Reporter Module
Generate structured reports from scan results in Markdown + JSON.
"""

import json
import os
from datetime import datetime, timezone
from typing import Optional


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


class Finding:
    """Represents a single security finding."""

    _counter = 0

    def __init__(self, title: str, severity: str, category: str, description: str,
                 evidence: str = "", impact: str = "", remediation: str = "",
                 cvss: float = 0.0):
        Finding._counter += 1
        self.id = f"SH-{Finding._counter:03d}"
        self.title = title
        self.severity = severity.upper()
        self.category = category
        self.description = description
        self.evidence = evidence
        self.impact = impact
        self.remediation = remediation
        self.cvss = cvss

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity,
            "category": self.category,
            "description": self.description,
            "evidence": self.evidence,
            "impact": self.impact,
            "remediation": self.remediation,
            "cvss": self.cvss,
        }


class ScanReport:
    """Aggregates all findings and generates reports."""

    def __init__(self, target_url: str, target_info: dict = None):
        self.target_url = target_url
        self.target_info = target_info or {}
        self.findings: list[Finding] = []
        self.tables_found: list = []
        self.rpcs_found: list = []
        self.buckets_found: list = []
        self.exfil_stats: dict = {}
        self.start_time = datetime.now(timezone.utc)
        self.end_time: Optional[datetime] = None

    def add_finding(self, **kwargs) -> Finding:
        f = Finding(**kwargs)
        self.findings.append(f)
        return f

    def severity_count(self) -> dict:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in self.findings:
            if f.severity in counts:
                counts[f.severity] += 1
        return counts

    def finalize(self):
        self.end_time = datetime.now(timezone.utc)

    def to_markdown(self) -> str:
        self.finalize()
        counts = self.severity_count()
        duration = (self.end_time - self.start_time).total_seconds()

        lines = []
        lines.append("# SupaHunt — Supabase Security Assessment Report\n")
        lines.append(f"**Target**: {self.target_url}")
        if self.target_info.get("supabase_url"):
            lines.append(f"**Supabase**: {self.target_info['supabase_url']}")
        if self.target_info.get("project_ref"):
            lines.append(f"**Project Ref**: {self.target_info['project_ref']}")
        lines.append(f"**Date**: {self.start_time.strftime('%Y-%m-%d %H:%M UTC')}")
        lines.append(f"**Duration**: {duration:.0f}s")
        lines.append(f"**Tool**: SupaHunt v1.0")
        lines.append("")

        # Executive summary
        lines.append("---\n")
        lines.append("## Executive Summary\n")
        total = sum(counts.values())
        lines.append(f"**{total} findings** discovered:\n")
        lines.append(f"| Severity | Count |")
        lines.append(f"|----------|-------|")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            if counts[sev] > 0:
                lines.append(f"| **{sev}** | {counts[sev]} |")
        lines.append("")

        if self.tables_found:
            total_records = sum(
                t.get("record_count", 0) or 0
                for t in self.tables_found
                if isinstance(t, dict)
            )
            lines.append(
                f"**{len(self.tables_found)} tables** discovered"
                f" ({total_records:,} total records accessible)"
            )
        if self.rpcs_found:
            callable_count = sum(1 for r in self.rpcs_found if r.get("callable"))
            lines.append(f"**{len(self.rpcs_found)} RPC functions** discovered ({callable_count} callable)")
        if self.buckets_found:
            lines.append(f"**{len(self.buckets_found)} storage buckets** discovered")
        lines.append("")

        # Auth settings
        auth = self.target_info.get("auth_settings", {})
        if auth:
            lines.append("---\n")
            lines.append("## Auth Configuration\n")
            lines.append(f"| Setting | Value |")
            lines.append(f"|---------|-------|")
            lines.append(f"| Signup enabled | {not auth.get('disable_signup', True)} |")
            lines.append(f"| Auto-confirm | {auth.get('mailer_autoconfirm', False)} |")
            ext = auth.get("external", {})
            providers = [k for k, v in ext.items() if v and isinstance(v, bool)]
            lines.append(f"| OAuth providers | {', '.join(providers) if providers else 'none'} |")
            lines.append("")

        # Findings
        lines.append("---\n")
        lines.append("## Findings\n")

        sorted_findings = sorted(
            self.findings,
            key=lambda f: SEVERITY_ORDER.get(f.severity, 99),
        )

        for f in sorted_findings:
            lines.append(f"### {f.id} [{f.severity}] {f.title}\n")
            lines.append(f"**Category**: {f.category}")
            if f.cvss:
                lines.append(f"**CVSS**: {f.cvss}")
            lines.append(f"\n{f.description}\n")
            if f.evidence:
                lines.append(f"**Evidence**:\n```\n{f.evidence}\n```\n")
            if f.impact:
                lines.append(f"**Impact**: {f.impact}\n")
            if f.remediation:
                lines.append(f"**Remediation**: {f.remediation}\n")
            lines.append("---\n")

        # Tables
        if self.tables_found:
            lines.append("## Discovered Tables\n")
            lines.append("| Table | Records | SELECT | INSERT | UPDATE | DELETE |")
            lines.append("|-------|---------|--------|--------|--------|--------|")
            for t in self.tables_found:
                if isinstance(t, dict):
                    name = t.get("name", "?")
                    count = t.get("record_count", "?")
                    s = "Y" if t.get("select") else "N"
                    i = "Y" if t.get("insert") else "N"
                    u = "Y" if t.get("update") else "N"
                    d = "Y" if t.get("delete") else "N"
                    lines.append(f"| {name} | {count} | {s} | {i} | {u} | {d} |")
            lines.append("")

        # RPCs
        if self.rpcs_found:
            lines.append("## Discovered RPC Functions\n")
            lines.append("| Function | Callable | Impact |")
            lines.append("|----------|----------|--------|")
            for r in self.rpcs_found:
                name = r.get("name", "?")
                call = "YES" if r.get("callable") else "no"
                impact = r.get("impact", "")
                lines.append(f"| {name} | {call} | {impact} |")
            lines.append("")

        return "\n".join(lines)

    def to_json(self) -> str:
        self.finalize()
        return json.dumps(
            {
                "target": self.target_url,
                "target_info": self.target_info,
                "scan_time": self.start_time.isoformat(),
                "duration_seconds": (self.end_time - self.start_time).total_seconds(),
                "severity_counts": self.severity_count(),
                "findings": [f.to_dict() for f in self.findings],
                "tables": self.tables_found,
                "rpcs": self.rpcs_found,
                "buckets": [b if isinstance(b, dict) else b for b in self.buckets_found],
            },
            indent=2,
            default=str,
        )

    def save(self, output_dir: str, basename: str = None):
        """Save report as both Markdown and JSON."""
        os.makedirs(output_dir, exist_ok=True)
        if not basename:
            ts = self.start_time.strftime("%Y%m%d-%H%M%S")
            ref = self.target_info.get("project_ref", "unknown")
            basename = f"supahunt-{ref}-{ts}"

        md_path = os.path.join(output_dir, f"{basename}.md")
        json_path = os.path.join(output_dir, f"{basename}.json")

        with open(md_path, "w") as f:
            f.write(self.to_markdown())
        with open(json_path, "w") as f:
            f.write(self.to_json())

        return md_path, json_path
