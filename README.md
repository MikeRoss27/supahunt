<p align="center">
  <h1 align="center">SupaHunt</h1>
  <p align="center">
    <b>Supabase Security Auditing & Penetration Testing Framework</b>
  </p>
  <p align="center">
    <img src="https://img.shields.io/badge/python-3.8+-blue.svg" alt="Python">
    <img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License">
    <img src="https://img.shields.io/badge/version-1.0-red.svg" alt="Version">
    <img src="https://img.shields.io/badge/supabase-offensive-orange.svg" alt="Supabase">
  </p>
</p>

---

**SupaHunt** automatically discovers, enumerates, and exploits Supabase instances. Point it at any URL using Supabase — it extracts the anon key from JS bundles, maps the entire database via GraphQL introspection, tests every RLS policy, and chains vulnerabilities into full kill chains.

Built from real-world bug bounty experience testing production Supabase applications.

> **Disclaimer**: For authorized security testing and bug bounty programs only.

---

## Features

| Capability | Details |
|-----------|---------|
| **Auto-Discovery** | Extracts Supabase URL + anon key from HTML, `__NEXT_DATA__`, JS chunks, build manifests |
| **Service Role Detection** | Flags leaked `service_role` keys in client-side code |
| **Table Enumeration** | GraphQL introspection + brute-force of 100+ common table names |
| **RLS Testing** | Automated SELECT/INSERT/UPDATE/DELETE permission testing per table |
| **RPC Auditing** | Discovers and probes dangerous functions (cleanup, delete, financial) |
| **JWT Injection** | Tests `user_metadata` claim injection via `PUT /auth/v1/user` |
| **Role Escalation** | Tests profile role field mutability (admin, moderator, etc.) |
| **GraphQL Exploitation** | Full schema introspection, mutation discovery, INSERT schema extraction |
| **Storage Buckets** | Enumerates buckets, lists files, tests upload permissions |
| **Data Exfiltration** | Batch extraction with progress tracking |
| **Persistence** | OAuth state backdoor injection testing |
| **Auto-Reporting** | Markdown + JSON reports with CVSS-scored findings |

---

## Install

```bash
git clone https://github.com/MikeRoss27/supahunt.git
cd supahunt
pip install requests rich
```

---

## Usage

### Quick Start

```bash
# Full automated kill chain (discover -> enum -> exploit -> exfil -> report)
python3 supahunt.py full https://target.com
```

### Commands

```bash
# Phase 1: Auto-discover Supabase from any URL
python3 supahunt.py discover https://target.com

# Phase 2: Enumerate tables, RPCs, storage, GraphQL
python3 supahunt.py enum https://target.com

# Phase 3: Run exploitation modules
python3 supahunt.py exploit https://target.com

# Phase 4: Mass data exfiltration
python3 supahunt.py exfil https://target.com

# Recon only (no exploitation, no exfil)
python3 supahunt.py scan https://target.com
```

### Advanced Options

```bash
# Skip discovery — provide Supabase config directly
python3 supahunt.py full https://target.com \
  --supabase-url https://xxxxx.supabase.co \
  --anon-key eyJhbGci...

# Use existing auth token (skip account creation)
python3 supahunt.py enum https://target.com --token eyJhbGci...

# Route through Burp/ZAP proxy
python3 supahunt.py full https://target.com --proxy http://127.0.0.1:8080

# Add custom table names to probe
python3 supahunt.py enum https://target.com --tables invoices,receipts,secrets

# Recon only (safe mode)
python3 supahunt.py full https://target.com --no-exploit --no-exfil

# Control threads and timeout
python3 supahunt.py full https://target.com --threads 20 --timeout 30
```

---

## Modules

### `discovery.py` — Target Reconnaissance
- Fetches target HTML, extracts inline Supabase config
- Crawls JS bundles (Next.js, Vite, React) for keys
- Parses `__NEXT_DATA__`, build manifests
- Validates JWT keys (anon vs service_role)
- Fetches GoTrue `/auth/v1/settings` (signup, autoconfirm, providers)

### `enumerator.py` — Database Mapping
- GraphQL `__schema` introspection → all collections
- Brute-force 100+ common Supabase table names
- Per-table RLS testing (SELECT/INSERT/UPDATE/DELETE)
- Record count extraction via `Content-Range` headers
- Column discovery from response data
- RPC function enumeration via GraphQL mutations
- Storage bucket listing + file enumeration

### `exploiter.py` — Vulnerability Exploitation
- **AuthExploiter**: Account creation, JWT claim injection, token refresh
- **ProfileExploiter**: Role escalation, sensitive field mutation, stored XSS
- **RPCExploiter**: Dangerous function execution (cleanup, expire, financial)
- **DataExploiter**: IDOR testing, cross-user data access, GraphQL queries
- **PersistenceExploiter**: OAuth state backdoor injection

### `reporter.py` — Report Generation
- Structured findings with severity, CVSS, evidence, remediation
- Markdown report with executive summary
- JSON export for integration with other tools
- Table/RPC/bucket inventory

---

## Nuclei Templates

6 custom Nuclei templates for passive/active Supabase checks:

```bash
nuclei -t templates/supabase-misconfig.yaml -u https://target.com -var anon_key=eyJ...
```

| Template | Severity | Check |
|----------|----------|-------|
| `supabase-auth-settings-leak` | Medium | Auth settings disclosure |
| `supabase-graphql-introspection` | High | GraphQL schema exposed |
| `supabase-autoconfirm-enabled` | High | No email verification |
| `supabase-jwt-claim-injection` | Critical | user_metadata writable |
| `supabase-storage-buckets-list` | Medium | Bucket enumeration |
| `supabase-rpc-dangerous-functions` | Critical | Admin RPCs callable |

---

## Output

```
output/
├── supahunt-{project_ref}-{timestamp}.md    # Markdown report
├── supahunt-{project_ref}-{timestamp}.json  # JSON report
└── exfil/
    ├── profiles.json
    ├── users.json
    └── ...
```

---

## Common Vulnerability Patterns

SupaHunt tests for these Supabase-specific vulnerability classes:

| Class | Description |
|-------|-------------|
| **RLS Bypass** | Tables with `USING (true)` or `WITH CHECK (true)` policies |
| **JWT Injection** | `PUT /auth/v1/user` accepting arbitrary `user_metadata` |
| **SECURITY DEFINER RPCs** | Functions executing with creator privileges, no auth check |
| **GraphQL Schema Leak** | Introspection exposing all tables, columns, relationships |
| **Auto-Confirm Signup** | `mailer_autoconfirm: true` enabling mass account creation |
| **Storage Misconfiguration** | Public buckets or missing upload restrictions |
| **Service Role Key Leak** | `service_role` JWT in client-side JavaScript |
| **IDOR via RPC** | Functions accepting `user_id` param without ownership check |

---

## Contributing

PRs welcome. If you find new Supabase attack patterns, open an issue or submit a template.

## License

MIT
