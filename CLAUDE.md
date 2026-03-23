# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

SupaHunt is a Supabase security auditing & penetration testing framework (v3.0). It auto-discovers, enumerates, and exploits Supabase instances. 14 CLI commands, 12-phase kill chain, 13 modules.

**For authorized security testing only.**

## Commands

```bash
# Verify all modules compile
python3 -m py_compile supahunt.py && for f in modules/*.py; do python3 -m py_compile "$f"; done

# Lint (matches CI)
flake8 --max-line-length=120 --count --statistics --exit-zero .

# Run the tool
python3 supahunt.py <command> <url> [options]

# Available commands: discover, discover2, scan, enum, exploit, graphql, storage, filters, exfil, webhook, reviews, rpc-abuse, forge, full
```

There are no unit tests. CI only runs `py_compile` + flake8 on push/PR to main.

## Architecture

### Data Flow

Every scan revolves around two objects passed through the command chain:
- **`SupabaseTarget`** (immutable) — holds discovered URLs, keys, auth settings. Created once in discovery, never modified.
- **`ScanReport`** (mutable) — accumulates `Finding` objects throughout all phases. Written to markdown + JSON at the end.

```
cmd_full() orchestrates:
  Phase 1:  cmd_discover_v2()  → SupabaseTarget
  Phase 2:  cmd_enum()         → tables, rpcs (+ report findings)
  Phase 3:  cmd_exploit()      → auth token (+ report findings)
  Phase 4:  cmd_graphql_test() → mutation RLS results
  Phase 5:  cmd_storage_audit()
  Phase 6:  cmd_filter_test()
  Phase 7:  cmd_exfil()
  Phase 8:  cmd_webhook()
  Phase 9:  cmd_reviews()
  Phase 10: cmd_rpc_abuse()
  Phase 11: cmd_forge()
  Phase 12: report.save() → output/*.md + output/*.json
```

Each `cmd_*()` can run standalone (auto-discovers target) or receive `target`/`report`/`token` from the previous phase.

### Module Pattern

All exploit modules inherit from `BaseModule` (`modules/base.py`) which provides:
- HTTP session with rate limiting (`RateLimiter`, token-bucket) and exponential backoff retry
- Auth header builders: `_anon_headers()`, `_auth_headers(token)`, `_headers(token)` (smart — uses token if provided, else anon key)
- Supabase helpers: `rest_url()`, `rpc_url()`, `call_rpc()`, `graphql_query()`, `graphql_mutation()`
- JWT decode (unverified) and validation
- Rich console logging (`log_info`, `log_critical`, etc.)

**Exception**: `Enumerator` and `AuthExploiter` do NOT inherit from BaseModule — they manage their own sessions.

### v3 Modules — Design Principles

The v3 modules (`webhook_poisoner`, `review_injector`, `rpc_abuser`, `token_forger`) must be **fully generic**:
- **Auto-discover** targets via GraphQL introspection — never hardcode table names, RPC names, or field names
- **Classify by keyword pattern** (e.g., "cleanup" → evidence_destruction, "credit" → financial)
- **Schema-aware**: introspect INSERT/UPDATE input types, map fields by naming convention (user_id, content, title, etc.)
- **Cleanup support**: every module that creates data must have a `cleanup()` method

### CLI Dispatch

`supahunt.py` uses argparse with subparsers. Common args are in a shared parent parser. Each subcommand maps to a `cmd_*()` function via a dict at the bottom of the file. New commands need:
1. Subparser in `build_parser()`
2. `cmd_*()` handler function
3. Entry in the `commands` dict
4. Integration into `cmd_full()` if it should run in the kill chain

### Key Supabase Concepts

- **Anon key**: Public JWT embedded in client-side JS — grants access governed by RLS policies
- **Service role key**: Admin JWT that bypasses all RLS — catastrophic if leaked
- **RLS (Row Level Security)**: Per-table policies that should restrict access. Zero RLS = anyone with anon key can read/write
- **GraphQL via pg_graphql**: Supabase exposes `/graphql/v1` — mutations follow pattern `insertInto{table}Collection`, `update{table}Collection`, `deleteFrom{table}Collection`
- **Aliased mutations**: Supabase limits UPDATE/DELETE to 1 record per mutation. Bypass: use GraphQL aliases (`u0:update...Collection(...) u1:update...Collection(...)`) — up to ~25 per request
- **RPC functions**: PostgreSQL functions exposed via `/rest/v1/rpc/{name}` — dangerous when `SECURITY DEFINER` without auth checks

## Important Conventions

- Dependencies are minimal: `requests`, `rich`, `urllib3` only
- Max line length: 120 (flake8 config in CI)
- No target-specific data in source code — the tool must work against any Supabase project
- `output/` is gitignored — never commit scan results, exfil data, or reports
- XSS payloads use `CALLBACK` as placeholder, replaced at runtime with user-provided `--callback-url`
- GraphQL BigFloat fields (numeric) must be passed as strings in mutations (e.g., `rating:"1"` not `rating:1`)
