# Contributing to SupaHunt

## How to Contribute

### New Attack Modules
Found a new Supabase attack pattern? Submit a PR:
1. Create a new module in `modules/` inheriting from `BaseModule`
2. Make it **generic** — auto-discover targets via GraphQL introspection, don't hardcode table/function names
3. Add the module import to `modules/__init__.py`
4. Add a `cmd_*` handler and CLI subcommand in `supahunt.py`
5. Update `README.md` with the new capability
6. Add a Nuclei template in `templates/` if applicable

### Module Design Guidelines
- **Auto-discover, don't hardcode**: Use GraphQL introspection and REST probing to find tables, RPCs, and schemas at runtime
- **Classify by pattern**: Use keyword matching to categorize discovered items (e.g., "cleanup" -> evidence destruction)
- **Schema-aware**: Introspect INSERT/UPDATE input types to map fields by convention
- **Cleanup support**: Always implement a `cleanup()` method to remove test artifacts
- **Inherit from BaseModule**: Use the provided HTTP helpers, rate limiting, and logging

### Bug Reports
Open an issue with:
- Python version
- Command used
- Error output
- Target type (Next.js, Vite, React, SvelteKit, etc.)

### Nuclei Templates
Add new `.yaml` files to `templates/`. Follow the existing format with proper `info` metadata.

## Guidelines

- **No real target data** in PRs (URLs, keys, credentials, PII)
- Use `https://target.com` or `https://xxxxx.supabase.co` as examples
- Keep dependencies minimal (`requests` + `rich` + `urllib3`)
- Test your changes before submitting
- Follow existing code style
- Don't add target-specific logic — modules must work against any Supabase project

## PR Process

1. Fork the repo
2. Create a feature branch (`git checkout -b feature/new-attack`)
3. Commit your changes
4. Push and open a PR against `main`
