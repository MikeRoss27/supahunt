# Contributing to SupaHunt

## How to Contribute

### New Attack Modules
Found a new Supabase attack pattern? Submit a PR:
1. Add the technique to the relevant module in `modules/`
2. Update `README.md` with the new capability
3. Add a Nuclei template in `templates/` if applicable

### Bug Reports
Open an issue with:
- Python version
- Command used
- Error output
- Target type (Next.js, Vite, React, etc.)

### Nuclei Templates
Add new `.yaml` files to `templates/`. Follow the existing format with proper `info` metadata.

## Guidelines

- **No real target data** in PRs (URLs, keys, credentials, PII)
- Use `https://target.com` or `https://xxxxx.supabase.co` as examples
- Keep dependencies minimal (only `requests` + `rich`)
- Test your changes before submitting
- Follow existing code style

## PR Process

1. Fork the repo
2. Create a feature branch (`git checkout -b feature/new-attack`)
3. Commit your changes
4. Push and open a PR against `main`
