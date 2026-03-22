# SupaHunt

Supabase Security Auditing & Penetration Testing Framework.

## Install

```bash
pip install requests rich
```

## Usage

```bash
# Auto-discover Supabase from any URL
python3 supahunt.py discover https://target.com

# Full automated scan (recon only)
python3 supahunt.py scan https://target.com

# Enumerate tables, RPCs, storage, GraphQL
python3 supahunt.py enum https://target.com

# Run exploitation modules
python3 supahunt.py exploit https://target.com

# Mass data exfiltration
python3 supahunt.py exfil https://target.com

# Full kill chain (discover → enum → exploit → exfil → report)
python3 supahunt.py full https://target.com

# With known Supabase config (skip discovery)
python3 supahunt.py full https://target.com \
  --supabase-url https://xxxxx.supabase.co \
  --anon-key eyJhbGci...

# With existing auth token
python3 supahunt.py enum https://target.com --token eyJhbGci...

# Through Burp proxy
python3 supahunt.py full https://target.com --proxy http://127.0.0.1:8080
```

## Modules

| Module | Description |
|--------|-------------|
| `discovery` | Auto-detect Supabase URL + anon key from HTML/JS bundles |
| `enumerator` | Enumerate tables (GraphQL + brute-force), RPCs, storage buckets |
| `exploiter` | JWT injection, profile manipulation, RPC abuse, persistence |
| `reporter` | Generate Markdown + JSON reports with findings |

## Attack Coverage

- Supabase anon key extraction from JS bundles
- Service role key detection
- Auth settings disclosure (autoconfirm, providers)
- GraphQL introspection + full schema extraction
- Table enumeration with record counts
- RLS policy testing (CRUD per table)
- RPC function discovery + dangerous function testing
- JWT claim injection via user_metadata
- Profile field manipulation (XSS, privilege flags)
- Role escalation testing
- OAuth backdoor planting
- Mass data exfiltration with progress tracking
- Storage bucket enumeration + file listing

## Nuclei Templates

```bash
nuclei -t templates/supabase-misconfig.yaml -u https://target.com -var anon_key=eyJ...
```

## Output

Reports saved as Markdown + JSON in `./output/`:
- `supahunt-{ref}-{timestamp}.md`
- `supahunt-{ref}-{timestamp}.json`
- `exfil/{table_name}.json` (exfiltrated data)
