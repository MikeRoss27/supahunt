## What does this PR do?

<!-- Brief description of the change -->

## Type of change

- [ ] New attack module
- [ ] New payload / detection technique
- [ ] Bug fix
- [ ] Nuclei template
- [ ] Documentation
- [ ] Other

## Checklist

- [ ] `python3 -m py_compile` passes on all changed files
- [ ] No real target data (URLs, keys, credentials, PII) in the code
- [ ] New modules inherit from `BaseModule` and use auto-discovery (no hardcoded table/function names)
- [ ] New modules include a `cleanup()` method if they create data
- [ ] Updated `modules/__init__.py` with new imports
- [ ] Updated `README.md` if adding a new command or module
- [ ] Tested against a local or authorized Supabase instance
