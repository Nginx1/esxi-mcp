# Contributing

Use Python 3.10+ and install `.[dev]` in a virtual environment. Before opening a pull request, run:

```bash
python -m pytest -q
python scripts/verify_vmomi_contract.py
python -m build
```

Add tests for behavior changes that affect writes, target selection, cleanup or configuration. Preserve dry-run defaults, precise name matching, protected VM checks and omitted resource settings. Use mocks or offline pyVmomi stubs in default tests. Never add ESXi credentials, private keys, live infrastructure inventories or personal client configuration.

Describe the behavior change and test evidence in the pull request. Report vulnerabilities according to [SECURITY.md](SECURITY.md). Contributions are licensed under this project's MIT license.
