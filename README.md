# deamgo/setup

Automation scripts for provisioning a UIPaaS host. Use `go.sh` as the single entry point to download, verify, and execute `setup.sh`.

## Quick start

```bash
curl -fsSL https://raw.githubusercontent.com/deamgo/setup/main/go.sh | sudo bash
```

Optional environment variables:

- `SETUP_REF` - Git ref to pull (branch/commit/tag, default `main`)
- `SETUP_KEEP_FILES=1` - keep the temporary download directory for inspection

## Repository contents

- `setup.sh` - main installation workflow
- `https.sh` - ACME/TLS helper utility
- `nginx/` - default Nginx config and error pages
- `manifest.sha256` - file checksums consumed by `go.sh`
