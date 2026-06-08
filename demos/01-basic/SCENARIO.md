# Demo 01 - Basic: guarding an agent's tool-calls

This demo shows TOOLGUARD auditing a batch of tool-calls that an AI agent
wants to make, against the built-in default policy.

The built-in policy:

- **Denylist** (always blocked): `shell_exec`, `delete_file`
- **Allowlist** (only these run when `default_action=deny`): `read_file`,
  `list_dir`, `web_search`, `http_get`
- **Argument guards**:
  - `http_get.url` may not target localhost / link-local / cloud-metadata
    (SSRF protection).
  - `read_file.path` may not touch `/etc/shadow`, `.ssh/`, `.env`, `id_rsa`.
- **Redaction**: argument values containing API keys / secrets / passwords /
  `sk-...` tokens are masked before the call is allowed through.

## Input

`calls.json` is a realistic trace of what an agent attempted in one turn:
a safe file read, a legitimate web fetch, an SSRF attempt at the cloud
metadata endpoint, a destructive `delete_file`, a path-traversal read of
`id_rsa`, and a `web_search` whose query leaked an API key.

## Run it

```sh
# Table summary; exits non-zero because some calls are denied.
python -m toolguard audit --input demos/01-basic/calls.json

# Full machine-readable decisions (what an agent runtime would consume).
python -m toolguard --format json audit --input demos/01-basic/calls.json

# Check a single call ad-hoc.
python -m toolguard check --tool http_get --arg url=http://169.254.169.254/latest/meta-data
```

## Expected outcome

- `read_file path=README.md` -> **allow**
- `http_get url=https://api.example.com/v1/status` -> **allow**
- `http_get url=http://169.254.169.254/...` -> **deny** (SSRF pattern)
- `delete_file` -> **deny** (denylist)
- `read_file path=~/.ssh/id_rsa` -> **deny** (sensitive path)
- `web_search query="... api_key=sk-..."` -> **redact** (allowed, secret masked)

Process exit code is `2` (denials present), which an agent harness can use
to halt the run.
