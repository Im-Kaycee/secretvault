# secretvault

A local, encrypted secrets vault with a tamper-evident audit log. Stores API keys, passwords, and other secrets on disk in encrypted form, and keeps a hash-chained record of every access so tampering with the log can be detected.

## Installation

```bash
cd secretvault
pipx install -e .
```

This registers a `vault` command, usable from any directory.

## Usage

```bash
vault put gemini_api_key "AIzaSy-your-key-here"
vault get gemini_api_key
vault list
vault delete gemini_api_key
vault audit-log
vault verify
vault rotate-master-key
```

On first run, if no master key is found, the vault generates one and prints an `export VAULT_MASTER_KEY=...` line. This needs to be added to your shell profile (`~/.bashrc` or `~/.zshrc`) so the key persists across terminal sessions; it is never stored in the vault's own database file.

## How it works

### Envelope encryption

Each secret is encrypted with its own randomly generated Data Encryption Key (DEK). The DEK is then encrypted ("wrapped") by a single Key Encryption Key (KEK), which is supplied via the `VAULT_MASTER_KEY` environment variable rather than stored in the database.

This two-layer structure is the same pattern used by AWS KMS, Google Cloud KMS, and HashiCorp Vault's transit backend. Its main benefit is cheap key rotation: rotating the KEK only requires re-wrapping each secret's small DEK, not re-encrypting the secret values themselves.

### Tamper-evident audit log

Every `put`, `get`, `delete`, and `rotate-master-key` operation appends an entry to an audit log. Each entry's hash is computed from its own content plus the previous entry's hash, forming a chain. Editing any historical entry breaks its stored hash, and the break propagates forward through every subsequent entry. Running `vault verify` walks the entire chain and reports the first point of divergence, if any.

This guarantees that existing log entries haven't been altered after the fact. It does not guarantee that every action against the vault was logged — that's enforced by the application code always pairing data writes with a log write, not by the hash chain itself. An attacker with direct database access who bypasses the CLI entirely (e.g. editing the `secrets` table directly) would not be caught by chain verification, since no log entry would exist to flag.

### Storage

A single SQLite file at `~/.secretvault/vault.db`, with two tables: `secrets` (path, encrypted value, wrapped DEK) and `audit_log` (the hash chain). SQLite was chosen because this is a single-user, single-machine tool with no concurrent access to manage — a client-server database would be unnecessary overhead here.

## Architecture

```
secretvault/
├── pyproject.toml
└── secretvault/
    ├── crypto.py    # envelope encryption: KEK + per-secret DEK
    ├── storage.py   # SQLite layer for secrets and audit_log tables
    ├── audit.py     # hash-chained logging and verify_chain()
    └── cli.py        # the `vault` command, wires the above together
```

## Known limitations

This is a single-tenant design: any process with `VAULT_MASTER_KEY` set can read any secret stored in the vault, regardless of which project it was originally intended for. There's no per-client authentication or path-scoped access policy, the way HashiCorp Vault implements with its policy engine. For a personal, single-machine tool this is an acceptable tradeoff, but it would need to be addressed before this could safely back multiple, mutually distrusting applications.

The master key itself lives in a shell profile file in plaintext. This is a meaningful improvement over storing secrets in plaintext `.env` files, but a production system would use a hardware security module or cloud-managed key store (e.g. AWS KMS) rather than exposing the raw key to any file at all.