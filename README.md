# Termius MCP

stdio MCP server for [Termius](https://termius.com/) Cloud.

This tree talks to **Termius desktop 10.0.6** APIs:

- Device login (`/api/v3.3/auth/device/login/`) with `DeviceToken` auth
- Desktop request headers (`X-DEVICE-APP-VERSION`, `X-DEVICE-PLATFORM`)
- SRP / Socket.IO login for accounts on encryption schema v5
- RNCryptor (v3) and Sodium XChaCha20-Poly1305 (v4/v5) field encryption
- `v4/terminal/sync/` with fallback to `v3/terminal/bulk/`
- Host passwords, key passphrases, and extra SSH settings from the app

There is no human CLI. `termius` only speaks MCP on stdin/stdout.

## Install

```bash
python3 -m venv ~/.local/share/termius-cli
~/.local/share/termius-cli/bin/pip install -U pip
~/.local/share/termius-cli/bin/pip install -e .
ln -sf ~/.local/share/termius-cli/bin/termius ~/.local/bin/termius
```

Python 3.9+ is required. On Debian/Ubuntu (PEP 668) do not use system `pip`;
use a venv as above, or `pipx install -e .`.

## MCP client

```bash
termius
```

Example Claude / generic MCP config (`contrib/mcp/termius.mcp.json`):

```json
{
  "mcpServers": {
    "termius": {
      "command": "termius",
      "args": []
    }
  }
}
```

Example Codex config (`contrib/mcp/codex.toml`, merge into `~/.codex/config.toml`):

```toml
[mcp_servers.termius]
command = "termius"
args = []
startup_timeout_sec = 30.0
tool_timeout_sec = 60.0
```

Optional environment variables:

| Variable | Purpose |
| --- | --- |
| `TERMIUS_VAULT_PASSWORD` | Vault encryption password (preferred over the remember file) |
| `TERMIUS_SYNC_TTL` | Seconds before the next automatic pull. Default `60`. `0` pulls on every read. |

## Tools

Call `status` first.

| Tool | Purpose |
| --- | --- |
| `status` | Login state, last sync, stale flag, vault remembered, counts. Does not pull. |
| `login` | `method=email` with username + password, or `method=google` to get an SSO URL |
| `login_complete` | Finish Google SSO with `callback_url` + vault password |
| `logout` | Clear the session, remembered password, and local inventory |
| `sync` | Force a cloud pull now |
| `hosts` | List hosts (optional `query`) |
| `host` | One host + merged SSH settings + `ssh_command` |
| `exec` | Run a remote command over SSH |
| `inventory` | `kind=groups\|identities\|keys\|snippets` |

`hosts`, `host`, `exec`, and `inventory` pull automatically when the local cache is older than `TERMIUS_SYNC_TTL` and a vault password is available.

`login` / `sync` with `remember=true` (the default) writes `~/.termius/vault` mode `0600`. The process never returns that password in a tool result.

## Google SSO

1. Call `login` with `method=google`.
2. Open the returned URL on any device. Sign in with Google.
3. Paste `termius://app/continue-sso?email=...&firebaseToken=...&requestId=...` into `login_complete` with the **vault encryption password** (the one from the Termius app, not the Google password).

Google only proves identity. The Firebase callback is valid for about an hour.

## Local data

After a successful pull, decrypted inventory lives in:

- `~/.termius/config` — DeviceToken, salts, `last_synced`
- `~/.termius/storage` — hosts, groups, identities, keys, snippets (plaintext JSON)
- `~/.termius/ssh_keys/` — private key files
- `~/.termius/vault` — remembered vault password, if you chose `remember`

Treat that directory as secret.

## Encryption notes

Termius Cloud currently has two personal encryption schemas:

- **v3** — per-field RNCryptor (AES-CBC + HMAC). REST login is enough.
- **v5** — entity `content` blobs sealed with Argon2id + XChaCha20-Poly1305, plus SRP login.

The server auto-detects ciphertext version (`A…` = v3, `B…` = v5). Login uses
gRPC/SRP first (desktop `login_v2`); REST is only the fallback for accounts
that are not migrated (`NOT_MIGRATED`). For v5 SRP the vault password is Argon2id-hashed (libsodium interactive,
16-byte salt) and base64-encoded, then proven with Botan SRP-6a
``modp/srp/8192`` + **Blake2b-512**. ``public_data`` / ``proof`` are
uppercase hex **without** a ``0x`` prefix (Android ``libtermius`` strips
Botan's prefix before the gRPC/Socket.IO payload).

Team vaults: `sync` / auto-pull loads `/api/v4/team/vault/keys/`, unwraps each `encrypted_with` key with the personal X25519 keypair (ECDH + HChaCha20 + XChaCha20-Poly1305), and decrypts shared hosts/keys/identities. Entities whose vault key is missing are skipped, not deleted.

## License

See [LICENSE](LICENSE).
