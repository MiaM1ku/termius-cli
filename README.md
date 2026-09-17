# Termius CLI

Command-line and MCP interface for [Termius](https://termius.com/) Cloud.

This tree restores the old `termius` CLI against **Termius desktop 10.0.6**:

- Device login (`/api/v3.3/auth/device/login/`) with `DeviceToken` auth
- Desktop request headers (`X-DEVICE-APP-VERSION`, `X-DEVICE-PLATFORM`)
- SRP / Socket.IO login for accounts on encryption schema v5
- RNCryptor (v3) and Sodium XChaCha20-Poly1305 (v4/v5) field encryption
- `v4/terminal/sync/` with fallback to `v3/terminal/bulk/`
- Host passwords, key passphrases, and extra SSH settings from the app
- An MCP server for AI agents

## Install

```bash
python3 -m venv ~/.local/share/termius-cli
~/.local/share/termius-cli/bin/pip install -U pip
~/.local/share/termius-cli/bin/pip install -e .
ln -sf ~/.local/share/termius-cli/bin/termius ~/.local/bin/termius
```

Python 3.9+ is required. On Debian/Ubuntu (PEP 668) do not use system `pip`;
use a venv as above, or `pipx install -e .`.

## Usage

```bash
termius init                         # login, pull, import ssh config, push
termius login -u you@example.com
termius login --google               # print SSO URL, paste termius:// callback
                                     # then enter the vault encryption password
termius pull
termius hosts
termius info myhost
termius ssh-command myhost           # print ssh(1) without connecting
termius connect myhost
termius status
termius export-ssh-config
```

JSON output (already supported by cliff) is the easiest form for agents:

```bash
termius hosts -f json
termius info myhost -f json
```

## MCP server

Run over stdio:

```bash
termius mcp
```

Example Claude / generic MCP config (`contrib/mcp/termius.mcp.json`):

```json
{
  "mcpServers": {
    "termius": {
      "command": "termius",
      "args": ["mcp"]
    }
  }
}
```

Example Codex config (`contrib/mcp/codex.toml`, merge into `~/.codex/config.toml`):

```toml
[mcp_servers.termius]
command = "termius"
args = ["mcp"]
startup_timeout_sec = 30.0
tool_timeout_sec = 60.0
```

Tools:

| Tool | Purpose |
| --- | --- |
| `termius_status` | Login state and inventory counts |
| `termius_hosts` | List hosts |
| `termius_host_info` | One host + generated `ssh` command |
| `termius_ssh_command` | `ssh` command only |
| `termius_identities` | Usernames / key labels (no secrets) |
| `termius_keys` | SSH key labels (no private material) |
| `termius_groups` | Groups |
| `termius_snippets` | Snippets |

Login and pull stay on the CLI (`termius login` / `termius pull`) so credentials are not passed through the MCP session.

Google / SSO accounts:

```bash
termius login --google
```

The CLI **does not open a browser**. It prints:

`https://account.termius.com/sso/desktop?provider=google&request=<uuid>`

Open that on any device, sign in with Google, then paste
`termius://app/continue-sso?email=...&firebaseToken=...&requestId=...`.

```bash
termius login --google --callback-url 'termius://app/continue-sso?email=...&firebaseToken=...&requestId=...'
```

Google only proves identity. Termius then asks for the **vault encryption
password** (the one you set in the Termius app, not your Google password).
The Firebase callback is valid for about an hour; if login says the session
expired, run `termius login --google` again. Do not use `w3m`/`lynx` — they
steal the TTY and cannot show the `termius://` handoff.

## Encryption notes

Termius Cloud currently has two personal encryption schemas:

- **v3** — per-field RNCryptor (AES-CBC + HMAC). REST login is enough.
- **v5** — entity `content` blobs sealed with Argon2id + XChaCha20-Poly1305, plus SRP login.

The CLI auto-detects ciphertext version (`A…` = v3, `B…` = v5). Login uses
gRPC/SRP first (desktop `login_v2`); REST is only the fallback for accounts
that are not migrated (`NOT_MIGRATED`). For v5 SRP the vault password is Argon2id-hashed (libsodium interactive,
16-byte salt) and base64-encoded, then proven with Botan SRP-6a
``modp/srp/8192`` + **Blake2b-512**. ``public_data`` / ``proof`` are
uppercase hex **without** a ``0x`` prefix (Android ``libtermius`` strips
Botan's prefix before the gRPC/Socket.IO payload).

Team vaults: `termius pull` loads `/api/v4/team/vault/keys/`, unwraps each `encrypted_with` key with the personal X25519 keypair (ECDH + HChaCha20 + XChaCha20-Poly1305), and decrypts shared hosts/keys/identities. Entities whose vault key is missing are skipped, not deleted.

## License

See [LICENSE](LICENSE).
