# agssh

SSH hosts as first-class tools for a Hermes agent. Each host in the agssh registry is reachable
through a small, fixed tool surface — run a command, read file lines, recursive-grep, list hosts —
over one persistent multiplexed connection per host, with real remote exit codes and the same human
approval gate Hermes terminal commands use. The model never assembles
`ssh -i key user@host 'quoted string'` again; it calls a tool and gets a JSON envelope back.

## What it does

Every tool call returns the same envelope:

```json
{"output": "...", "exit_code": 0, "host": "web1", "cwd": "/var/www",
 "duration_ms": 42, "truncated": false, "full_output_path": null, "error": null}
```

Execution properties:

- **One ControlMaster connection per host.** All commands multiplex over a single persistent TCP
  connection, so rapid agent calls never consume a new sshd auth slot (`MaxStartups` is a non-issue).
- **Byte-exact quoting.** The command travels as exactly one argv element, quoted once; no nested
  quoting to get wrong.
- **Real remote exit code.** `exit_code` is the remote command's status, never mapped to a transport
  error; transport and executor failures land in `error` instead.
- **Bounded output.** Remote output is capped at 96k chars; the full text spills to a local file
  (`full_output_path`) and the serialized result stays under the 100k stored-result budget.
- **No pty, no background jobs.** Interactive prompts fail fast instead of hanging; on timeout the
  remote process is killed, not just the local `ssh`.
- **Audit log.** Executed calls, denials and boot rejections are appended as JSONL to
  `<HERMES_HOME>/logs/agssh.log` (`~/.hermes` unless `HERMES_HOME` is set).

## Install

Requirements: an OpenSSH client (`ssh` on PATH) and Hermes with plugin support.

**Recommended:**

```
hermes plugins install mosesman831/agssh
hermes plugins enable agssh
```

That is the whole install. The plugin ships its own executor; nothing else on the
machine is modified. Tools appear on the next session.

From a clone (for development):

```
git clone https://github.com/mosesman831/agssh && cd agssh
scripts/install.sh
```

`install.sh` only symlinks `plugin/agssh` into `~/.hermes/plugins/agssh` and `bin/agssh`
into `~/bin/agssh`. It does **not** touch any other skill. If you also run the older
`persist-ssh` skill and want its script to share this executor, that patch is opt-in:
`scripts/install.sh --patch-persist-ssh` (it writes a `.agssh-orig` backup first).

The CLI is optional — the agent tools do not need it — but it is how a human drives the
same executor, and it provides `agssh add-host`.

## Add a host

The registry is per profile: `<hermes-home>/plugin-data/agssh/hosts.json`, created with
mode `0600` on your first `agssh add-host` and never written at plugin load. Older
`~/.config/agssh/hosts.json` and `~/.config/persist-ssh.json` files are merged in
read-only when present — the primary wins per alias.
`AGSSH_REGISTRY` (or `PERSIST_SSH_CONFIG`) overrides the path.

```
agssh add-host web1 --host 192.0.2.10 --user ubuntu --key ~/.ssh/id_ed25519
```

Options: `--user U` (default `root`), `--key K` (default `~/.ssh/id_rsa`), `--port P` (default `22`),
`--workdir D` (default directory for `agssh-find` without a `path`). Without the CLI, write the same
entry into `hosts.json` by hand — it is plain JSON. An entry may set `"as_tool": false` to stay in
the registry without getting a command tool.

Aliases must match `[a-z][a-z0-9-]{0,30}`. At session boot every entry is validated — alias shape,
key exists, is a regular file, carries no group/other permission bits (mode 600). Bad entries are
warned, audited and skipped, never fatal. Registry edits take effect on the next session.

## The tools

### `agssh` — run a command

```python
agssh(host="web1", command="systemctl status nginx", workdir="/var/www", timeout=60)
```

`host` is a JSON Schema enum of the registry's validated aliases (a plain string with an onboarding
hint when the registry is empty). `workdir` is absolute and per-call — never sticky. `timeout` is
1–600 s, default 180; the remote process is killed on expiry. Do not append pipes or `tail` to
recover an exit code — `exit_code` is already the remote status.

### `agssh-read` — read file lines

```python
agssh-read(host="web1", path="/var/log/nginx/error.log", offset=200, limit=100)
```

Remote `sed -n`. `path` must be absolute, `offset` is 1-based, `limit` caps at 2000 lines.

### `agssh-find` — recursive grep

```python
agssh-find(host="db1", pattern="listen_addresses", path="/etc/postgresql",
           file_glob="*.conf", context=2, limit=50)
```

Remote `grep -n -E -r`. `path` defaults to the host's `default_workdir`; `context` max 20; `limit`
max 200 matching lines. A no-match grep returns `exit_code: 0` with empty output.

### `agssh-hosts` — list the registry

```python
agssh-hosts()
```

Registry table (alias, `as_tool`, this session's tool name, socket state, boot errors, notes) plus
`Host` aliases discovered in `~/.ssh/config` that are not registered yet. No arguments; makes no
connection.

## Safety model

- **Hardline commands are refused outright**, using the same classification Hermes applies to
  terminal commands — what a terminal would never run is never run remotely.
- **Dangerous commands escalate to the same human approval gate** Hermes terminal commands use
  (session/permanent allowlists, CLI prompt, gateway pending). Approval inheritance: agssh does not
  invent a second approval system, and any failure of the approval path fails closed.
- **Raw `ssh` to registered hosts is blocked.** A `pre_tool_call` hook vetoes `terminal` commands
  whose ssh destination names a registered host, so remote exit codes and the audit trail stay
  honest. Disable with `plugins.entries.agssh.settings.block_raw_ssh: false`.
- **No pty** means password and host-key prompts fail fast instead of hanging the agent.
- **Boot validation** drops malformed aliases and unreadable or group/world-readable private keys
  before any tool is registered for them.

## Limitations

- Requires an OpenSSH client and key-based auth on every registered host; there are no password
  prompts — a host that demands one fails rather than waits.
- Requires Hermes with plugin support (tool/hook registration, entry settings).
- Commands run as the registry entry's user, with that user's remote privileges; there is no
  additional privilege boundary.
- The raw-ssh block is a policy guard, not a sandbox: `scp`, `sftp`, nested shells and other
  transports bypass it.
- The audit log is best-effort local JSONL — not tamper-proof, and nothing is logged remote-side.
- No file transfer, no port forwarding, no pty, no background jobs.
- The plugin deliberately imports three private Hermes modules (approval classification, the
  approval gate, output redaction); each fails closed when absent. See `docs/PUBLIC-SURFACE.md`.

## Local per-host mode

`plugins.entries.agssh.settings.per_host_tools: true` registers one `agssh-<alias>` tool per host
(up to 10 tool hosts; above that it falls back to the generic tool). The model then picks a tool
name instead of passing a `host` argument.

This is a local-only convenience mode: the registered tool names vary per install, so it cannot
pass catalog validation. The default generic mode always exposes exactly the four declared tools,
and is what catalog installs run.

## Development and testing

```
python -m pytest tests/
```

The suite is unit plus acceptance tests; it stubs the Hermes import surface and exercises the
vendored executor under an isolated `HERMES_HOME`. Integration tests that need a real SSH host run
only when `AGSSH_TEST_HOST` names an alias in your live registry:

```
AGSSH_TEST_HOST=web1 python -m pytest tests/
```

Host details never live in the repo — the alias is resolved from the per-profile registry at
run time.

## License

MIT — see `LICENSE`.
