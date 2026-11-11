# Public surface — private Hermes imports

agssh deliberately imports three **private** Hermes core modules. The catalog validator warns on
private imports; for agssh that warning is **expected** and documented here. Each import is
justified below with its fail-closed fallback and the public seam that should replace it. Removal
waits on those seams, tracked upstream against the Hermes plugin API (the operator files the issue).

## Import discipline

Every Hermes import happens **inside a function**, never at module top. `agssh/__init__.py`,
`agssh/handlers.py` and `agssh/guard.py` therefore import cleanly in a bare interpreter — the plugin
loads, validates and its test suite runs without Hermes internals. If a private module is absent or
changes shape, only the call that needed it fails, and it fails closed.

## 1. `tools.approval_detection` — dangerous/hardline classification

- **Import site:** `agssh/guard.py::guard_command` —
  `from tools.approval_detection import detect_dangerous_command, detect_hardline_command`.
- **Why it is used:** agssh inherits Hermes' command classification rather than shipping its own
  blocklist. A command that would be denied in a local `terminal` call is denied through agssh, and
  a dangerous command escalates the same way. One classifier means terminal and remote policy cannot
  drift apart.
- **Fail-closed fallback:** any import or call failure returns a denial envelope
  (`exit_code: -1`, `error: "approval subsystem unavailable"`). The command does not run.
- **Public seam needed:** a ctx-declared approval/danger classifier hook for plugins — e.g.
  `ctx.classify_command(command) -> (tier, description)` — so plugins inherit the policy without
  importing `tools.*`.

## 2. `tools.approval` — the human approval gate

- **Import site:** `agssh/guard.py::guard_command` —
  `from tools.approval import request_tool_approval`.
- **Why it is used:** dangerous-but-allowed commands must reach the same human gate Hermes terminal
  commands use — session and permanent allowlists, the CLI prompt, and gateway pending approvals —
  under the tool's own name. Inventing a second approval system would split the operator's
  allowlists and audit trail.
- **Fail-closed fallback:** any import or call failure returns the same denial envelope as above.
  No approval path, no execution.
- **Public seam needed:** a documented `ctx.request_approval(tool, reason)` plugin API that routes
  to the Hermes gate.

## 3. `agent.redact` — model-facing output redaction

- **Import site:** `agssh/handlers.py::apply_model_cap` —
  `from agent.redact import redact_terminal_output`.
- **Why it is used:** remote command output gets the same secret-redaction pass terminal output gets
  before it reaches the model — and the local spill file (`full_output_path`) is rewritten in place
  with the redacted text, so secrets do not sit on disk either.
- **Fail-closed fallback:** the command has already run, so the unredacted output and spill must not
  survive: the spill file is deleted, `output` is cleared, and the envelope keeps a non-negative
  remote `exit_code` with an explanatory `error`. Nothing unredacted is returned or left on disk.
- **Public seam needed:** a ctx- or tools-provided output-redaction function (e.g.
  `ctx.redact_output(text, command)`).

## Validator note

Do not "fix" the private-import warning by deleting these imports — each fallback would be strictly
less safe (a parallel blocklist that drifts from terminal policy, a second approval system, or
unredacted output reaching the model). The correct resolution is the public seams above; the warning
is expected until they land.

## Security-scan caution: `ssh_dir_access`

The install scanner also reports `caution` findings for reads under `~/.ssh/` — private-key paths
from the registry, `~/.ssh/config` Host-alias discovery in `agssh-hosts`, and the ControlMaster
socket files under `~/.ssh/cm-*`. These reads are the plugin's function (SSH is the product), not
credential harvesting: key paths are only ever passed to the local `ssh` binary, never read into
model output, and `~/.ssh/config` parsing yields alias names only. The caution is expected and
documented for reviewers.
