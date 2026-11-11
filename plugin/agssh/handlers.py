"""Tool handlers for the agssh plugin plus the shared session state.

Module attrs (EX, EX_PATH, HOSTS, BOOT_ERRORS, TOOL_NAMES, MODE) are filled
by agssh.register() once per process; handlers read them at call time so a
re-register simply rebinds. Every Hermes import is lazy inside functions:
this module must import cleanly outside Hermes (tests stub agent.redact,
tools.approval_detection and tools.approval in sys.modules).
"""

import importlib.util
import json
import os
import shutil

from . import guard

MAX_RESULT_CHARS = 100_000
DEFAULT_TIMEOUT_S = 180

EX = None          # executor module (persist-ssh) or None when missing
EX_PATH = ""       # resolved executor path, for the "executor missing" row
HOSTS = {}         # boot-validated registry hosts {alias: info}
BOOT_ERRORS = {}   # {alias: str} hosts skipped at register time
TOOL_NAMES = {}    # {alias: registered tool name or None}
MODE = None        # "per-host" | "generic" | None


def executor_path():
    """Executor file path: $AGSSH_EXECUTOR, then the vendored sibling
    executor.py (self-contained default), then the persist-ssh skill copy
    as a last resort."""
    override = os.environ.get("AGSSH_EXECUTOR")
    if override:
        return override
    vendored = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "executor.py")
    if os.path.isfile(vendored):
        return vendored
    return os.path.expanduser(
        "~/.hermes/skills/devops/persistent-ssh/scripts/persist-ssh.py")


def load_executor():
    """Import the executor by path and stamp AGSSH_VIA="tool" so its audit
    lines show the plugin path. Raises on a missing or unloadable file."""
    path = executor_path()
    spec = importlib.util.spec_from_file_location("persist_ssh", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.AGSSH_VIA = "tool"
    return mod


def ssh_available():
    """check_fn: the local ssh binary is the only hard requirement."""
    return shutil.which("ssh") is not None


def _envelope(output="", exit_code=-1, host="", cwd=None, duration_ms=0,
              truncated=False, full_output_path=None, error=None):
    return {
        "output": output,
        "exit_code": exit_code,
        "host": host,
        "cwd": cwd,
        "duration_ms": int(duration_ms),
        "truncated": bool(truncated),
        "full_output_path": full_output_path,
        "error": error,
    }


def _json(envelope):
    return json.dumps(envelope, ensure_ascii=False)


def _audit(host, exit_code, duration_ms, chars, truncated, via, command):
    """Handler-side audit (denials); executed calls are audited inside the
    executor itself. Never raises into the call path."""
    if EX is None:
        return
    try:
        EX.audit_call(host, exit_code, duration_ms, chars, truncated,
                      via, command)
    except Exception:
        pass


# --------------------------------------------------------------------------
# Schemas
# --------------------------------------------------------------------------

def _command_parameters(host_enum=None):
    props = {}
    required = []
    if host_enum is not None:
        if host_enum:
            props["host"] = {
                "type": "string",
                "enum": list(host_enum),
                "description": "Registry alias of the remote host",
            }
        else:
            props["host"] = {
                "type": "string",
                "description": ("Registry alias of the remote host "
                                "(no hosts configured yet — run `agssh "
                                "add-host <alias> --host H --key K` first)"),
            }
        required.append("host")
    props["command"] = {
        "type": "string",
        "description": "The shell command to execute on the remote host",
    }
    required.append("command")
    props["workdir"] = {
        "type": "string",
        "description": "Absolute working directory for this command only",
    }
    props["timeout"] = {
        "type": "integer",
        "description": ("Max seconds (default 180, max 600). Remote process"
                        " is killed, not just the local ssh."),
        "minimum": 1,
        "maximum": 600,
        "default": DEFAULT_TIMEOUT_S,
    }
    return {"type": "object", "properties": props, "required": required}


def host_tool_schema(alias, info):
    """Per-host `agssh-<alias>` schema (per-host mode, <= 10 tool hosts)."""
    info = info or {}
    user = info.get("user") or "unknown"
    ip = info.get("host") or "unknown"
    shell = "bash -lc" if info.get("login_shell", True) else "bash -c"
    return {
        "name": f"agssh-{alias}",
        "description": (
            f"Run a shell command on {alias} ({user}@{ip}) over SSH. "
            "Byte-exact command transmission, real remote exit code, output "
            "capped at 96k chars. Login shell (" + shell + "). No pty, no "
            "background jobs: interactive prompts fail rather than hang. "
            "workdir is per-call, never sticky. Do not append pipes or "
            "tail: exit_code is the remote status. Registry edits need a "
            "new session; new hosts: `agssh add-host` then a new "
            "session."),
        "parameters": _command_parameters(),
    }


def generic_tool_schema(aliases):
    """Single `agssh` schema (catalog mode default / >10 tool hosts):
    host is a JSON Schema enum of validated aliases, or a plain string
    with an onboarding hint when the registry is empty."""
    if aliases:
        desc = (
            "Run a shell command on a registered SSH host (host picks the "
            "registry alias). Byte-exact command transmission, real remote "
            "exit code, output capped at 96k chars. No pty, no background "
            "jobs: interactive prompts fail rather than hang. workdir is "
            "per-call, never sticky. Do not append pipes or tail: "
            "exit_code is the remote status. Registry edits need a new "
            "session; new hosts: `agssh add-host` then a new session.")
    else:
        desc = (
            "Run a shell command on a registered SSH host. No hosts are "
            "configured yet: add one with `agssh add-host <alias> --host H "
            "--user U --key K` (or `agssh-hosts` to see aliases your "
            "~/.ssh/config already names), then start a new session. "
            "Byte-exact command transmission, real remote exit code, "
            "output capped at 96k chars. No pty, no background jobs.")
    return {
        "name": "agssh",
        "description": desc,
        "parameters": _command_parameters(host_enum=list(aliases)),
    }


READ_SCHEMA = {
    "name": "agssh-read",
    "description": (
        "Read lines from a file on a registered SSH host (remote sed -n). "
        "path must be absolute; offset is 1-based; limit caps at 2000 "
        "lines. Real remote exit code."),
    "parameters": {
        "type": "object",
        "properties": {
            "host": {"type": "string",
                     "description": "Registry alias of the remote host"},
            "path": {"type": "string",
                     "description": "Absolute path on the remote host"},
            "offset": {"type": "integer", "minimum": 1, "default": 1,
                       "description": "1-based first line to read"},
            "limit": {"type": "integer", "minimum": 1, "maximum": 2000,
                      "default": 2000,
                      "description": "Max lines to read (1-2000)"},
        },
        "required": ["host", "path"],
    },
}

FIND_SCHEMA = {
    "name": "agssh-find",
    "description": (
        "Recursive grep on a registered SSH host (grep -n -E -r). path "
        "defaults to the host's default_workdir. A no-match grep returns "
        "exit_code 0 with empty output; grep errors surface as their "
        "status. Real remote exit code."),
    "parameters": {
        "type": "object",
        "properties": {
            "host": {"type": "string",
                     "description": "Registry alias of the remote host"},
            "pattern": {"type": "string",
                        "description": "Extended regex to search for"},
            "path": {"type": "string",
                     "description": ("Directory or file to search "
                                     "(default: host default_workdir)")},
            "file_glob": {"type": "string",
                          "description": ("Only search files matching this "
                                          "glob (grep --include)")},
            "context": {"type": "integer", "minimum": 0, "maximum": 20,
                        "default": 0,
                        "description": "Context lines around each match"},
            "limit": {"type": "integer", "minimum": 1, "maximum": 200,
                      "default": 50,
                      "description": "Max matching lines kept (1-200)"},
        },
        "required": ["host", "pattern"],
    },
}

HOSTS_SCHEMA = {
    "name": "agssh-hosts",
    "description": (
        "List the agssh host registry: alias, as_tool, the command tool "
        "registered this session, boot errors, ControlMaster socket state "
        "and notes; then Host aliases discovered in ~/.ssh/config that are "
        "not registered yet (read-only). Makes no connection."),
    "parameters": {"type": "object", "properties": {}},
}


# --------------------------------------------------------------------------
# Output pipeline: redact -> spill -> serialized cap
# --------------------------------------------------------------------------

def _redact_spill(envelope, redact, command):
    """Rewrite the executor's spill file with redacted content, mode 0600.
    An unreadable spill is dropped (never a dangling unredacted file); a
    redact failure propagates to apply_model_cap's discard path."""
    spill = envelope.get("full_output_path")
    if not spill:
        return
    try:
        with open(spill, encoding="utf-8", errors="replace") as f:
            raw = f.read()
    except OSError:
        try:
            os.remove(spill)
        except OSError:
            pass
        envelope["full_output_path"] = None
        return
    redacted = redact(raw, command)
    fd = os.open(spill, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.fchmod(fd, 0o600)
    except OSError:
        pass
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(redacted)


def _discard_unredacted(envelope):
    """Redaction unavailable: the command already ran, so the unredacted
    output and spill must not survive. Keeps a remote exit_code >= 0."""
    spill = envelope.get("full_output_path")
    if spill:
        try:
            os.remove(spill)
        except OSError:
            pass
    code = envelope.get("exit_code", -1)
    code = code if isinstance(code, int) and code >= 0 else -1
    alias = envelope.get("host") or ""
    envelope["output"] = ""
    envelope["exit_code"] = code
    envelope["full_output_path"] = None
    envelope["error"] = (f"redaction unavailable for '{alias}'; command"
                         f" already ran (exit {code}); output discarded")


def _fit_serialized(envelope):
    """Trim output's tail until json.dumps(envelope) <= MAX_RESULT_CHARS,
    so the 100k stored-result budget never swaps the envelope for a
    preview that hides exit_code."""
    while envelope.get("output"):
        size = len(json.dumps(envelope, ensure_ascii=False))
        if size <= MAX_RESULT_CHARS:
            break
        excess = size - MAX_RESULT_CHARS
        out = envelope["output"]
        envelope["output"] = out[:-excess] if excess < len(out) else ""
    return envelope


def apply_model_cap(envelope, command=None):
    """Model-facing pipeline: redact output via agent.redact
    (redact_terminal_output), redact the spill in place, then fit the
    serialized envelope under 100_000 chars. If the redact import or call
    raises, output is discarded and the executor-written spill deleted."""
    try:
        from agent.redact import redact_terminal_output
        envelope["output"] = redact_terminal_output(
            envelope.get("output") or "", command)
        _redact_spill(envelope, redact_terminal_output, command)
    except Exception:
        _discard_unredacted(envelope)
    return _fit_serialized(envelope)


# --------------------------------------------------------------------------
# Handlers
# --------------------------------------------------------------------------

def tool_name_for(alias):
    """Tool name shown to the approval gate: per-host name in per-host
    mode, the generic `agssh` otherwise."""
    if MODE == "per-host" and alias:
        return f"agssh-{alias}"
    return "agssh"


def handle_host(args, **kwargs):
    """agssh-<alias> / generic agssh: guard_command, execute, cap."""
    args = args or {}
    alias = args.get("host")
    command = args.get("command")
    try:
        deny = guard.guard_command(tool_name_for(alias), command,
                                   alias=alias)
        if deny is not None:
            _audit(str(alias or ""), -1, 0, len(command or ""), False,
                   "tool", command)
            return _json(apply_model_cap(deny, command))
        env = EX.execute(alias, command,
                         workdir=args.get("workdir"),
                         timeout_s=args.get("timeout", DEFAULT_TIMEOUT_S))
        return _json(apply_model_cap(env, command))
    except Exception as exc:
        return _json(_envelope(host=str(alias or ""), error=str(exc)))


def make_host_handler(alias):
    """Per-host closure injecting the alias as args['host'] (per-host
    mode has no `host` parameter in the schema)."""
    def _handle(args, **kwargs):
        return handle_host({**(args or {}), "host": alias}, **kwargs)
    return _handle


def handle_read(args, **kwargs):
    """agssh-read: remote `sed -n <offset>,<offset+limit-1>p -- <path>`."""
    args = args or {}
    host = args.get("host")
    try:
        path = args.get("path")
        if not isinstance(path, str) or not os.path.isabs(path):
            return _json(_envelope(host=str(host or ""),
                                   error="path must be absolute"))
        argv = EX.read_argv(path, args.get("offset", 1),
                            args.get("limit", 2000))
        env = EX.execute(host, argv)
        return _json(apply_model_cap(
            env, " ".join(str(part) for part in argv)))
    except Exception as exc:
        return _json(_envelope(host=str(host or ""), error=str(exc)))


def _host_info(host):
    """Host info: session-validated registry first, live file second so
    as_tool=false / boot-failed entries still resolve default_workdir."""
    if host in HOSTS:
        return HOSTS.get(host)
    try:
        return (EX.load_config().get("hosts") or {}).get(host)
    except Exception:
        return None


def handle_find(args, **kwargs):
    """agssh-find: remote `grep -n -E -r`, status 1 remapped to a clean
    empty result, first `limit` matching lines kept."""
    args = args or {}
    host = args.get("host")
    try:
        pattern = args.get("pattern")
        if not isinstance(pattern, str) or not pattern:
            return _json(_envelope(
                host=str(host or ""),
                error="pattern must be a non-empty string"))
        path = args.get("path")
        if not path:
            path = (_host_info(host) or {}).get("default_workdir")
        if not path:
            return _json(_envelope(
                host=str(host or ""),
                error=f"path required for 'find' on '{host}'"
                      " (no default_workdir)"))
        argv = EX.find_argv(pattern, path, args.get("file_glob"),
                            args.get("context", 0))
        env = EX.execute(host, argv)
        env = EX.find_result(env, args.get("limit", 50))
        return _json(apply_model_cap(
            env, " ".join(str(part) for part in argv)))
    except Exception as exc:
        return _json(_envelope(host=str(host or ""), error=str(exc)))


def _render_table(headers, rows):
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))
    lines = ["  ".join(h.ljust(widths[i]) for i, h in enumerate(headers)),
             "  ".join("-" * w for w in widths)]
    lines += ["  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row))
              for row in rows]
    if not rows:
        lines.append("(no hosts in registry)")
    return "\n".join(lines)


def _ssh_config_aliases():
    """Host aliases from ~/.ssh/config (and missing-file tolerant).

    `Host` entries name connection profiles a user already maintains;
    wildcard patterns (* ?) and negations are skipped since they are not
    addable aliases. Read-only: nothing here is registered or connected."""
    path = os.path.expanduser("~/.ssh/config")
    aliases = []
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                words = line.split()
                if len(words) >= 2 and words[0].lower() == "host":
                    for alias in words[1:]:
                        if not any(c in alias for c in "*?!"):
                            aliases.append(alias)
    except OSError:
        return []
    return aliases


def handle_hosts(args, **kwargs):
    """agssh-hosts: registry table (alias, as_tool, this session's tool
    name, boot error, socket state, notes), then unregistered
    ~/.ssh/config Host aliases. Makes no connection."""
    try:
        if EX is None:
            return _json(_envelope(output=f"executor missing: {EX_PATH}",
                                   exit_code=0, host=""))
        hosts = (EX.load_config().get("hosts") or {})
        rows = []
        for alias in sorted(hosts):
            info = hosts.get(alias) or {}
            try:
                state = EX.socket_state(alias, info)
            except Exception:
                state = "unknown"
            rows.append([
                str(alias),
                "yes" if info.get("as_tool", True) != False else "no",
                str(TOOL_NAMES.get(alias) or "-"),
                state,
                str(BOOT_ERRORS.get(alias) or "-"),
                str(info.get("notes") or "-"),
            ])
        output = _render_table(
            ["alias", "as_tool", "tool", "socket", "boot_error", "notes"],
            rows)
        discovered = [a for a in _ssh_config_aliases() if a not in hosts]
        if discovered:
            output += ("\n\n~/.ssh/config Host aliases (not registered — "
                       "`agssh add-host <alias> --host H` to add):\n  "
                       + "\n  ".join(sorted(discovered)))
        return _json(apply_model_cap(
            _envelope(output=output, exit_code=0, host="")))
    except Exception as exc:
        return _json(_envelope(host="", error=str(exc)))
