"""Approval gate for host commands plus the raw-ssh pre_tool_call block (B11).

Hermes imports stay lazy inside functions so this module loads cleanly
outside a Hermes process (tests stub tools.approval_detection /
tools.approval). Shared session state arrives through configure() from
agssh.register(); no import cycle back into the package __init__.
"""

import os
import re
import shlex

SSH_ARG_FLAGS = {"-i", "-p", "-o", "-F", "-J", "-l", "-c", "-b", "-D",
                 "-L", "-R", "-W", "-w", "-S", "-E", "-B"}

_CTX = None       # PluginContext, for ctx.get_config("block_raw_ssh", ...)
_MODE = None      # "per-host" | "generic" | None (executor missing)
_TOOL_HOSTS = {}  # {alias: info} for aliases that own a command tool now

_SEGMENT_SPLIT = re.compile(r"[;|&\n]+")


def configure(ctx, mode, tool_hosts):
    """Bind session state once per register(): the plugin context, the
    registration mode and the {alias: info} map of hosts that received a
    command tool this session (the set B11 blocks raw ssh against)."""
    global _CTX, _MODE, _TOOL_HOSTS
    _CTX = ctx
    _MODE = mode
    _TOOL_HOSTS = dict(tool_hosts or {})


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


def _argv(segment):
    try:
        return shlex.split(segment)
    except ValueError:
        return segment.split()


def _ssh_dest(argv):
    """Destination token of an `ssh ...` argv (argv[0] already consumed).

    Flags in SSH_ARG_FLAGS consume the next token too; other dash tokens
    consume only themselves; after `--` the next token is the destination;
    otherwise the first non-flag token is it."""
    i = 1
    while i < len(argv):
        tok = argv[i]
        if tok == "--":
            return argv[i + 1] if i + 1 < len(argv) else None
        if tok in SSH_ARG_FLAGS:
            i += 2
            continue
        if tok.startswith("-") and len(tok) > 1:
            i += 1
            continue
        return tok
    return None


def _dest_alias(dest, hosts):
    """Alias whose registry entry `dest` names, else None. Matches the
    alias itself, the registry host, {user}@{host}, {host}:{port},
    {user}@{alias} and any other {anything}@{alias}."""
    for alias, info in (hosts or {}).items():
        info = info or {}
        if dest == alias:
            return alias
        host = str(info.get("host") or "")
        user = info.get("user")
        port = info.get("port", 22)
        if host and dest == host:
            return alias
        if user and host and dest == f"{user}@{host}":
            return alias
        if host and port is not None and dest == f"{host}:{port}":
            return alias
        if "@" in dest and dest.rsplit("@", 1)[1] == alias:
            return alias
    return None


def _segment_dest(segment, hosts, descend):
    """Match a single command segment. `descend` allows exactly one hop
    into a bash/sh -c|-lc argument; the inner segment is parsed but never
    descended again."""
    argv = _argv(segment)
    if not argv:
        return None
    base = os.path.basename(argv[0])
    if descend and base in ("bash", "sh"):
        for i, tok in enumerate(argv[1:], start=1):
            if tok in ("-c", "-lc"):
                if i + 1 < len(argv):
                    return _segment_dest(argv[i + 1], hosts, descend=False)
                return None
        return None
    if base != "ssh":
        return None
    dest = _ssh_dest(argv)
    if dest is not None and _dest_alias(dest, hosts) is not None:
        return dest
    return None


def find_registered_ssh_dest(command, hosts):
    """First ssh destination in `command` that names a registered host,
    returned as typed, else None. Splits on ';', '|', '&' and newlines;
    descends one level into `bash`/`sh` -c/-lc; parses argv[0] basename
    `ssh` only (scp, sftp, ssh-keygen, `echo ssh ...` never match)."""
    if not isinstance(command, str):
        return None
    for segment in _SEGMENT_SPLIT.split(command):
        dest = _segment_dest(segment, hosts, descend=True)
        if dest is not None:
            return dest
    return None


def guard_command(tool_name, command, alias=None):
    """Pre-execute gate for host command tools: hardline patterns are
    denied outright (never approval-bypassed), dangerous patterns go
    through request_tool_approval. Returns a denial envelope or None to
    proceed. Any failure of the approval subsystem fails closed. The
    caller (handler) audits denials with via="tool"."""
    if alias is None and isinstance(tool_name, str) \
            and tool_name.startswith("agssh-"):
        alias = tool_name[len("agssh-"):]
    if not isinstance(command, str) or not command.strip():
        return None  # execute reports bad_command
    host = str(alias or "")
    try:
        from tools.approval_detection import (
            detect_dangerous_command, detect_hardline_command)
        is_hardline, description = detect_hardline_command(command)
        if is_hardline:
            return _envelope(
                exit_code=-1, host=host,
                error=f"hardline blocked on '{host}': {description}")
        is_dangerous, pattern_key, description = detect_dangerous_command(command)
        if not is_dangerous:
            return None
        from tools.approval import request_tool_approval
        result = request_tool_approval(tool_name, description,
                                       rule_key=pattern_key)
        if result.get("approved"):
            return None
        message = result.get("message") or description
        return _envelope(
            exit_code=-1, host=host,
            error=f"approval denied for '{host}': {message}")
    except Exception:
        return _envelope(
            exit_code=-1, host=host,
            error=f"approval denied for '{host}':"
                  " approval subsystem unavailable")


def on_pre_tool_call(tool_name, args, **kwargs):
    """pre_tool_call hook (B11): veto `terminal` commands that ssh to a
    host which owns an agssh command tool this session. Disabled by
    plugins.entries.agssh.settings.block_raw_ssh: false."""
    if tool_name != "terminal":
        return None
    ctx = _CTX
    enabled = True if ctx is None else bool(
        ctx.get_config("block_raw_ssh", True))
    if not enabled or not isinstance(args, dict):
        return None
    command = args.get("command")
    if not isinstance(command, str):
        return None
    dest = find_registered_ssh_dest(command, _TOOL_HOSTS)
    if dest is None:
        return None
    alias = _dest_alias(dest, _TOOL_HOSTS) or dest
    if _MODE == "generic":
        message = (f"use agssh(host='{alias}', ...) instead of ssh to"
                   f" '{dest}'. terminal ssh to a registered host is"
                   " blocked.")
    else:
        message = (f"use agssh-{alias} instead of ssh to '{dest}'."
                   " terminal ssh to a registered host is blocked.")
    return {"action": "block", "message": message}
