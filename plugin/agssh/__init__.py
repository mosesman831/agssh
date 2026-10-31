"""agssh — persist-ssh registry hosts as native Hermes tools.

register(ctx) only. Load order: executor -> boot-validate every registry
host (bad entries are warned, audited via="boot" and skipped, never
fatal) -> mode switch at 10 validated as_tool hosts (per-host `agssh-<x>`
tools vs one generic `agssh` with a host enum) -> register the command
tools plus agssh-read/-find/-hosts -> bind guard state -> pre_tool_call
hook. agssh-hosts is registered even when the executor file is missing.
"""

import logging
import os
import re
import stat

from . import guard, handlers

logger = logging.getLogger(__name__)

ALIAS_RE = re.compile(r"[a-z][a-z0-9-]{0,30}")
GENERIC_HOST_THRESHOLD = 10


def _boot_error(alias, info):
    """Boot validation: alias shape, then key exists, is a regular file
    after symlink follow, and carries no group/other permission bits."""
    if not ALIAS_RE.fullmatch(str(alias)):
        return (f"alias '{alias}' rejected: must match"
                " [a-z][a-z0-9-]{0,30}")
    key = os.path.expanduser(str((info or {}).get("key") or ""))
    try:
        st = os.stat(key)
    except OSError:
        return (f"key for host '{alias}' not readable: {key}"
                " (expected mode 600)")
    if not stat.S_ISREG(st.st_mode) or stat.S_IMODE(st.st_mode) & 0o077:
        return (f"key for host '{alias}' not readable: {key}"
                " (expected mode 600)")
    return None


def register(ctx):
    """Plugin entry point called by the Hermes plugin loader."""
    ex_path = handlers.executor_path()
    try:
        ex = handlers.load_executor()
    except Exception:
        ex = None
    handlers.EX = ex
    handlers.EX_PATH = ex_path

    if ex is None:
        handlers.HOSTS = {}
        handlers.BOOT_ERRORS = {}
        handlers.TOOL_NAMES = {}
        handlers.MODE = None
        guard.configure(ctx, None, {})
        ctx.register_tool("agssh-hosts", "agssh", handlers.HOSTS_SCHEMA,
                          handlers.handle_hosts,
                          check_fn=handlers.ssh_available)
        ctx.register_hook("pre_tool_call", guard.on_pre_tool_call)
        return

    try:
        hosts = (ex.load_config().get("hosts") or {})
    except Exception as exc:
        logger.warning("agssh: registry unreadable: %s", exc)
        hosts = {}

    validated = {}
    boot_errors = {}
    for alias, info in hosts.items():
        err = _boot_error(str(alias), info)
        if err is not None:
            logger.warning("agssh: %s", err)
            ex.audit_call(str(alias), -1, 0, 0, False, "boot", "")
            boot_errors[str(alias)] = err
            continue
        validated[str(alias)] = info or {}

    # Q4: command tools go only to validated hosts with as_tool != False.
    tool_hosts = {a: i for a, i in validated.items()
                  if (i or {}).get("as_tool", True) != False}
    mode = ("per-host" if len(tool_hosts) <= GENERIC_HOST_THRESHOLD
            else "generic")

    tool_names = {str(alias): None for alias in hosts}
    if mode == "per-host":
        for alias in sorted(tool_hosts):
            name = f"agssh-{alias}"
            try:
                ctx.register_tool(
                    name, "agssh",
                    handlers.host_tool_schema(alias, tool_hosts[alias]),
                    handlers.make_host_handler(alias),
                    check_fn=handlers.ssh_available)
                tool_names[alias] = name
            except Exception as exc:
                logger.warning("agssh: failed to register %s: %s",
                               name, exc)
                boot_errors.setdefault(alias, f"register failed: {exc}")
    else:
        try:
            ctx.register_tool(
                "agssh", "agssh",
                handlers.generic_tool_schema(sorted(tool_hosts)),
                handlers.handle_host,
                check_fn=handlers.ssh_available)
            for alias in tool_hosts:
                tool_names[alias] = "agssh"
        except Exception as exc:
            logger.warning("agssh: failed to register agssh: %s", exc)

    for name, schema, handler in (
        ("agssh-read", handlers.READ_SCHEMA, handlers.handle_read),
        ("agssh-find", handlers.FIND_SCHEMA, handlers.handle_find),
        ("agssh-hosts", handlers.HOSTS_SCHEMA, handlers.handle_hosts),
    ):
        try:
            ctx.register_tool(name, "agssh", schema, handler,
                              check_fn=handlers.ssh_available)
        except Exception as exc:
            logger.warning("agssh: failed to register %s: %s", name, exc)

    handlers.HOSTS = validated
    handlers.BOOT_ERRORS = boot_errors
    handlers.TOOL_NAMES = tool_names
    handlers.MODE = mode
    guard.configure(
        ctx, mode,
        {a: validated[a] for a in validated if tool_names.get(a)})
    ctx.register_hook("pre_tool_call", guard.on_pre_tool_call)
