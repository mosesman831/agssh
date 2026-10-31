"""Plugin-facing integration tests for agssh: A4, A6, A7, A15, A16, A17.

Sole target: fatpsyk (140.238.97.70, key ~/.ssh/oci_fat_proxy_4). Remote
writes stay under /tmp. No sudo, no rm outside our own /tmp fixtures, no
mkfs/dd/shutdown/reboot/installs.

The whole module skips when the fatpsyk key is missing, and skips cleanly
while the plugin (W1) has not landed yet.
"""

import glob
import importlib
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

FATPSYK_KEY = os.path.expanduser("~/.ssh/oci_fat_proxy_4")
DEFAULT_REGISTRY = os.path.expanduser("~/.config/persist-ssh.json")

if not os.path.exists(FATPSYK_KEY):
    pytest.skip(
        "integration key ~/.ssh/oci_fat_proxy_4 is missing",
        allow_module_level=True,
    )

agssh = pytest.importorskip("agssh", reason="agssh plugin is not installed yet")
agssh_handlers = pytest.importorskip("agssh.handlers")
agssh_guard = pytest.importorskip("agssh.guard")


# --------------------------------------------------------------------------
# plugin / ctx helpers
# --------------------------------------------------------------------------


class _MiniCtx:
    """Minimal PluginContext stand-in used only as a fallback when the
    conftest ``fake_ctx`` cannot express a needed config override."""

    def __init__(self, config=None):
        self.tools = {}
        self.hooks = {}
        self._config = dict(config or {})

    def register_tool(self, name, toolset, schema, handler, **kw):
        self.tools[name] = {
            "toolset": toolset,
            "schema": schema,
            "handler": handler,
            **kw,
        }
        return None

    def register_hook(self, hook_name, callback):
        self.hooks.setdefault(hook_name, []).append(callback)
        return None

    def get_config(self, key, default=None):
        return self._config.get(key, default)


def _reload_plugin():
    """Re-execute guard -> handlers -> package so module-level plugin state
    (registered tools, boot errors, configured guard) is fresh."""
    importlib.reload(agssh_guard)
    importlib.reload(agssh_handlers)
    importlib.reload(agssh)


def _register_plugin(ctx, *, reload=True):
    if reload:
        _reload_plugin()
    agssh.register(ctx)
    return ctx


def _tool_names(ctx):
    """Extract registered tool names from whatever shape fake_ctx captures."""
    names = set()
    reg = getattr(ctx, "register_tool", None)
    calls = getattr(reg, "call_args_list", None) or getattr(reg, "mock_calls", None)
    if calls:
        for c in calls:
            args = getattr(c, "args", ()) or ()
            if args:
                names.add(args[0])
            kw = getattr(c, "kwargs", None) or {}
            if isinstance(kw.get("name"), str):
                names.add(kw["name"])
    for attr in ("tools", "tool_names", "registered_tools",
                 "registrations", "calls", "_tools"):
        val = getattr(ctx, attr, None)
        if val is None:
            continue
        if isinstance(val, dict):
            names.update(k for k in val if isinstance(k, str))
        elif isinstance(val, (list, tuple, set, frozenset)):
            for item in val:
                if isinstance(item, str):
                    names.add(item)
                elif isinstance(item, dict):
                    for k in ("name", "tool_name", "tool"):
                        if isinstance(item.get(k), str):
                            names.add(item[k])
                elif isinstance(item, (list, tuple)) and item \
                        and isinstance(item[0], str):
                    names.add(item[0])
                elif isinstance(getattr(item, "name", None), str):
                    names.add(item.name)
    if not any(n.startswith("agssh") for n in names):
        try:
            values = vars(ctx).values()
        except TypeError:
            values = ()
        for v in values:
            if isinstance(v, dict):
                names.update(
                    k for k in v
                    if isinstance(k, str) and k.startswith("agssh")
                )
            elif isinstance(v, (list, tuple)):
                for item in v:
                    if isinstance(item, (list, tuple)) and item \
                            and isinstance(item[0], str) \
                            and item[0].startswith("agssh"):
                        names.add(item[0])
                    elif isinstance(item, dict) \
                            and str(item.get("name", "")).startswith("agssh"):
                        names.add(item["name"])
    return names


def _handler_from_ctx(ctx, name):
    tools = getattr(ctx, "tools", None)
    rec = None
    if isinstance(tools, dict):
        rec = tools.get(name)
    elif isinstance(tools, (list, tuple)):
        for item in tools:
            if isinstance(item, dict):
                n = item.get("name")
            elif isinstance(item, (list, tuple)) and item:
                n = item[0]
            else:
                n = getattr(item, "name", None)
            if n == name:
                rec = item
                break
    if rec is None:
        return None
    if isinstance(rec, dict):
        return rec.get("handler")
    if getattr(rec, "handler", None) is not None:
        return rec.handler
    if isinstance(rec, (list, tuple)):
        for x in rec:
            if callable(x):
                return x
    return rec if callable(rec) else None


def _call_host_tool(alias, command, timeout=None, workdir=None, ctx=None):
    """Invoke the host-command handler. Returns (raw_json_str, envelope)."""
    args = {"command": command}
    if timeout is not None:
        args["timeout"] = timeout
    if workdir is not None:
        args["workdir"] = workdir

    attempts = [
        ("handle_host",
         lambda: agssh_handlers.handle_host({**args, "host": alias})),
        ("make_host_handler",
         lambda: agssh_handlers.make_host_handler(alias)(args)),
    ]
    if ctx is not None:
        def _via_ctx():
            h = _handler_from_ctx(ctx, f"agssh-{alias}")
            if h is None:
                raise LookupError(f"no handler for agssh-{alias} in ctx")
            return h(args)
        attempts.append(("ctx-registered", _via_ctx))

    last_err = None
    for label, attempt in attempts:
        try:
            res = attempt()
        except Exception as exc:  # wrong call shape -> next handler form
            last_err = f"{label} raised {exc!r}"
            continue
        try:
            env = json.loads(res)
        except (TypeError, ValueError):
            return res, {}
        if not isinstance(env, dict):
            return res, {}
        err = str(env.get("error") or "")
        shape_reject = (
            "unknown host" in err
            or ("host" in err and (
                "required" in err or "missing" in err or "expected" in err))
            or "not registered" in err
        )
        if shape_reject:
            last_err = f"{label} -> {err}"
            continue
        return res, env
    pytest.fail(f"no host-tool handler accepted the call for "
                f"'{alias}': {last_err}")


def _call_hosts_output():
    errs = []
    for call in (lambda: agssh_handlers.handle_hosts({}),
                 lambda: agssh_handlers.handle_hosts()):
        try:
            res = call()
        except TypeError as exc:
            errs.append(str(exc))
            continue
        return res if isinstance(res, str) \
            else json.dumps(res, default=str, ensure_ascii=False)
    pytest.fail(f"handle_hosts not callable: {errs}")


def _ctx_config_set(ctx, key, value):
    """Write a config override into fake_ctx if it stores settings in a dict."""
    for attr in ("settings", "config", "_config", "configs",
                 "values", "_settings"):
        d = getattr(ctx, attr, None)
        if isinstance(d, dict):
            d[key] = value
            return True
    return False


# --------------------------------------------------------------------------
# executor / registry helpers
# --------------------------------------------------------------------------


def _executor_modules(ex=None):
    """Every module object that looks like the persist-ssh executor (the
    plugin may hold its own copy under an arbitrary attribute name)."""
    mods = []

    def _add(m):
        if (m is not None and not isinstance(m, str)
                and callable(getattr(m, "execute", None))
                and callable(getattr(m, "control_path", None))
                and m not in mods):
            mods.append(m)

    _add(ex)
    for holder in (agssh, agssh_handlers, agssh_guard):
        try:
            values = vars(holder).values()
        except TypeError:
            continue
        for v in values:
            _add(v)
    for m in list(sys.modules.values()):
        _add(m)
    return mods


def _pin_registry_file(monkeypatch, ex, path):
    """Point env + every reachable executor module at `path`."""
    monkeypatch.setenv("PERSIST_SSH_CONFIG", str(path))
    for m in _executor_modules(ex):
        monkeypatch.setattr(m, "CONFIG_PATH", str(path), raising=False)


def _install_hosts_registry(monkeypatch, ex, tmp_registry, tmp_path, hosts):
    """Route every registry read at `hosts`, whatever tmp_registry's shape is:
    callable factory, dict-like, namespace, or a path to write."""
    path = None
    reg = tmp_registry
    if callable(reg):
        res = called = None
        for payload in (hosts, {"hosts": hosts}):
            try:
                res = reg(payload)
                called = True
                break
            except TypeError:
                continue
        if not called:
            try:
                res = reg()
            except TypeError:
                res = None
        if isinstance(res, (str, os.PathLike)):
            path = str(res)
    elif isinstance(reg, dict):
        reg.clear()
        reg["hosts"] = hosts
    elif isinstance(reg, (str, os.PathLike)):
        path = str(reg)
    else:
        done = False
        for meth in ("write", "set", "set_hosts", "install", "update"):
            fn = getattr(reg, meth, None)
            if callable(fn):
                try:
                    res = fn(hosts)
                except TypeError:
                    res = fn({"hosts": hosts})
                if isinstance(res, (str, os.PathLike)):
                    path = str(res)
                done = True
                break
        if not done:
            for attr in ("hosts", "registry"):
                if hasattr(reg, attr):
                    try:
                        setattr(reg, attr, hosts)
                    except AttributeError:
                        pass
                    break
        if path is None and isinstance(
                getattr(reg, "path", None), (str, os.PathLike)):
            path = str(reg.path)
    if path is None:
        path = str(tmp_path / "agssh-registry.json")
    p = Path(path)
    if p.is_dir():
        p = p / "persist-ssh.json"
        path = str(p)
    try:
        needs_write = (not p.exists()
                       or json.loads(p.read_text() or "{}").get("hosts")
                       != hosts)
    except (OSError, ValueError):
        needs_write = True
    if needs_write:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps({"hosts": hosts}))
    _pin_registry_file(monkeypatch, ex, path)
    # Hard guarantee: any executor-module copy returns exactly these hosts.
    for m in _executor_modules(ex):
        if callable(getattr(m, "load_config", None)):
            monkeypatch.setattr(
                m, "load_config", lambda *a, **kw: {"hosts": hosts})
    return path


def _host_info(ex, alias, fallback):
    try:
        hosts = ex.load_config().get("hosts", {})
        if isinstance(hosts.get(alias), dict):
            return hosts[alias]
    except Exception:
        pass
    return fallback


def _kill_master(ex, alias, info):
    """Stop the control master and remove a lingering socket file."""
    cp = ex.control_path(alias, info)
    try:
        subprocess.run(
            ["ssh", "-O", "exit", "-o", f"ControlPath={cp}",
             f"{info['user']}@{info['host']}"],
            capture_output=True, timeout=20,
        )
    except Exception:
        pass
    try:
        ex.purge_socket(alias, info)
    except Exception:
        try:
            os.remove(cp)
        except OSError:
            pass


# --------------------------------------------------------------------------
# approval stubs (A15)
# --------------------------------------------------------------------------


def _stub_approval(monkeypatch, result):
    """Patch request_tool_approval wherever the plugin could have bound it."""
    import tools.approval

    stub = lambda *a, **kw: result
    real = tools.approval.request_tool_approval
    monkeypatch.setattr(tools.approval, "request_tool_approval", stub)
    for m in (agssh, agssh_handlers, agssh_guard):
        if hasattr(m, "request_tool_approval"):
            monkeypatch.setattr(m, "request_tool_approval", stub)
        for name, val in list(vars(m).items()):
            if val is real and name != "request_tool_approval":
                monkeypatch.setattr(m, name, stub)


def _stub_yolo(monkeypatch):
    try:
        import tools.approval as appr
    except Exception:
        appr = None
    for m in (appr, agssh, agssh_handlers, agssh_guard):
        if m is not None and hasattr(m, "_yolo_active"):
            monkeypatch.setattr(m, "_yolo_active", lambda *a, **kw: True)


# --------------------------------------------------------------------------
# Tests
# --------------------------------------------------------------------------


def test_a4_output_cap(ex, fake_ctx, monkeypatch):
    """200_000 remote chars -> truncated, 96_000 output, spill == capture,
    serialized envelope <= 100_000."""
    _pin_registry_file(monkeypatch, ex, DEFAULT_REGISTRY)
    _register_plugin(fake_ctx)
    # 200_000 remote chars, zero newlines: a 'y\n' payload would JSON-escape
    # ~48k newlines into ~144k serialized chars and _fit_serialized would trim
    # output below the 96_000 cap to satisfy the 100_000 serialized budget.
    res, env = _call_host_tool(
        "fatpsyk", "printf 'y%.0s' {1..200000}", timeout=60, ctx=fake_ctx)
    assert env.get("truncated") is True, env
    assert len(env.get("output", "")) == 96_000, (
        f"output len {len(env.get('output', ''))}")
    spill = env.get("full_output_path")
    assert spill, env
    assert os.path.exists(spill), f"spill file missing: {spill}"
    try:
        with open(spill, "rb") as fh:
            content = fh.read()
        assert len(content) == 200_000, f"spill has {len(content)} bytes"
        assert len(res) <= 100_000, (
            f"serialized envelope is {len(res)} chars")
    finally:
        os.remove(spill)


def test_a6_dead_mid(ex, host_fatpsyk):
    """Kill the master under an in-flight call -> dead_mid envelope, no
    re-run, next call rebuilds exactly one socket."""
    info = _host_info(ex, "fatpsyk", host_fatpsyk)
    warm = ex.execute("fatpsyk", "echo warm", timeout_s=30)
    assert warm.get("exit_code") == 0, warm
    # pre-clean our own /tmp fixture marker (a stale one would false-fail)
    ex.execute("fatpsyk", "rm -f /tmp/agssh-marker", timeout_s=30)

    box = {}

    def _run():
        box["env"] = ex.execute(
            "fatpsyk", "sleep 30 && touch /tmp/agssh-marker", timeout_s=180)

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    time.sleep(1.5)
    cp = ex.control_path("fatpsyk", info)
    subprocess.run(
        ["ssh", "-O", "exit", "-o", f"ControlPath={cp}",
         f"{info['user']}@{info['host']}"],
        capture_output=True, timeout=20,
    )
    t.join(timeout=90)
    assert not t.is_alive(), "execute hung after the master was killed"
    env = box["env"]
    assert env["exit_code"] == -1, env
    assert "lost its control socket mid-run" in (env.get("error") or ""), env

    chk = ex.execute(
        "fatpsyk", "ls /tmp/agssh-marker 2>/dev/null || echo ABSENT",
        timeout_s=60)
    assert "ABSENT" in chk.get("output", ""), chk

    ok = ex.execute("fatpsyk", "echo ok", timeout_s=60)
    assert ok["exit_code"] == 0 and "ok" in ok.get("output", ""), ok
    socks = [
        p for p in glob.glob(os.path.expanduser("~/.ssh/cm-fatpsyk-*"))
        if os.path.basename(p) != "cm-fatpsyk.lock"
    ]
    assert len(socks) == 1 and socks[0] == cp, socks


def test_a7_missing_key_boot(ex, tmp_registry, fake_ctx, tmp_path,
                             monkeypatch, host_fatpsyk):
    """A host whose key fails boot validation gets no tool; siblings
    register; agssh-hosts reports the key error."""
    hosts = {
        "fatpsyk": dict(host_fatpsyk),
        "badhost": {
            "host": "140.238.97.70",
            "user": "ubuntu",
            "key": "/nonexistent/key",
            "port": 22,
            "accept_new": True,
            "control_persist": 3600,
        },
    }
    _install_hosts_registry(monkeypatch, ex, tmp_registry, tmp_path, hosts)
    _register_plugin(fake_ctx)
    names = _tool_names(fake_ctx)
    assert "agssh-fatpsyk" in names, f"registered tools: {sorted(names)}"
    assert "agssh-badhost" not in names, f"registered tools: {sorted(names)}"
    out = _call_hosts_output()
    assert "badhost" in out, out
    assert "/nonexistent/key" in out, out


def test_a15_guard_denials(ex, fake_ctx, monkeypatch):
    """Dangerous command denied by approval stub does not run; hardline is
    blocked even with approval+yolo stubbed on."""
    import tools.approval_detection  # noqa: F401  (contract: standalone import)
    _pin_registry_file(monkeypatch, ex, DEFAULT_REGISTRY)
    _stub_approval(monkeypatch, {"approved": False, "message": "denied for test"})
    _register_plugin(fake_ctx)

    setup = ex.execute(
        "fatpsyk", "mkdir -p /tmp/agssh-a15 && touch /tmp/agssh-a15/sentinel",
        timeout_s=30)
    assert setup["exit_code"] == 0, setup
    try:
        _, env = _call_host_tool("fatpsyk", "rm -rf /tmp/agssh-a15",
                                 ctx=fake_ctx)
        assert env.get("exit_code") == -1, env
        assert "approval denied" in (env.get("error") or ""), env
        chk = ex.execute(
            "fatpsyk", "test -f /tmp/agssh-a15/sentinel && echo EXISTS",
            timeout_s=30)
        assert "EXISTS" in chk.get("output", ""), chk

        _stub_approval(monkeypatch, {"approved": True, "message": "ok"})
        _stub_yolo(monkeypatch)
        _, env2 = _call_host_tool("fatpsyk", "rm -rf /", ctx=fake_ctx)
        assert env2.get("exit_code") == -1, env2
        assert "hardline blocked" in (env2.get("error") or ""), env2
    finally:
        ex.execute("fatpsyk", "rm -rf /tmp/agssh-a15", timeout_s=30)


def test_a16_b11_block(ex, fake_ctx, monkeypatch):
    """pre_tool_call hook blocks terminal ssh to registered hosts with the
    exact B11 sentence; unregistered dests and other tools pass;
    block_raw_ssh: false disables."""
    _pin_registry_file(monkeypatch, ex, DEFAULT_REGISTRY)
    _register_plugin(fake_ctx)

    r = agssh_guard.on_pre_tool_call(
        "terminal", {"command": "ssh fatpsyk true"})
    assert r == {
        "action": "block",
        "message": "use agssh-fatpsyk instead of ssh to 'fatpsyk'."
                   " terminal ssh to a registered host is blocked.",
    }, r
    r = agssh_guard.on_pre_tool_call(
        "terminal", {"command": "ssh ubuntu@140.238.97.70"})
    assert r == {
        "action": "block",
        "message": "use agssh-fatpsyk instead of ssh to "
                   "'ubuntu@140.238.97.70'. terminal ssh to a registered "
                   "host is blocked.",
    }, r
    assert agssh_guard.on_pre_tool_call(
        "terminal", {"command": "ssh 192.0.2.1 true"}) is None
    assert agssh_guard.on_pre_tool_call(
        "other_tool", {"command": "ssh fatpsyk"}) is None

    assert _disable_block_raw_ssh(ex, fake_ctx), (
        "hook still blocking after block_raw_ssh=False")
    assert agssh_guard.on_pre_tool_call(
        "terminal", {"command": "ssh fatpsyk true"}) is None


def _disable_block_raw_ssh(ex, fake_ctx):
    """Re-run register/configure with block_raw_ssh disabled, using whatever
    ctx mechanism works. True when the hook stops blocking."""

    def still_blocks():
        return agssh_guard.on_pre_tool_call(
            "terminal", {"command": "ssh fatpsyk true"}) is not None

    if _ctx_config_set(fake_ctx, "block_raw_ssh", False):
        agssh.register(fake_ctx)
        if not still_blocks():
            return True
    mini = _MiniCtx({"block_raw_ssh": False})
    try:
        agssh.register(mini)
        if not still_blocks():
            return True
    except Exception:
        pass
    try:
        hosts = ex.load_config().get("hosts", {}) if ex is not None else {}
    except Exception:
        hosts = {}
    for tool_hosts in (hosts, set(hosts), list(hosts),
                       {a: a for a in hosts}):
        try:
            agssh_guard.configure(mini, "per_host", tool_hosts)
            if not still_blocks():
                return True
        except Exception:
            continue
    return not still_blocks()


def test_a17_publickey(ex, tmp_registry, tmp_path, monkeypatch,
                       host_fatpsyk):
    """A valid-format but unauthorized key fails setup with a publickey
    error that names the key; exactly one spawn attempt (no retry)."""
    badkey = tmp_path / "agssh-badkey"
    subprocess.run(
        ["ssh-keygen", "-f", str(badkey), "-N", "", "-t", "ed25519"],
        check=True, capture_output=True)
    os.chmod(badkey, 0o600)
    hosts = {"fatpsyk": {**host_fatpsyk, "key": str(badkey)}}
    _install_hosts_registry(monkeypatch, ex, tmp_registry, tmp_path, hosts)
    # the control path is key-independent: drop any live master first
    _kill_master(ex, "fatpsyk", host_fatpsyk)

    attempts = []
    orig_spawn = ex._spawn_and_verify

    def counting(name, info):
        attempts.append(name)
        return orig_spawn(name, info)

    monkeypatch.setattr(ex, "_spawn_and_verify", counting)
    env = ex.execute("fatpsyk", "echo hi", timeout_s=60)
    assert env["exit_code"] == -1, env
    assert "permission denied (publickey)" in (env.get("error") or "").lower(), env
    assert str(badkey) in (env.get("error") or ""), env
    assert attempts == ["fatpsyk"], attempts
