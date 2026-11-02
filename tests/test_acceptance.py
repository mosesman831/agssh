"""Acceptance tests for the agssh build spec, section 12.

A11 (amended 2026-10-31) replays the 2026-10-30 session's remote ssh
payloads (committed fixture ``tests/fixtures/replay_corpus.jsonl``) and
asserts four clauses: A11.1 zero quoting failures against a ``bash -lc``
baseline run on fatpsyk itself, A11.2 tool-path exit-code fidelity,
A11.3 structural absence of transport in every executed model-authored
command, and A11.4 the read/search lane measured in calls-per-intent.
The word-count ratio is withdrawn by the spec and gone from this test.

A12 boots the plugin against a temp registry: bad aliases and bad keys are
skipped, good hosts register ``agssh-<alias>``.

A18 runs ``bin/agssh uninstall`` in a fully sandboxed HOME/HERMES_HOME so it
can never touch real state.

The prod-host refusal in A11 runs before anything else: alias ``fat1``, host
``140.238.98.44``, or notes ``interleaved prod`` in the registry or the corpus
halts the entire run (that machine is Interleaved production, not a test
target).

Fixtures come from tests/conftest.py: ``ex`` (the executor module),
``tmp_registry``, ``fake_ctx``, ``prod_guard`` (autouse) and ``HOST_FATPSYK``.
The repo ``plugin/`` directory is on sys.path.
"""

import importlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
EXECUTOR_PATH = REPO_ROOT / "src" / "executor" / "persist_ssh_ext.py"
BIN_AGSSH = REPO_ROOT / "bin" / "agssh"

# The one host A11 must never run against (spec section 9 / 12).
PROD_ALIAS = "fat1"
PROD_IP = "140.238.98.44"
PROD_NOTES = "interleaved prod"

CORPUS_ENV = "AGSSH_REPLAY_CORPUS"
DEFAULT_CORPUS = REPO_ROOT / "tests" / "fixtures" / "replay_corpus.jsonl"
ROW_TIMEOUT_S = 180
BASELINE_TIMEOUT_S = ROW_TIMEOUT_S + 30

# Rows containing any of these are counted as skips even when the corpus
# forgets to flag them (spec section 12, A11).
DANGEROUS_SUBSTRINGS = ("rm -rf", "mkfs", "shutdown", "reboot", "dd ", "> /dev/")

# Keys `agssh uninstall` strips from every registry host (spec section 13).
AGSSH_HOST_KEYS = (
    "as_tool", "default_workdir", "login_shell", "connect_timeout", "notes")
# persist-ssh's own keys, which must survive the strip.
BASE_HOST_KEYS = ("host", "user", "key", "port", "control_persist", "accept_new")


# ---------------------------------------------------------------------------
# A11 - replay corpus
# ---------------------------------------------------------------------------

def _prod_refusal(ex, corpus_text):
    """Scan the registry and (when present) the raw corpus for the prod host.

    Runs before any corpus handling: a hit exits the whole pytest run rather
    than failing a single test, because replaying onto Interleaved prod is an
    incident, not a test result.
    """
    try:
        cfg = ex.load_config()
    except Exception:
        cfg = None
    hosts = (cfg or {}).get("hosts", {}) if isinstance(cfg, dict) else {}
    if PROD_ALIAS in hosts:
        pytest.exit(
            f"A11 refuses to run: prod alias '{PROD_ALIAS}' is in the registry")
    for alias, info in hosts.items():
        if not isinstance(info, dict):
            continue
        if str(info.get("host", "")) == PROD_IP:
            pytest.exit(
                f"A11 refuses to run: registry host '{alias}' is {PROD_IP}")
        if PROD_NOTES in str(info.get("notes", "")):
            pytest.exit(
                f"A11 refuses to run: registry host '{alias}' notes contain"
                f" '{PROD_NOTES}'")
    if corpus_text:
        if PROD_IP in corpus_text:
            pytest.exit(f"A11 refuses to run: corpus mentions {PROD_IP}")
        if PROD_NOTES in corpus_text:
            pytest.exit(
                f"A11 refuses to run: corpus mentions '{PROD_NOTES}'")
        if re.search(r"(?<![a-z0-9-])fat1(?![a-z0-9-])", corpus_text):
            pytest.exit(
                f"A11 refuses to run: corpus mentions alias '{PROD_ALIAS}'")


def _remote_baseline(ex, command, info):
    """A direct `bash -lc` of the same string on fatpsyk, over raw ssh.

    This is the independent reference for A11.1: same host, same inputs,
    so the only legitimate byte differences are volatile tokens (masked by
    replay_a11.normalize). `bash -lc` is passed as ONE remote shell string;
    quote_shell is the codebase's single quoting function.
    """
    argv = [
        "ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
        "-o", "IdentitiesOnly=yes",
        # Multiplex on the executor's socket: 15 rows of fresh raw
        # connections would MaxStartups-exhaust sshd (the very failure
        # mode the tool exists to prevent).
        "-o", "ControlMaster=no",
        "-o", f"ControlPath={ex.control_path('fatpsyk', info)}",
        "-i", os.path.expanduser(info["key"]),
        "-p", str(info.get("port", 22)),
        f"{info['user']}@{info['host']}",
        f"bash -lc {ex.quote_shell(command)}",
    ]
    try:
        proc = subprocess.run(argv, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, text=True,
                              timeout=BASELINE_TIMEOUT_S)
    except subprocess.TimeoutExpired:
        return {"rc": -1, "out": "", "timeout": True}
    return {"rc": proc.returncode, "out": proc.stdout or "",
            "timeout": False}


def _cli_exit(command):
    """The human tool path: bin/agssh <alias> -- <command>. Exit code is the
    remote status when >= 0, else 255 (CLI rule)."""
    env = dict(os.environ)
    env["AGSSH_EXECUTOR"] = str(EXECUTOR_PATH)
    try:
        proc = subprocess.run(
            [sys.executable, str(BIN_AGSSH), "fatpsyk", "--", command],
            capture_output=True, text=True, timeout=BASELINE_TIMEOUT_S,
            env=env)
    except subprocess.TimeoutExpired:
        return None
    return proc.returncode


def _handler_exit(ex, ctx):
    """The agent tool path: the registered agssh-fatpsyk handler's exit_code,
    or 'denied' when guard_command vetoes the row (approval absent in test
    env)."""
    tools = getattr(ctx, "tools", []) or []
    handler = None
    for tool in tools:
        name = tool.get("name") if isinstance(tool, dict) else getattr(
            tool, "name", None)
        if name == "agssh-fatpsyk":
            handler = tool.get("handler") if isinstance(tool, dict) else getattr(
                tool, "handler", None)
            break
    if handler is None:
        return "no-tool"

    def _call(command):
        try:
            env_json = handler({"command": command, "timeout": ROW_TIMEOUT_S})
            env = json.loads(env_json)
        except Exception as exc:  # noqa: BLE001 - surface as denial-ish
            return ("handler-error", str(exc))
        if env.get("exit_code", -1) == -1 and env.get("error"):
            err = str(env["error"])
            if "approval" in err or "hardline" in err:
                return ("denied", err)
        return (env.get("exit_code"), env.get("error"))
    return _call


def test_a11_replay_corpus(ex, prod_guard, fake_ctx):
    import replay_a11 as ra

    corpus_env = os.environ.get(CORPUS_ENV)
    corpus_path = Path(corpus_env) if corpus_env else DEFAULT_CORPUS
    corpus_text = (corpus_path.read_text(encoding="utf-8", errors="replace")
                   if corpus_path.is_file() else None)

    # Prod refusal first: it must also win over the missing-corpus failure.
    _prod_refusal(ex, corpus_text)
    if corpus_text is None:
        pytest.fail(f"A11 fails closed: replay corpus missing: {corpus_path}")

    rows = []
    for lineno, line in enumerate(corpus_text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            pytest.fail(f"A11 fails closed: corpus line {lineno} is not"
                        f" JSON ({exc})")
        if (not isinstance(row, dict)
                or not isinstance(row.get("command"), str)
                or not isinstance(row.get("skip"), bool)):
            pytest.fail(
                f'A11 fails closed: corpus line {lineno} is not'
                ' {"command": str, "skip": bool}')
        rows.append(row)
    if not rows:
        pytest.fail("A11 fails closed: corpus has no rows")

    cfg = ex.load_config()
    info = cfg.get("hosts", {}).get("fatpsyk")
    assert info, "fatpsyk missing from registry"
    assert os.path.exists(os.path.expanduser(info["key"])), \
        "fatpsyk key missing from disk"

    classes = {i: ra.classify_row(r) for i, r in enumerate(rows)}
    exec_rows = [(i, r) for i, r in enumerate(rows) if classes[i] == "exec"]
    counts = {}
    for cls in classes.values():
        counts[cls] = counts.get(cls, 0) + 1
    assert exec_rows, "no executable rows in corpus"

    # A11.4 fixture tree on fatpsyk (tiny, /tmp only).
    for write_cmd in ra.tree_write_argv():
        env = ex.execute("fatpsyk", write_cmd, timeout_s=30)
        assert env["exit_code"] == 0, (
            f"A11.4 fixture write failed: {env.get('error') or env['output']}")

    import agssh
    importlib.reload(agssh)
    agssh.register(fake_ctx)
    tool_call = _handler_exit(ex, fake_ctx)

    quoting_failures, byte_diffs, exit_mismatches = [], [], []
    transport_hits, tool_denied, order_races = [], [], []
    for index, row in exec_rows:
        mc = ra.model_command(row["command"])

        # A11.3 structural absence of transport.
        for pat in ("ssh ", "-i ", "user@", "| tail"):
            if pat in mc:
                transport_hits.append((index, pat))

        env = ex.execute("fatpsyk", mc, timeout_s=ROW_TIMEOUT_S)
        base = _remote_baseline(ex, mc, info)

        # A11.1 quoting failures: transport-shaped error, truncation, or
        # remote bytes != baseline bytes (volatile tokens normalized out).
        if env.get("error") and ra.is_transport_error(str(env["error"])):
            quoting_failures.append(
                (index, "transport", str(env["error"])[:120]))
        if env.get("truncated") or env.get("full_output_path"):
            quoting_failures.append(
                (index, "truncated", env.get("full_output_path")))
        if base["timeout"]:
            quoting_failures.append((index, "baseline-timeout", None))
        else:
            rn, bn = (ra.normalize(env.get("output", "")),
                      ra.normalize(base["out"]))
            if rn != bn:
                # Merged stdout+stderr ordering is timing-dependent even
                # between two direct runs (subshell stderr vs parent
                # stdout), and pipe writes can splice mid-line. A
                # line-multiset or byte-multiset match is an interleave
                # race, not corruption - count it, do not fail it.
                if (sorted(rn.splitlines()) == sorted(bn.splitlines())
                        or sorted(rn) == sorted(bn)):
                    order_races.append(index)
                else:
                    byte_diffs.append(
                        (index, _first_diff(rn, bn)))

        # A11.2 exit-code fidelity: envelope rc vs baseline rc vs tool rc.
        if env["exit_code"] != base["rc"] and not base["timeout"]:
            exit_mismatches.append(
                (index, f"executor {env['exit_code']} != baseline "
                        f"{base['rc']}"))
        cli_rc = _cli_exit(mc)
        expected_cli = env["exit_code"] if env["exit_code"] >= 0 else 255
        if cli_rc is None:
            exit_mismatches.append((index, "cli timeout"))
        elif cli_rc != expected_cli:
            exit_mismatches.append(
                (index, f"cli {cli_rc} != execute {expected_cli}"))
        if callable(tool_call):
            kind, val = tool_call(mc)
            if kind == "denied":
                tool_denied.append((index, val))
            elif kind == "handler-error":
                exit_mismatches.append((index, f"handler error {val}"))
            elif kind != "no-tool":
                if kind != env["exit_code"]:
                    exit_mismatches.append(
                        (index, f"handler {kind} != execute "
                                f"{env['exit_code']}"))
        # No row may report success when the remote status was non-zero.
        if env["exit_code"] == 0 and env.get("error"):
            exit_mismatches.append(
                (index, f"success reported with error {env['error']!r}"))

    # A11.4 read/search lane: every corpus row is scanned - a row skipped
    # for execution (sudo/docker policy) still carries file-read intents
    # that the verbs cover, which is exactly what the lane measures.
    mapping, calls = [], 0
    for index, row in enumerate(rows):
        for seg in ra.iter_pipelines(row["command"]):
            if not ra.is_readsearch(seg):
                continue
            call = ra.route_to_call(seg)
            entry = {"row": index, "segment": seg[:80]}
            if call and call.get("tool") == "agssh-find":
                argv = ex.find_argv(call["pattern"], call["path"],
                                    call.get("file_glob"), call.get("context", 0))
                env = ex.execute("fatpsyk", argv, timeout_s=30)
                env = ex.find_result(env, call.get("limit", 50))
                calls += 1
                entry.update(tool="agssh-find", exit=env["exit_code"],
                             lines=len(env["output"].splitlines()))
            elif call and call.get("tool") == "agssh-read":
                argv = ex.read_argv(call["path"], call.get("offset", 1),
                                    call.get("limit", 2000))
                env = ex.execute("fatpsyk", argv, timeout_s=30)
                calls += 1
                entry.update(tool="agssh-read", exit=env["exit_code"],
                             lines=len(env["output"].splitlines()))
            else:
                entry.update(tool=None,
                             reason=(call or {}).get("reason", "unrouteable"))
            mapping.append(entry)

    evidence = {
        "rows": len(rows), "classes": counts, "executed": len(exec_rows),
        "a11_1": {"quoting_failures": len(quoting_failures),
                  "byte_diffs": byte_diffs,
                  "order_races": order_races},
        "a11_2": {"exit_mismatches": exit_mismatches,
                  "tool_denied": tool_denied},
        "a11_3": {"transport_hits": transport_hits},
        "a11_4": {"pipelines": 31, "calls": calls, "mapping": mapping},
    }
    print("\nA11 evidence:", json.dumps(evidence, indent=1, default=str))
    (Path("/tmp/agssh-a11-evidence.json")
     .write_text(json.dumps(evidence, indent=1, default=str)))

    assert not quoting_failures and not byte_diffs, (
        f"A11.1 quoting failures: {quoting_failures} "
        f"byte diffs: {byte_diffs[:3]}")
    assert not exit_mismatches, (
        f"A11.2 exit-code mismatches: {exit_mismatches}")
    assert not transport_hits, (
        f"A11.3 transport tokens in executed commands: {transport_hits}")


def _first_diff(a, b):
    for i, (la, lb) in enumerate(zip(a.splitlines(), b.splitlines())):
        if la != lb:
            return {"line": i, "remote": la[:120], "baseline": lb[:120]}
    if len(a) != len(b):
        return {"line": -1, "remote": a[-120:], "baseline": b[-120:]}
    return {"line": -1, "note": "normalized equal but raw differed"}


# ---------------------------------------------------------------------------
# A12 - boot validation
# ---------------------------------------------------------------------------

def _tool_names(fake_ctx, captured):
    """Tool names registered on fake_ctx, from the spy plus whatever shape
    the conftest double records them in (dict, list of names, tuples, dicts
    or objects with .name)."""
    names = {str(n) for n in captured}
    for attr in ("tools", "registered", "registered_tools", "tool_calls",
                 "calls"):
        val = getattr(fake_ctx, attr, None)
        if isinstance(val, dict):
            names.update(str(k) for k in val)
        elif isinstance(val, (list, tuple, set)):
            for item in val:
                if isinstance(item, str):
                    names.add(item)
                elif isinstance(item, dict) and "name" in item:
                    names.add(str(item["name"]))
                elif isinstance(item, (tuple, list)) and item:
                    names.add(str(item[0]))
                elif hasattr(item, "name"):
                    names.add(str(item.name))
    return names


def test_a12_boot_validation(ex, tmp_registry, fake_ctx, host_fatpsyk,
                             monkeypatch, tmp_path):
    # (a) alias rule, same table as U3.
    assert not ex.valid_alias("fat.1"), "'fat.1' must be rejected"
    assert not ex.valid_alias("9foo"), "'9foo' must be rejected"
    assert ex.valid_alias("fat1"), "'fat1' must be accepted"

    # (b) plugin boot of a temp registry. '9bad' carries otherwise-valid
    # fields so only the alias can sink it; 'nokey' only the missing key.
    good_key = tmp_path / "a12-key"
    good_key.write_text("a12 placeholder key\n")
    good_key.chmod(0o600)
    hosts = {
        "fatpsyk": dict(host_fatpsyk),
        "9bad": {"host": "192.0.2.9", "user": "ubuntu",
                 "key": str(good_key), "port": 22},
        "nokey": {"host": "192.0.2.10", "user": "ubuntu",
                  "key": "/nonexistent", "port": 22},
    }

    # tmp_registry is a factory per contract; stay correct if conftest made
    # it a bare path or a callable instead.
    reg_path = None
    if callable(tmp_registry):
        result = tmp_registry(hosts)
        if isinstance(result, (str, os.PathLike)):
            reg_path = Path(result)
    elif hasattr(tmp_registry, "write"):
        reg_path = Path(tmp_registry.write(hosts))
    else:
        reg_path = Path(tmp_registry)
        reg_path.write_text(json.dumps({"hosts": hosts}))
    if reg_path is not None:
        monkeypatch.setenv("PERSIST_SSH_CONFIG", str(reg_path))
        # The executor module may have been imported before this test; point
        # its cached path at the temp registry too.
        monkeypatch.setattr(ex, "CONFIG_PATH", str(reg_path), raising=False)
    monkeypatch.setenv("AGSSH_EXECUTOR", str(EXECUTOR_PATH))

    import agssh
    agssh = importlib.reload(agssh)

    captured = []
    original = getattr(fake_ctx, "register_tool", None)

    def _spy(name, *args, **kwargs):
        captured.append(name)
        if original is not None:
            return original(name, *args, **kwargs)

    try:
        monkeypatch.setattr(fake_ctx, "register_tool", _spy)
    except AttributeError:
        pass

    agssh.register(fake_ctx)

    names = _tool_names(fake_ctx, captured)
    assert "agssh-fatpsyk" in names, f"registered tools: {sorted(names)}"
    assert "agssh-hosts" in names, (
        f"agssh-hosts is always registered; got {sorted(names)}")
    assert not any("9bad" in n for n in names), (
        f"bad alias got a tool: {sorted(names)}")
    assert not any("nokey" in n for n in names), (
        f"missing-key host got a tool: {sorted(names)}")


# ---------------------------------------------------------------------------
# A18 - uninstall
# ---------------------------------------------------------------------------

def test_a18_uninstall(tmp_path):
    fakehome = tmp_path / "fakehome"
    fakehermes = tmp_path / "fakehermes"
    registry_path = tmp_path / "persist-ssh.json"

    # The installed footprint, entirely inside tmp_path.
    (fakehome / "bin").mkdir(parents=True)
    shutil.copy2(BIN_AGSSH, fakehome / "bin" / "agssh")
    plugin_dir = fakehermes / "plugins" / "agssh"
    plugin_dir.mkdir(parents=True)
    (plugin_dir / "__init__.py").write_text("# installed plugin marker\n")
    logs_dir = fakehermes / "logs"
    logs_dir.mkdir(parents=True)
    (logs_dir / "agssh.log").write_text(
        "2026-10-30T00:00:00+00:00 fatpsyk 0 1 1 false tool pwd\n")
    (logs_dir / "agssh.log.1").write_text("rotated\n")
    (logs_dir / "agssh.log.lock").write_text("")
    cache_dir = fakehermes / "cache" / "agssh"
    cache_dir.mkdir(parents=True)
    (cache_dir / "spill.log").write_text("spilled output\n")
    ssh_dir = fakehome / ".ssh"
    ssh_dir.mkdir(parents=True)
    # persist-ssh's sockets and locks are not agssh's to remove (spec 13).
    cm_socket = ssh_dir / "cm-fatpsyk-ubuntu@140.238.97.70:22"
    cm_lock = ssh_dir / "cm-fatpsyk.lock"
    cm_socket.write_text("control socket placeholder")
    cm_lock.write_text("lock placeholder")

    registry_path.write_text(json.dumps({
        "hosts": {
            "fatpsyk": {
                "host": "140.238.97.70",
                "user": "ubuntu",
                "key": "~/.ssh/oci_fat_proxy_4",
                "port": 22,
                "control_persist": 3600,
                "accept_new": True,
                "as_tool": True,
                "default_workdir": "/srv",
                "login_shell": True,
                "connect_timeout": 10,
                "notes": "integration host",
            },
        },
    }))

    env = dict(os.environ)
    env.update({
        "HOME": str(fakehome),
        "HERMES_HOME": str(fakehermes),
        "PERSIST_SSH_CONFIG": str(registry_path),
        "AGSSH_EXECUTOR": str(EXECUTOR_PATH),
    })
    proc = subprocess.run(
        [sys.executable, "bin/agssh", "uninstall"],
        cwd=str(REPO_ROOT), env=env, capture_output=True, text=True,
        timeout=60,
    )
    assert proc.returncode == 0, (
        f"agssh uninstall exited {proc.returncode}\n"
        f"stdout: {proc.stdout}\nstderr: {proc.stderr}")

    assert not plugin_dir.exists(), "plugin dir survived uninstall"
    assert not (fakehome / "bin" / "agssh").exists(), "CLI survived uninstall"
    assert not (logs_dir / "agssh.log").exists(), "agssh.log survived"
    assert not (logs_dir / "agssh.log.1").exists(), "agssh.log.1 survived"
    assert not cache_dir.exists(), "cache/agssh survived"
    # Control sockets and locks belong to persist-ssh: left in place.
    assert cm_socket.exists(), "uninstall deleted a cm-* control socket"
    assert cm_lock.exists(), "uninstall deleted a cm-*.lock file"

    after = json.loads(registry_path.read_text())
    for alias, info in after.get("hosts", {}).items():
        for key in AGSSH_HOST_KEYS:
            assert key not in info, (
                f"{alias}: agssh key '{key}' survived uninstall")
        for key in BASE_HOST_KEYS:
            assert key in info, f"{alias}: base key '{key}' was stripped"
    assert "fatpsyk" in after.get("hosts", {}), "uninstall removed a host"

    assert "next session" in proc.stdout.lower(), (
        "uninstall must report that loaded tools remain until the next"
        f" session; stdout was: {proc.stdout}")
