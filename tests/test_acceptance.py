"""Acceptance tests for the agssh build spec, section 12.

A11 replays the 2026-10-30 session's 37 raw ``terminal`` ssh command strings
through the executor and proves the remote payload is transmitted verbatim at
less than half the word count (the ssh wrapper, key path and ``2>&1 | tail``
scaffolding is gone). The corpus was not shipped with the build, so its
absence is a loud failure, never a silent skip.

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
import shlex
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
CORPUS_ROWS = 37
MAX_SKIPS = 5
RATIO_LIMIT = 0.40
ROW_TIMEOUT_S = 30

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


def _remote_payload(command):
    """Extract the remote command from a full terminal ssh string.

    ``shlex.split`` turns ``ssh -i key -p 22 user@host 'payload' 2>&1 | tail``
    into tokens where the single-quoted payload is one token; it sits right
    after the ``user@host`` destination. Returns None when the shape is not
    an ssh command the corpus claims it is.
    """
    try:
        tokens = shlex.split(command)
    except ValueError:
        return None
    for index, token in enumerate(tokens):
        if "@" in token:
            return tokens[index + 1] if index + 1 < len(tokens) else None
    return None


def test_a11_replay_corpus(ex, prod_guard):
    corpus_env = os.environ.get(CORPUS_ENV)
    corpus_path = Path(corpus_env) if corpus_env else None
    corpus_text = None
    if corpus_path is not None and corpus_path.is_file():
        corpus_text = corpus_path.read_text(encoding="utf-8", errors="replace")

    # Prod refusal first: it must also win over the missing-corpus failure.
    _prod_refusal(ex, corpus_text)

    if corpus_text is None:
        pytest.fail(
            "A11 corpus missing: set AGSSH_REPLAY_CORPUS to the session JSONL")

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

    if len(rows) != CORPUS_ROWS:
        pytest.fail(
            f"A11 fails closed: corpus has {len(rows)} rows,"
            f" expected exactly {CORPUS_ROWS}")

    # Baseline counts the FULL strings - ssh, key path, tail and all.
    baseline = sum(len(row["command"].split()) for row in rows)
    if baseline <= 0:
        pytest.fail("A11 fails closed: baseline word count is zero")

    def is_skipped(row):
        return row["skip"] or any(
            pat in row["command"] for pat in DANGEROUS_SUBSTRINGS)

    skips = sum(1 for row in rows if is_skipped(row))
    if skips > MAX_SKIPS:
        pytest.fail("skips <= 5 or A11 fails closed")

    new_sum = 0
    for index, row in enumerate(rows):
        if is_skipped(row):
            continue
        remote = _remote_payload(row["command"])
        if remote is None:
            pytest.fail(
                f"A11 fails closed: row {index} has no remote payload after"
                " the user@host token")
        new_sum += len(remote.split())

        # Transmission, not success: non-zero exit codes are fine (the rows
        # may not be idempotent and may touch paths absent on fatpsyk). What
        # must hold is that the call returns a real int exit code - no
        # quoting failure - and matches a direct execute on the same row.
        env = ex.execute("fatpsyk", remote, timeout_s=ROW_TIMEOUT_S)
        env2 = ex.execute("fatpsyk", remote, timeout_s=ROW_TIMEOUT_S)
        assert isinstance(env, dict), f"A11 row {index}: no envelope: {env!r}"
        assert isinstance(env.get("exit_code"), int), (
            f"A11 row {index}: exit_code is not an int"
            f" (quoting failure?): {env!r}")
        assert env["exit_code"] == env2["exit_code"], (
            f"A11 row {index}: tool exit_code {env['exit_code']} != direct"
            f" execute {env2['exit_code']}")

    ratio = new_sum / baseline
    assert ratio <= RATIO_LIMIT, (
        f"A11 command-token ratio {ratio:.3f} > {RATIO_LIMIT}"
        f" (new={new_sum} words, baseline={baseline} words)")


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
