"""agssh spec section 12 — unit layer U1..U8 plus M5 coverage U9..U16.

Executor tests (U1-U4, U7, U8, U10, U11) run against the vendored
``plugin/agssh/executor.py`` loaded through the ``ex`` fixture — the same
bytes as ``src/executor/persist_ssh_ext.py`` (U9 locks that parity).
Plugin tests (U5, U6, U12-U16) import the ``agssh`` package lazily inside
the test body, so collection of the executor tests does not depend on the
plugin existing.
"""

import importlib.machinery
import importlib.util
import inspect
import json
import os
import stat
import shlex

import pytest

# The single-quote escape produced by shlex.quote: '"'"'
SQ_ESCAPE = "'" + '"' + "'" + '"' + "'"


# ---------------------------------------------------------------------------
# U1 — quoting owner (R1): one remote element, quote_shell's only caller is
# build_remote_command, and nothing else reaches shlex.quote.
# ---------------------------------------------------------------------------

def test_u1_quoting_owner(ex):
    remote = ex.build_remote_command(
        "echo 'a b'", workdir=None, timeout_s=5,
        login_shell=True, sentinel="agssh-s")
    assert isinstance(remote, str)
    # one remote element: `bash -lc <one quoted payload>`
    assert remote.startswith("bash -lc ")
    assert len(shlex.split(remote)) == 3
    assert "timeout -k 2 5s bash -c" in remote
    # the wrapped command is single-quoted
    payload_arg = remote.split(" ", 2)[2]
    assert SQ_ESCAPE in remote or payload_arg.startswith("'")

    plain = ex.build_remote_command(
        "true", workdir=None, timeout_s=5,
        login_shell=False, sentinel="agssh-s")
    assert plain.startswith("bash -c ")
    assert len(shlex.split(plain)) == 3

    wd = ex.build_remote_command(
        "pwd", workdir="/tmp/x", timeout_s=5,
        login_shell=True, sentinel="agssh-s")
    assert "cd -- /tmp/x &&" in wd

    # argv form: each element quoted; the joined string is the bash -c script.
    argv = ["sed", "-n", "1,5p", "--", "/etc/pa ss"]
    remote = ex.build_remote_command(
        argv, workdir=None, timeout_s=5, login_shell=False, sentinel="agssh-s")
    assert "'/etc/pa ss'" in remote  # spaced element appears quoted
    payload = shlex.split(remote)[2]
    tokens = shlex.split(payload)
    script = tokens[tokens.index("-c") + 1]
    assert shlex.split(script) == argv

    # one call site for the quoting inner: exactly one `shlex.quote(` in the
    # module (inside quote_shell) and `quote_shell(` only inside
    # build_remote_command's body.
    assert inspect.getsource(ex).count("shlex.quote(") == 1
    assert "quote_shell(" in inspect.getsource(ex.build_remote_command)
    for name, fn in inspect.getmembers(ex, inspect.isfunction):
        if name in ("quote_shell", "build_remote_command"):
            continue
        fsrc = inspect.getsource(fn)
        assert "shlex.quote(" not in fsrc, f"{name} reaches shlex.quote directly"
        assert "quote_shell(" not in fsrc, f"{name} calls quote_shell"


# ---------------------------------------------------------------------------
# U2 — B14 classifier order: output markers first (maxstartups > publickey >
# mux), then 124 -> timeout, 255 -> connect, else remote.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("output,returncode,expected", [
    ("kex_exchange_identification: read: Connection reset by peer", 255, "maxstartups"),
    ("Permission denied (publickey).", 255, "publickey"),
    ("kex_exchange_identification + permission denied publickey", 255, "maxstartups"),
    ("mux_client_request_session: fail", 255, "mux"),
    ("", 124, "timeout"),
    ("", 255, "connect"),
    ("garbage", 3, "remote"),
])
def test_u2_classify_order(ex, output, returncode, expected):
    assert ex.classify_failure(output, returncode) == expected


# ---------------------------------------------------------------------------
# U3 — alias rule [a-z0-9][a-z0-9-]{0,30} plus the boot rejection of a leading
# digit (A12): '9foo' must NOT validate.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("alias,expected", [
    ("bad.1", False),
    ("9foo", False),
    ("web1", True),
    ("a", True),
    ("A", False),
    ("a" * 32, False),
    ("a" * 31, True),
    ("foo_bar", False),
])
def test_u3_alias(ex, alias, expected):
    assert ex.valid_alias(alias) is expected


# ---------------------------------------------------------------------------
# U4 — cap vs persistence: a 96_000-char output envelope still serializes
# under the 100_000-char result budget, so exit_code survives persistence.
# ---------------------------------------------------------------------------

def test_u4_cap_vs_persistence(ex):
    envelope = {
        "output": "x" * 96_000,
        "exit_code": 0,
        "host": "h",
        "cwd": None,
        "duration_ms": 1,
        "truncated": True,
        "full_output_path": "/tmp/x",
        "error": "output truncated at 96000 chars; full text at /tmp/x",
    }
    assert len(json.dumps(envelope, ensure_ascii=False)) <= 100_000


# ---------------------------------------------------------------------------
# U5 — Q4 switch under the per_host_tools opt-in: <=10 validated hosts
# register per-host tools and no generic `agssh`; >10 registers ONE generic
# `agssh` whose host param is the alias enum, and no per-host command tools.
# Verbs exist in both modes. The default (per_host_tools unset) is catalog
# mode — always the generic surface — covered by U12.
# ---------------------------------------------------------------------------

def _hosts(count, key):
    return {
        f"h{i:02d}": {
            "host": f"10.0.0.{i + 1}",
            "user": "ubuntu",
            "key": key,
            "port": 22,
            "control_persist": 3600,
            "accept_new": True,
        }
        for i in range(count)
    }


_VERBS = ("agssh-read", "agssh-find", "agssh-hosts")


def test_u5_q4_switch(ex, fake_ctx, tmp_registry, make_key):
    import agssh  # noqa: plugin package — resolved from repo plugin/ on sys.path
    import agssh.handlers  # noqa: F401

    key = make_key()
    fake_ctx.settings["per_host_tools"] = True

    # --- 10 hosts: per-host mode ---
    hosts10 = _hosts(10, key)
    tmp_registry.write(hosts10)
    agssh.register(fake_ctx)
    names = [t["name"] for t in fake_ctx.tools]
    per_host = sorted(n for n in names if n.startswith("agssh-") and n not in _VERBS)
    assert per_host == [f"agssh-{a}" for a in sorted(hosts10)]
    assert "agssh" not in names
    for verb in _VERBS:
        assert verb in names

    # --- 11 hosts: over the threshold, one generic tool ---
    hosts11 = _hosts(11, key)
    tmp_registry.write(hosts11)
    ctx2 = type(fake_ctx)()
    ctx2.settings["per_host_tools"] = True
    agssh.register(ctx2)
    names2 = [t["name"] for t in ctx2.tools]
    assert names2.count("agssh") == 1
    generic = next(t for t in ctx2.tools if t["name"] == "agssh")
    enum = generic["schema"]["parameters"]["properties"]["host"]["enum"]
    assert enum == sorted(hosts11)
    assert not any(n in {f"agssh-{a}" for a in hosts11} for n in names2)
    for verb in _VERBS:
        assert verb in names2


# ---------------------------------------------------------------------------
# U6 — B11 matcher: find_registered_ssh_dest spots ssh to a registered alias
# or its host/IP (incl. inside `bash -c`, after `;`/`|`, after `--`, with
# flag-skipping), and ignores non-ssh, unregistered, or non-command text.
# ---------------------------------------------------------------------------

_U6_HOSTS = {"web1": {"host": "192.0.2.10", "user": "deploy", "port": 22}}

_U6_MATCH = [
    "ssh web1 true",
    "ssh deploy@192.0.2.10",
    "bash -c 'ssh web1 true'",
    "bash -lc 'ssh deploy@192.0.2.10 x'",
    "ssh -i ~/.ssh/k -p 22 deploy@192.0.2.10",
    "x; ssh 192.0.2.10",
    "echo hi | ssh web1",
    "ssh -- web1",
    "ssh 192.0.2.10:22",
]

_U6_NO_MATCH = [
    "echo ssh web1",
    "ssh-keygen -l",
    "scp a web1:b",
    "sftp web1",
    "ssh 192.0.2.99 true",
    "",
]


@pytest.mark.parametrize("command", _U6_MATCH)
def test_u6_b11_matcher_hits(command):
    import agssh.guard
    assert agssh.guard.find_registered_ssh_dest(command, _U6_HOSTS)


@pytest.mark.parametrize("command", _U6_NO_MATCH)
def test_u6_b11_matcher_misses(command):
    import agssh.guard
    assert agssh.guard.find_registered_ssh_dest(command, _U6_HOSTS) is None


# ---------------------------------------------------------------------------
# U7 — spec section 8 retry policy: one retry per call, only when stripped
# output is empty and the class is mux/maxstartups/connect. The retry is
# purge -> ensure_master -> the command again, still multiplexed.
# ---------------------------------------------------------------------------

def _wire_retry_stubs(ex, monkeypatch, scripted):
    """Stub the transport edges of execute(); return the event log."""
    events = []
    monkeypatch.setattr(ex, "ensure_master",
                        lambda *a, **k: events.append("ensure_master"))
    monkeypatch.setattr(ex, "purge_socket",
                        lambda *a, **k: events.append("purge_socket"))
    monkeypatch.setattr(ex, "master_alive", lambda *a, **k: True)
    monkeypatch.setattr(ex, "audit_call", lambda *a, **k: None)
    results = list(scripted)

    def fake_run_capture(argv, watchdog_s, capture_max):
        events.append("run_capture")
        if results:
            return results.pop(0)
        return (3, "unexpected extra call", False, False)

    monkeypatch.setattr(ex, "_run_capture", fake_run_capture)
    return events


def test_u7_retry_policy(ex, tmp_registry, make_key, monkeypatch):
    key = make_key()
    tmp_registry.write({
        "web1": {
            "host": "192.0.2.10",
            "user": "deploy",
            "key": key,
            "port": 22,
        },
    })

    # Case A: non-empty output blocks the retry — exactly one capture call.
    events = _wire_retry_stubs(ex, monkeypatch, [(255, "some output", False, False)])
    env = ex.execute("web1", "true")
    assert events.count("run_capture") == 1
    assert env["exit_code"] == -1
    assert "connect failed" in env["error"]
    assert "web1" in env["error"]

    # Case B: first failure empty (retryable), second failure reported —
    # never a third call. Covers both a second connect and a second mux.
    for second_output in ("", "mux_client_request_session: fail"):
        events = _wire_retry_stubs(
            ex, monkeypatch,
            [(255, "", False, False),
             (255, second_output, False, False),
             (0, "x", False, False)])
        env = ex.execute("web1", "true")
        assert events.count("run_capture") == 2
        assert events == [
            "ensure_master", "run_capture",
            "purge_socket", "ensure_master", "run_capture",
        ]
        assert env["exit_code"] == -1
        assert "connect failed" in env["error"]

    # Case C: failure then success — the retry can recover the call.
    events = _wire_retry_stubs(
        ex, monkeypatch, [(255, "", False, False), (0, "ok", False, False)])
    env = ex.execute("web1", "true")
    assert events.count("run_capture") == 2
    assert env["exit_code"] == 0
    assert env["output"] == "ok"
    assert env["error"] is None


# ---------------------------------------------------------------------------
# U8 — find_result remap: grep status 1 -> exit 0 + empty output (find only);
# status >= 2 returned as-is; otherwise first `limit` matching lines survive.
# ---------------------------------------------------------------------------

def test_u8_find_map(ex):
    no_match = ex.find_result({"exit_code": 1, "output": "", "error": None}, 50)
    assert no_match["exit_code"] == 0
    assert no_match["output"] == ""

    limited = ex.find_result(
        {"exit_code": 0, "output": "f:1:a\nf:2:b\nf:3:c\n", "error": None}, 2)
    assert limited["exit_code"] == 0
    assert limited["output"] == "f:1:a\nf:2:b"

    grep_err = ex.find_result(
        {"exit_code": 2, "output": "grep: bad", "error": None}, 50)
    assert grep_err["exit_code"] == 2
    assert grep_err["output"] == "grep: bad"


# ---------------------------------------------------------------------------
# M5 additions: vendored parity, registry semantics, register modes,
# CLI add-host, ~/.ssh/config discovery, executor resolution.
# ---------------------------------------------------------------------------

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_VENDORED_EXECUTOR = os.path.join(_REPO_ROOT, "plugin", "agssh", "executor.py")
_SRC_EXECUTOR = os.path.join(
    _REPO_ROOT, "src", "executor", "persist_ssh_ext.py")
_CLI_PATH = os.path.join(_REPO_ROOT, "bin", "agssh")


def _load_cli():
    """bin/agssh has no .py suffix; load it by explicit path like the
    plugin loads its executor."""
    loader = importlib.machinery.SourceFileLoader("agssh_cli", _CLI_PATH)
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# U9 — vendored parity: plugin/agssh/executor.py and
# src/executor/persist_ssh_ext.py are the same file shipped two ways.
# ---------------------------------------------------------------------------

def test_u9_vendored_parity():
    with open(_VENDORED_EXECUTOR, "rb") as f:
        vendored = f.read()
    with open(_SRC_EXECUTOR, "rb") as f:
        src = f.read()
    assert vendored == src


# ---------------------------------------------------------------------------
# U10 — registry default: CONFIG_PATH falls back to
# ~/.config/agssh/hosts.json (env override wins), the first-run seed is
# {"hosts": {}} and load_config never prints.
# ---------------------------------------------------------------------------

def test_u10_default_seed_silent(ex, tmp_path, monkeypatch, capsys):
    """Registry is per profile, loading never creates it, add-host creates
    it 0600 (maintainer review items 1 and 2)."""
    monkeypatch.delenv("PERSIST_SSH_CONFIG", raising=False)
    monkeypatch.delenv("AGSSH_REGISTRY", raising=False)

    assert ex.DEFAULT_SEED == {"hosts": {}}
    default = ex._default_config_path()
    assert default.endswith(
        os.path.join("plugin-data", "agssh", "hosts.json"))
    assert "persist-ssh" not in default
    assert ex._hermes_home() in default

    primary = tmp_path / "fresh" / "agssh" / "hosts.json"
    monkeypatch.setattr(ex, "CONFIG_PATH", str(primary))
    monkeypatch.setattr(ex, "LEGACY_CONFIG_PATHS",
                        [str(tmp_path / "absent-legacy.json")])
    monkeypatch.setattr(ex, "_LEGACY_MERGE", True)

    cfg = ex.load_config()
    captured = capsys.readouterr()
    assert captured.out == "" and captured.err == ""
    assert cfg == {"hosts": {}}
    # Loading must NOT create the registry file or its directory.
    assert not primary.exists()
    assert not primary.parent.exists()

    # First write (add-host path) creates it, mode 0600.
    ex.save_config({"hosts": {"web1": {"host": "192.0.2.10"}}})
    assert primary.exists()
    assert stat.S_IMODE(primary.stat().st_mode) == 0o600


# ---------------------------------------------------------------------------
# U11 — legacy merge: with the default primary, a legacy
# ~/.config/persist-ssh.json is merged in read-only — its hosts appear
# under the primary's, the primary wins per alias, and the legacy file is
# never written back. An explicit env path disables the merge entirely.
# ---------------------------------------------------------------------------

def test_u11_legacy_merge_read_only(ex, tmp_path, monkeypatch):
    monkeypatch.delenv("PERSIST_SSH_CONFIG", raising=False)
    monkeypatch.delenv("AGSSH_REGISTRY", raising=False)

    primary = tmp_path / "agssh" / "hosts.json"
    legacy = tmp_path / "persist-ssh.json"
    primary.parent.mkdir(parents=True)
    primary.write_text(json.dumps({
        "hosts": {"web1": {"host": "192.0.2.10", "user": "deploy"}}}))
    legacy_payload = {
        "hosts": {
            "web1": {"host": "10.9.9.9"},        # shadowed by the primary
            "old1": {"host": "192.0.2.20"},      # legacy-only, merged in
        }}
    legacy.write_text(json.dumps(legacy_payload))
    monkeypatch.setattr(ex, "CONFIG_PATH", str(primary))
    monkeypatch.setattr(ex, "LEGACY_CONFIG_PATHS", [str(legacy)])
    monkeypatch.setattr(ex, "_LEGACY_MERGE", True)

    cfg = ex.load_config()
    assert set(cfg["hosts"]) == {"web1", "old1"}
    assert cfg["hosts"]["web1"]["host"] == "192.0.2.10"  # primary wins
    assert cfg["hosts"]["old1"]["host"] == "192.0.2.20"

    # An explicit env path (_LEGACY_MERGE off) sees only the primary.
    monkeypatch.setattr(ex, "_LEGACY_MERGE", False)
    cfg_no_merge = ex.load_config()
    assert set(cfg_no_merge["hosts"]) == {"web1"}
    monkeypatch.setattr(ex, "_LEGACY_MERGE", True)

    # Read-only: neither the merge nor a save writes the legacy file; the
    # merged view persists only to the primary.
    ex.save_config(cfg)
    assert json.loads(legacy.read_text()) == legacy_payload
    assert json.loads(primary.read_text())["hosts"]["old1"]["host"] \
        == "192.0.2.20"


# ---------------------------------------------------------------------------
# U12 — catalog mode (the default): an empty registry registers exactly
# {agssh, agssh-read, agssh-find, agssh-hosts}; the generic host parameter
# has NO enum until validated hosts exist, then it is the sorted aliases.
# ---------------------------------------------------------------------------

def test_u12_catalog_mode_register(ex, fake_ctx, tmp_registry, make_key):
    import agssh
    import agssh.handlers

    # --- empty registry, default config: generic surface, no enum ---
    tmp_registry.write({})
    agssh.register(fake_ctx)
    names = {t["name"] for t in fake_ctx.tools}
    assert names == {"agssh", "agssh-read", "agssh-find", "agssh-hosts"}
    generic = next(t for t in fake_ctx.tools if t["name"] == "agssh")
    host_prop = generic["schema"]["parameters"]["properties"]["host"]
    assert "enum" not in host_prop
    assert "host" in generic["schema"]["parameters"]["required"]

    # --- two valid hosts: enum is the sorted aliases ---
    key = make_key()
    hosts = {
        "web1": {"host": "192.0.2.10", "user": "deploy",
                 "key": key, "port": 22},
        "db1": {"host": "192.0.2.11", "user": "deploy",
                "key": key, "port": 22},
    }
    tmp_registry.write(hosts)
    ctx2 = type(fake_ctx)()
    agssh.register(ctx2)
    assert agssh.handlers.MODE == "generic"
    names2 = {t["name"] for t in ctx2.tools}
    assert names2 == {"agssh", "agssh-read", "agssh-find", "agssh-hosts"}
    enum = next(t for t in ctx2.tools if t["name"] == "agssh")[
        "schema"]["parameters"]["properties"]["host"]["enum"]
    assert enum == sorted(hosts)


# ---------------------------------------------------------------------------
# U13 — local mode: settings per_host_tools=True registers one
# agssh-<alias> command tool per validated host and no generic `agssh`.
# ---------------------------------------------------------------------------

def test_u13_local_mode_per_host(ex, fake_ctx, tmp_registry, make_key):
    import agssh
    import agssh.handlers

    fake_ctx.settings["per_host_tools"] = True
    key = make_key()
    hosts = {
        "web1": {"host": "192.0.2.10", "user": "deploy",
                 "key": key, "port": 22},
        "db1": {"host": "192.0.2.11", "user": "deploy",
                "key": key, "port": 22},
    }
    tmp_registry.write(hosts)
    agssh.register(fake_ctx)

    assert agssh.handlers.MODE == "per-host"
    names = [t["name"] for t in fake_ctx.tools]
    for alias in hosts:
        assert f"agssh-{alias}" in names
    assert "agssh" not in names
    for verb in _VERBS:
        assert verb in names


# ---------------------------------------------------------------------------
# U14 — CLI add-host: bin/agssh main(["add-host", ...]) writes the entry
# into the env-pointed registry; a second call for the same alias and a
# leading-digit alias both refuse with exit 2 and write nothing.
# ---------------------------------------------------------------------------

def test_u14_cli_add_host(ex, tmp_registry, make_key):
    cli = _load_cli()
    key = make_key()
    tmp_registry.write({})

    assert cli.main(["add-host", "web1", "--host", "192.0.2.10",
                     "--key", key]) == 0
    with open(tmp_registry.path) as f:
        hosts = json.load(f)["hosts"]
    assert hosts["web1"]["host"] == "192.0.2.10"
    assert hosts["web1"]["user"] == "root"          # --user default
    assert hosts["web1"]["key"] == key
    assert hosts["web1"]["port"] == 22
    assert hosts["web1"]["control_persist"] == 3600
    assert hosts["web1"]["accept_new"] is True

    # duplicate alias refuses with exit 2
    with pytest.raises(SystemExit) as dup:
        cli.main(["add-host", "web1", "--host", "192.0.2.99"])
    assert dup.value.code == 2

    # leading-digit alias refuses with exit 2
    with pytest.raises(SystemExit) as bad:
        cli.main(["add-host", "9x", "--host", "192.0.2.11"])
    assert bad.value.code == 2

    # failed calls wrote nothing
    with open(tmp_registry.path) as f:
        assert set(json.load(f)["hosts"]) == {"web1"}


# ---------------------------------------------------------------------------
# U15 — ~/.ssh/config discovery: `Host` aliases (wildcards skipped) are
# listed by _ssh_config_aliases and surface in agssh-hosts output as
# unregistered.
# ---------------------------------------------------------------------------

def test_u15_ssh_config_discovery(ex, fake_ctx, tmp_registry,
                                  monkeypatch, tmp_path):
    import agssh
    import agssh.handlers

    home = tmp_path / "home"
    ssh_dir = home / ".ssh"
    ssh_dir.mkdir(parents=True)
    (ssh_dir / "config").write_text(
        "Host alpha beta\n"
        "    HostName 192.0.2.10\n"
        "Host *\n"
        "    ServerAliveInterval 30\n")
    monkeypatch.setenv("HOME", str(home))
    tmp_registry.write({})
    agssh.register(fake_ctx)

    assert agssh.handlers._ssh_config_aliases() == ["alpha", "beta"]
    env = json.loads(agssh.handlers.handle_hosts({}))
    assert env["exit_code"] == 0
    assert "~/.ssh/config" in env["output"]
    assert "not registered" in env["output"]
    assert "alpha" in env["output"]
    assert "beta" in env["output"]


# ---------------------------------------------------------------------------
# U16 — executor resolution: with AGSSH_EXECUTOR unset,
# handlers.executor_path() resolves the vendored in-plugin executor.
# ---------------------------------------------------------------------------

def test_u16_executor_path_vendored(monkeypatch):
    import agssh.handlers

    monkeypatch.delenv("AGSSH_EXECUTOR", raising=False)
    expected = os.path.join(
        os.path.dirname(os.path.abspath(agssh.handlers.__file__)),
        "executor.py")
    assert os.path.isfile(expected)
    assert agssh.handlers.executor_path() == expected


# ---------------------------------------------------------------------------
# U12 — child environment allowlist (maintainer review item 3). ssh/scp
# children must never inherit the parent Hermes environment: provider API
# keys plus a SendEnv/AcceptEnv pair would forward them to the remote host.
# ---------------------------------------------------------------------------

def test_u12_child_env_allowlist(ex, monkeypatch):
    monkeypatch.setenv("AGSSH_TEST_SECRET", "do-not-forward-me")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-unit-test-should-not-leak")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-should-not-leak")
    monkeypatch.setenv("PATH", "/usr/bin:/bin")
    monkeypatch.setenv("HOME", "/home/tester")
    monkeypatch.setenv("LC_ALL", "C.UTF-8")
    monkeypatch.setenv("SSH_AUTH_SOCK", "/tmp/agent.sock")

    env = ex._child_env()
    assert "AGSSH_TEST_SECRET" not in env
    assert "OPENAI_API_KEY" not in env
    assert "ANTHROPIC_API_KEY" not in env
    assert not any("KEY" in k or "TOKEN" in k or "SECRET" in k for k in env), env
    assert env["PATH"] == "/usr/bin:/bin"
    assert env["HOME"] == "/home/tester"
    assert env["LC_ALL"] == "C.UTF-8"
    assert env["SSH_AUTH_SOCK"] == "/tmp/agent.sock"
    allowed = {"PATH", "HOME", "USER", "LOGNAME", "LANG", "SSH_AUTH_SOCK", "TERM"}
    assert all(k in allowed or k.startswith("LC_") for k in env), env


def test_u13_no_skill_path_fallback():
    """The bundled executor is always present; no ~/.hermes/skills probing.
    handlers.py uses a relative import, so assert on the shipped source and
    on the vendored file rather than importing it outside its package."""
    src = open(os.path.join(_REPO_ROOT, "plugin", "agssh", "handlers.py")).read()
    assert ".hermes/skills" not in src, "skill-path fallback still present"
    assert "persistent-ssh" not in src, "skill-path fallback still present"
    assert os.path.isfile(_VENDORED_EXECUTOR)


def test_u14_audit_redacts_secrets(ex, tmp_path, monkeypatch):
    """Audit lines must not store raw credentials (review recommendation 2)."""
    log = tmp_path / "agssh.log"
    monkeypatch.setattr(ex, "_audit_log_path", lambda: str(log))
    ex.audit_call("web1", 0, 5, 10, False, "tool",
                  "curl -H 'Authorization: Bearer sk-abcdef0123456789abcdef' https://x")
    text = log.read_text()
    assert "sk-abcdef0123456789abcdef" not in text, text
