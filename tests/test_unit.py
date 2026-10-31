"""agssh spec section 12 — unit layer U1..U8.

Executor tests (U1-U4, U7, U8) run against ``src/executor/persist_ssh_ext.py``
loaded through the ``ex`` fixture. Plugin tests (U5, U6) import the ``agssh``
package lazily inside the test body, so collection of the executor tests does
not depend on the plugin existing.
"""

import importlib
import inspect
import json
import shlex
import sys

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
    ("fat.1", False),
    ("9foo", False),
    ("fat1", True),
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
# U5 — Q4 switch: <=10 validated hosts register per-host tools and no generic
# `agssh`; >10 registers ONE generic `agssh` whose host param is the alias
# enum, and no per-host command tools. Verbs exist in both modes.
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

    # --- reset plugin module state, 11 hosts: generic mode ---
    for modname in ("agssh.guard", "agssh.handlers"):
        if modname in sys.modules:
            importlib.reload(sys.modules[modname])
    agssh = importlib.reload(agssh)

    hosts11 = _hosts(11, key)
    tmp_registry.write(hosts11)
    ctx2 = type(fake_ctx)()
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

_U6_HOSTS = {"fatpsyk": {"host": "140.238.97.70", "user": "ubuntu", "port": 22}}

_U6_MATCH = [
    "ssh fatpsyk true",
    "ssh ubuntu@140.238.97.70",
    "bash -c 'ssh fatpsyk true'",
    "bash -lc 'ssh ubuntu@140.238.97.70 x'",
    "ssh -i ~/.ssh/k -p 22 ubuntu@140.238.97.70",
    "x; ssh 140.238.97.70",
    "echo hi | ssh fatpsyk",
    "ssh -- fatpsyk",
]

_U6_NO_MATCH = [
    "echo ssh fatpsyk",
    "ssh-keygen -l",
    "scp a fatpsyk:b",
    "sftp fatpsyk",
    "ssh 192.0.2.1 true",
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
        "fatpsyk": {
            "host": "140.238.97.70",
            "user": "ubuntu",
            "key": key,
            "port": 22,
        },
    })

    # Case A: non-empty output blocks the retry — exactly one capture call.
    events = _wire_retry_stubs(ex, monkeypatch, [(255, "some output", False, False)])
    env = ex.execute("fatpsyk", "true")
    assert events.count("run_capture") == 1
    assert env["exit_code"] == -1
    assert "connect failed" in env["error"]
    assert "fatpsyk" in env["error"]

    # Case B: first failure empty (retryable), second failure reported —
    # never a third call. Covers both a second connect and a second mux.
    for second_output in ("", "mux_client_request_session: fail"):
        events = _wire_retry_stubs(
            ex, monkeypatch,
            [(255, "", False, False),
             (255, second_output, False, False),
             (0, "x", False, False)])
        env = ex.execute("fatpsyk", "true")
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
    env = ex.execute("fatpsyk", "true")
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
