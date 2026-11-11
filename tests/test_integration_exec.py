"""Integration tests for the agssh executor against a live SSH host.

Scope discipline: the ONLY host these tests may touch is the
AGSSH_TEST_HOST registry alias, resolved by tests/conftest.py from the
operator's live registries (~/.config/agssh/hosts.json then
~/.config/persist-ssh.json). Remote actions are read-only probes plus
writes strictly under /tmp/agssh-a10. Never sudo, systemctl, rm, mkfs,
dd, shutdown, reboot, package installs, or writes outside /tmp.

Fixtures come from tests/conftest.py: `ex` is the loaded executor module
(execute(name, command, *, workdir=None, timeout_s=180, capture_max=...)
returns the envelope dict {output, exit_code, host, cwd, duration_ms,
truncated, full_output_path, error}); `test_host` is the AGSSH_TEST_HOST
registry entry; `prod_guard` is autouse. Every test exercises the real
host, so each carries @requires_host — with AGSSH_TEST_HOST unset the
module collects and skips cleanly.
"""

import glob
import json
import os
import re
import stat
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor

from conftest import DEFAULT_EXECUTOR_PATH, TEST_ALIAS, requires_host

REMOTE_DIR = "/tmp/agssh-a10"
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SOCKET_GLOB = os.path.expanduser(f"~/.ssh/cm-{TEST_ALIAS}-*")


def _sockets():
    return glob.glob(SOCKET_GLOB)


def _stop_master(ex, info):
    """Best-effort teardown: politely ask the ControlMaster to exit (this
    removes the socket file server-side too), then purge any remnant."""
    cp = ex.control_path(TEST_ALIAS, info)
    try:
        subprocess.run(
            [
                "ssh", "-O", "exit",
                "-o", f"ControlPath={cp}",
                "-o", "BatchMode=yes",
                "-i", os.path.expanduser(info["key"]),
                "-p", str(info.get("port", 22)),
                f"{info['user']}@{info['host']}",
            ],
            capture_output=True,
            timeout=20,
        )
    except (OSError, subprocess.TimeoutExpired):
        pass
    ex.purge_socket(TEST_ALIAS, info)


@requires_host
def test_a1_byte_exact(ex, test_host):
    """The command string reaches the remote shell byte-exact through every
    quoting layer (mux argv, build_remote_command, bash -lc)."""
    # Shell text: printf '%s' "a'b\"c$d\`e<real newline>newline"
    # printf '%s' emits the argument verbatim: a'b"c`e\nnewline
    command = "printf '%s' \"a'b\\\"c$d\\`e\nnewline\""
    local = subprocess.run(
        ["bash", "-lc", command], capture_output=True, text=True
    ).stdout
    env = ex.execute(TEST_ALIAS, command)
    assert env["error"] is None
    assert env["exit_code"] == 0
    assert env["output"] == local


@requires_host
def test_a2_exit_code(ex, test_host):
    env = ex.execute(TEST_ALIAS, "sh -c 'exit 7'")
    assert env["exit_code"] == 7
    assert env["error"] is None


@requires_host
def test_a3_streams(ex, test_host):
    """stdout and stderr are merged into output, in order."""
    env = ex.execute(TEST_ALIAS, "sh -c 'echo out; echo err >&2; exit 3'")
    assert env["exit_code"] == 3
    assert env["error"] is None
    assert "out" in env["output"]
    assert "err" in env["output"]
    assert env["output"].index("out") < env["output"].index("err")


@requires_host
def test_a5_timeout_kills_remote(ex, test_host):
    # Warm the master so connect setup doesn't eat the timeout budget.
    warm = ex.execute(TEST_ALIAS, "true")
    assert warm["error"] is None
    t0 = time.monotonic()
    env = ex.execute(TEST_ALIAS, "sleep 300", timeout_s=5)
    elapsed = time.monotonic() - t0
    assert elapsed <= 8.0
    assert env["exit_code"] == -1
    assert "timed out after 5s" in (env["error"] or "")
    # The remote `timeout -k 2` must have killed the sleep for real.
    check = ex.execute(TEST_ALIAS, 'pgrep -f "sle[e]p 300" || echo GONE')
    assert "GONE" in check["output"]


@requires_host
def test_a8_workdir_per_call(ex, test_host):
    env = ex.execute(TEST_ALIAS, "pwd", workdir="/tmp")
    assert env["error"] is None
    assert env["output"].strip() == "/tmp"
    assert env["cwd"] == "/tmp"
    # workdir is per-call, never sticky.
    env2 = ex.execute(TEST_ALIAS, "pwd")
    assert env2["error"] is None
    assert env2["cwd"] != "/tmp"
    assert env2["output"].strip() != "/tmp"


@requires_host
def test_a9_six_parallel(ex, test_host):
    """Six threads multiplex over ONE control socket, each keeping its own
    output and exit code."""
    ex.execute(TEST_ALIAS, "true")  # warm master first

    def run(i):
        return i, ex.execute(TEST_ALIAS, f"echo {i}; exit {i % 2}")

    with ThreadPoolExecutor(max_workers=6) as pool:
        results = dict(pool.map(run, range(6)))

    assert len(results) == 6
    for i, env in results.items():
        assert env["error"] is None
        assert env["output"].strip() == str(i)
        assert env["exit_code"] == i % 2
    assert len(_sockets()) == 1


@requires_host
def test_a13_cold_race(ex, test_host):
    """Two fresh OS processes race to create the master from cold. The flock
    serializes setup: both succeed and exactly one socket results."""
    _stop_master(ex, test_host)
    assert not os.path.exists(ex.control_path(TEST_ALIAS, test_host))

    src = os.path.realpath(getattr(ex, "__file__", DEFAULT_EXECUTOR_PATH))
    assert os.path.isfile(src)
    child = (
        "import importlib.util,json,sys;"
        "spec=importlib.util.spec_from_file_location('p',sys.argv[1]);"
        "m=importlib.util.module_from_spec(spec);"
        "spec.loader.exec_module(m);"
        "e=m.execute(sys.argv[2],'echo ok');"
        "print(json.dumps(e))"
    )
    env = dict(os.environ)
    # The children must use the real registry and their own module instance.
    env.pop("PERSIST_SSH_CONFIG", None)
    env.pop("AGSSH_REGISTRY", None)
    env["AGSSH_EXECUTOR"] = src
    procs = [
        subprocess.Popen(
            [sys.executable, "-c", child, src, TEST_ALIAS],
            cwd=REPO_ROOT,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for _ in range(2)
    ]
    envelopes = []
    for p in procs:
        out, err = p.communicate(timeout=120)
        assert p.returncode == 0, f"child died: rc={p.returncode} stderr={err}"
        envelopes.append(json.loads(out.strip().splitlines()[-1]))

    assert len(envelopes) == 2
    for e in envelopes:
        assert e["exit_code"] == 0
        assert e["error"] is None
    assert len(_sockets()) == 1


@requires_host
def test_a14_stale_file(ex, test_host):
    """A regular file at the control path counts as stale: execute purges it
    and replaces it with a real live socket."""
    _stop_master(ex, test_host)
    cp = ex.control_path(TEST_ALIAS, test_host)
    with open(cp, "w") as f:
        f.write("x")
    assert ex.socket_state(TEST_ALIAS, test_host) == "stale"

    env = ex.execute(TEST_ALIAS, "echo ok")
    assert env["exit_code"] == 0
    assert env["error"] is None
    # The planted regular file is gone; a real socket file is in its place.
    assert os.path.exists(cp)
    assert stat.S_ISSOCK(os.stat(cp).st_mode)


@requires_host
def test_a10_find_verb(ex, test_host):
    setup = ex.execute(
        TEST_ALIAS,
        "mkdir -p /tmp/agssh-a10/sub"
        " && printf 'alpha reingest one\nbeta\n' > /tmp/agssh-a10/f1.txt"
        " && printf 'reingest two\nreingest three\n' > /tmp/agssh-a10/sub/f2.txt"
        " && printf 'nothing\n' > /tmp/agssh-a10/f3.txt",
    )
    assert setup["exit_code"] == 0

    env = ex.execute(TEST_ALIAS, ex.find_argv("reingest", REMOTE_DIR, None, 0))
    env = ex.find_result(env, 50)
    assert env["exit_code"] == 0
    lines = [l for l in env["output"].splitlines() if re.search(r":\d+:", l)]
    assert len(lines) == 3
    files = {os.path.basename(l.split(":")[0]) for l in lines}
    assert files == {"f1.txt", "f2.txt"}

    # grep status 1 (no matches) is remapped to exit 0 with empty output.
    miss = ex.execute(
        TEST_ALIAS, ex.find_argv("zzz-no-such-token-zzz", REMOTE_DIR, None, 0)
    )
    miss = ex.find_result(miss, 50)
    assert miss["exit_code"] == 0
    assert miss["output"] == ""


@requires_host
def test_a19_vendored_executor_no_skill(ex, test_host, tmp_registry,
                                        monkeypatch):
    """A fresh install with no skill script executes end to end.

    handlers.executor_path() resolves $AGSSH_EXECUTOR -> the vendored
    plugin/agssh/executor.py -> the persist-ssh skill copy. With the env
    override popped and the vendored file present, the skill path is never
    consulted — the module doesn't reference it at all — so this loads the
    vendored executor directly and proves the self-contained path."""
    import importlib.util

    tmp_registry.write({TEST_ALIAS: test_host})
    monkeypatch.delenv("AGSSH_EXECUTOR", raising=False)
    vendored = os.path.join(REPO_ROOT, "plugin", "agssh", "executor.py")
    spec = importlib.util.spec_from_file_location("vendored_ex", vendored)
    vex = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(vex)

    env = vex.execute(TEST_ALIAS, "hostname")
    assert env["exit_code"] == 0
    assert env["error"] is None
    assert env["output"].strip()


# --------------------------------------------------------------------------
# A20: argv-form `agssh <alias> -- <command...>` regression for cmd_exec.
#
# After `--`, len(command)>1 composes the remote string as
# " ".join(shlex.quote(e) for e in command); len(command)==1 passes the
# element through byte-exact. A bare join would splice `sh -c 'exit 7'`
# into `sh -c exit 7`, running `sh -c exit` and losing the remote exit
# code. These tests run bin/agssh as a real subprocess so the remote exit
# code becomes the process returncode and remote stdout lands byte-exact
# on proc.stdout. `ex` is taken for its env side effects: the exported
# AGSSH_EXECUTOR (and isolated HERMES_HOME) ride into the child via
# env=os.environ.copy(); `test_host` skips early if the alias is unknown.
# --------------------------------------------------------------------------

AGSSH_CLI = os.path.join(REPO_ROOT, "bin", "agssh")


def _run_cli(command):
    """Run `agssh <TEST_ALIAS> -- <command...>` in a fresh process.

    ``command`` is the argv list after ``--`` (one element per remote
    word). Returns the CompletedProcess with byte stdout/stderr.
    """
    return subprocess.run(
        [sys.executable, AGSSH_CLI, TEST_ALIAS, "--", *command],
        capture_output=True,
        env=os.environ.copy(),
        timeout=120,
    )


@requires_host
def test_a20a_argv_exit_code_7(ex, test_host):
    """["sh", "-c", "exit 7"] must yield remote exit 7 — a bare join would
    splice to `sh -c exit 7`, which runs `sh -c exit` and returns 0."""
    proc = _run_cli(["sh", "-c", "exit 7"])
    assert proc.returncode == 7, f"rc={proc.returncode} stderr={proc.stderr!r}"


@requires_host
def test_a20b_argv_exit_code_3(ex, test_host):
    """Same shape, different code: remote `exit 3` survives as rc 3."""
    proc = _run_cli(["sh", "-c", "exit 3"])
    assert proc.returncode == 3, f"rc={proc.returncode} stderr={proc.stderr!r}"


@requires_host
def test_a20c_argv_byte_exact_nasty(ex, test_host):
    """printf %s emits the argv element verbatim — every shell metachar
    (squote, dquote, $, backtick, backslash, newline, tab) survives the
    quote-each-element-and-join path byte-exact, with no trailing newline
    added by any layer."""
    nasty = "a'b\"c$HOME`x`\\d\n\tend"
    proc = _run_cli(["printf", "%s", nasty])
    assert proc.returncode == 0, f"rc={proc.returncode} stderr={proc.stderr!r}"
    assert proc.stdout == nasty.encode("utf-8")


@requires_host
def test_a20d_argv_echo_words(ex, test_host):
    """Plain words join with single spaces: `echo a b c` -> "a b c\\n"."""
    proc = _run_cli(["echo", "a", "b", "c"])
    assert proc.returncode == 0, f"rc={proc.returncode} stderr={proc.stderr!r}"
    assert proc.stdout == b"a b c\n"


@requires_host
def test_a20e_single_element_passthrough(ex, test_host):
    """One element after `--` is passed through byte-exact, so the caller's
    own quoting is honoured: ["sh -c 'exit 7'"] still exits 7."""
    proc = _run_cli(["sh -c 'exit 7'"])
    assert proc.returncode == 7, f"rc={proc.returncode} stderr={proc.stderr!r}"
