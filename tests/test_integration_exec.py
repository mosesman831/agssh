"""Integration tests for the agssh executor against the live `fatpsyk` host.

Scope discipline: the ONLY host these tests may touch is `fatpsyk`
(140.238.97.70, key ~/.ssh/oci_fat_proxy_4). Remote actions are read-only
probes plus writes strictly under /tmp/agssh-a10. Never sudo, systemctl,
rm, mkfs, dd, shutdown, reboot, package installs, or writes outside /tmp.

Fixtures come from tests/conftest.py: `ex` is the loaded executor module
(execute(name, command, *, workdir=None, timeout_s=180, capture_max=...)
returns the envelope dict {output, exit_code, host, cwd, duration_ms,
truncated, full_output_path, error}); `prod_guard` is autouse. Most tests
run against the live registry (~/.config/persist-ssh.json), which already
contains the fatpsyk alias.
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

import pytest

pytestmark = pytest.mark.skipif(
    not os.path.exists(os.path.expanduser("~/.ssh/oci_fat_proxy_4")),
    reason="fatpsyk key missing",
)

ALIAS = "fatpsyk"
REMOTE_DIR = "/tmp/agssh-a10"
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXECUTOR_PATH = os.path.join(REPO_ROOT, "src", "executor", "persist_ssh_ext.py")
SOCKET_GLOB = os.path.expanduser("~/.ssh/cm-fatpsyk-*")


def _info(ex):
    """Registry entry for fatpsyk from the live config."""
    return ex.load_config()["hosts"][ALIAS]


def _control_path(ex):
    return ex.control_path(ALIAS, _info(ex))


def _sockets():
    return glob.glob(SOCKET_GLOB)


def _stop_master(ex):
    """Best-effort teardown: politely ask the ControlMaster to exit (this
    removes the socket file server-side too), then purge any remnant."""
    info = _info(ex)
    cp = ex.control_path(ALIAS, info)
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
    ex.purge_socket(ALIAS, info)


def test_a1_byte_exact(ex):
    """The command string reaches the remote shell byte-exact through every
    quoting layer (mux argv, build_remote_command, bash -lc)."""
    # Shell text: printf '%s' "a'b\"c$d\`e<real newline>newline"
    # printf '%s' emits the argument verbatim: a'b"c`e\nnewline
    command = "printf '%s' \"a'b\\\"c$d\\`e\nnewline\""
    local = subprocess.run(
        ["bash", "-lc", command], capture_output=True, text=True
    ).stdout
    env = ex.execute(ALIAS, command)
    assert env["error"] is None
    assert env["exit_code"] == 0
    assert env["output"] == local


def test_a2_exit_code(ex):
    env = ex.execute(ALIAS, "sh -c 'exit 7'")
    assert env["exit_code"] == 7
    assert env["error"] is None


def test_a3_streams(ex):
    """stdout and stderr are merged into output, in order."""
    env = ex.execute(ALIAS, "sh -c 'echo out; echo err >&2; exit 3'")
    assert env["exit_code"] == 3
    assert env["error"] is None
    assert "out" in env["output"]
    assert "err" in env["output"]
    assert env["output"].index("out") < env["output"].index("err")


def test_a5_timeout_kills_remote(ex):
    # Warm the master so connect setup doesn't eat the timeout budget.
    warm = ex.execute(ALIAS, "true")
    assert warm["error"] is None
    t0 = time.monotonic()
    env = ex.execute(ALIAS, "sleep 300", timeout_s=5)
    elapsed = time.monotonic() - t0
    assert elapsed <= 8.0
    assert env["exit_code"] == -1
    assert "timed out after 5s" in (env["error"] or "")
    # The remote `timeout -k 2` must have killed the sleep for real.
    check = ex.execute(ALIAS, 'pgrep -f "sle[e]p 300" || echo GONE')
    assert "GONE" in check["output"]


def test_a8_workdir_per_call(ex):
    env = ex.execute(ALIAS, "pwd", workdir="/tmp")
    assert env["error"] is None
    assert env["output"].strip() == "/tmp"
    assert env["cwd"] == "/tmp"
    # workdir is per-call, never sticky.
    env2 = ex.execute(ALIAS, "pwd")
    assert env2["error"] is None
    assert env2["cwd"] != "/tmp"
    assert env2["output"].strip() != "/tmp"


def test_a9_six_parallel(ex):
    """Six threads multiplex over ONE control socket, each keeping its own
    output and exit code."""
    ex.execute(ALIAS, "true")  # warm master first

    def run(i):
        return i, ex.execute(ALIAS, f"echo {i}; exit {i % 2}")

    with ThreadPoolExecutor(max_workers=6) as pool:
        results = dict(pool.map(run, range(6)))

    assert len(results) == 6
    for i, env in results.items():
        assert env["error"] is None
        assert env["output"].strip() == str(i)
        assert env["exit_code"] == i % 2
    assert len(_sockets()) == 1


def test_a13_cold_race(ex):
    """Two fresh OS processes race to create the master from cold. The flock
    serializes setup: both succeed and exactly one socket results."""
    _stop_master(ex)
    assert not os.path.exists(_control_path(ex))

    src = os.path.realpath(getattr(ex, "__file__", EXECUTOR_PATH))
    assert os.path.isfile(src)
    child = (
        "import importlib.util,json,sys;"
        "spec=importlib.util.spec_from_file_location('p',sys.argv[1]);"
        "m=importlib.util.module_from_spec(spec);"
        "spec.loader.exec_module(m);"
        "e=m.execute('fatpsyk','echo ok');"
        "print(json.dumps(e))"
    )
    env = dict(os.environ)
    # The children must use the real registry and their own module instance.
    env.pop("PERSIST_SSH_CONFIG", None)
    env["AGSSH_EXECUTOR"] = src
    procs = [
        subprocess.Popen(
            [sys.executable, "-c", child, src],
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


def test_a14_stale_file(ex):
    """A regular file at the control path counts as stale: execute purges it
    and replaces it with a real live socket."""
    _stop_master(ex)
    info = _info(ex)
    cp = ex.control_path(ALIAS, info)
    with open(cp, "w") as f:
        f.write("x")
    assert ex.socket_state(ALIAS, info) == "stale"

    env = ex.execute(ALIAS, "echo ok")
    assert env["exit_code"] == 0
    assert env["error"] is None
    # The planted regular file is gone; a real socket file is in its place.
    assert os.path.exists(cp)
    assert stat.S_ISSOCK(os.stat(cp).st_mode)


def test_a10_find_verb(ex):
    setup = ex.execute(
        ALIAS,
        "mkdir -p /tmp/agssh-a10/sub"
        " && printf 'alpha reingest one\nbeta\n' > /tmp/agssh-a10/f1.txt"
        " && printf 'reingest two\nreingest three\n' > /tmp/agssh-a10/sub/f2.txt"
        " && printf 'nothing\n' > /tmp/agssh-a10/f3.txt",
    )
    assert setup["exit_code"] == 0

    env = ex.execute(ALIAS, ex.find_argv("reingest", REMOTE_DIR, None, 0))
    env = ex.find_result(env, 50)
    assert env["exit_code"] == 0
    lines = [l for l in env["output"].splitlines() if re.search(r":\d+:", l)]
    assert len(lines) == 3
    files = {os.path.basename(l.split(":")[0]) for l in lines}
    assert files == {"f1.txt", "f2.txt"}

    # grep status 1 (no matches) is remapped to exit 0 with empty output.
    miss = ex.execute(
        ALIAS, ex.find_argv("zzz-no-such-token-zzz", REMOTE_DIR, None, 0)
    )
    miss = ex.find_result(miss, 50)
    assert miss["exit_code"] == 0
    assert miss["output"] == ""
