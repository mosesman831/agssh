#!/usr/bin/env python3
"""
persist-ssh.py - ControlMaster session manager for agent SSH workflows.

Why this exists:
    Rapid-fire `ssh user@host "cmd"` calls spawn a fresh sshd pre-auth child per
    connection. On Ubuntu 24.04 the default MaxStartups 10:30:100 exhausts after
    ~10 quick connections and every subsequent attempt fails with
    `kex_exchange_identification: read: Connection reset by peer` (and sometimes
    a misleading transient `Permission denied (publickey)` on valid keys).

    ControlMaster multiplexing reuses ONE TCP connection for all commands, so it
    never consumes a new sshd auth slot. This script wraps that pattern: setup,
    run, list, close - with a host registry so aliases like `fatpms3` just work.

Stdlib only (argparse, subprocess, json, glob). No pip installs.

Usage:
    persist-ssh.py setup <name>          # open background ControlMaster (idempotent)
    persist-ssh.py run <name> -- <cmd>   # run command via the shared socket (auto-setup)
    persist-ssh.py status <name>         # is the master socket alive?
    persist-ssh.py list                  # all master sockets + alive state
    persist-ssh.py close <name>          # close the master socket
    persist-ssh.py scp <name> <local> <remote>    # upload via the shared socket
    persist-ssh.py fetch <name> <remote> <local>  # download via the shared socket
    persist-ssh.py add-host <name> --host IP [--user U] [--key K] [--port P]

Config: ~/.config/persist-ssh.json (auto-seeded with the fat proxies on first run).
Env override: PERSIST_SSH_CONFIG=/path/to/config.json

agssh extension (see agssh spec):
    execute() is the library entry point shared by the agssh plugin tools and
    the `agssh` CLI. It never prints and never calls sys.exit; it returns the
    envelope dict {output, exit_code, host, cwd, duration_ms, truncated,
    full_output_path, error}.
"""

import argparse
import codecs
import contextlib
import datetime
import errno
import fcntl
import io
import glob
import json
import os
import re
import select
import shlex
import shutil
import stat
import subprocess
import sys
import time
import uuid

CONFIG_PATH = os.environ.get(
    "PERSIST_SSH_CONFIG", os.path.expanduser("~/.config/persist-ssh.json")
)

# Auto-seeded on first run so the fat proxies work with zero setup.
# Edit ~/.config/persist-ssh.json to add your own hosts.
DEFAULT_SEED = {
    "hosts": {
        "fatp015": {
            "host": "132.145.20.34",
            "user": "ubuntu",
            "key": "~/.ssh/oci_fat_proxy",
            "port": 22,
            "control_persist": 3600,
            "accept_new": True,
        },
        "fatpms3": {
            "host": "141.147.111.247",
            "user": "ubuntu",
            "key": "~/.ssh/oci_fat_proxy_2",
            "port": 22,
            "control_persist": 3600,
            "accept_new": True,
        },
        "acct3": {
            "host": "140.238.102.148",
            "user": "ubuntu",
            "key": "~/.ssh/oci_fat_proxy_3",
            "port": 22,
            "control_persist": 3600,
            "accept_new": True,
        },
        "fatpsyk": {
            "host": "140.238.97.70",
            "user": "ubuntu",
            "key": "~/.ssh/oci_fat_proxy_4",
            "port": 22,
            "control_persist": 3600,
            "accept_new": True,
        },
    }
}


def load_config():
    if not os.path.exists(CONFIG_PATH):
        os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
        with open(CONFIG_PATH, "w") as f:
            json.dump(DEFAULT_SEED, f, indent=2)
        print(f"[persist-ssh] created {CONFIG_PATH} (seeded with fat proxies)")
    with open(CONFIG_PATH) as f:
        return json.load(f)


def save_config(cfg):
    with open(CONFIG_PATH, "w") as f:
        json.dump(cfg, f, indent=2)


def get_host(cfg, name):
    hosts = cfg.get("hosts", {})
    if name not in hosts:
        sys.exit(
            f"error: unknown host '{name}'. Known: {', '.join(sorted(hosts)) or '(none)'}."
            + " Add with: persist-ssh.py add-host <name> --host IP [--user U] [--key K]"
        )
    return hosts[name]


def control_path(name, info):
    """Matches the %r@%h:%p convention used across the skill docs."""
    return os.path.expanduser(f"~/.ssh/cm-{name}-{info['user']}@{info['host']}:{info.get('port', 22)}")


def ssh_base_args(info, cp, extra=None):
    args = ["ssh", "-o", f"ControlPath={cp}"]
    if extra:
        args.extend(extra)
    args += ["-i", os.path.expanduser(info["key"]), "-p", str(info.get("port", 22))]
    return args


def master_alive(name, info):
    """True when `ssh -O check` against the control socket exits 0. The check is
    killed at 6 seconds; a hung check means the master is dead to us (STALE)."""
    cp = control_path(name, info)
    try:
        r = subprocess.run(
            ["ssh", "-O", "check", "-o", f"ControlPath={cp}",
             "-o", "ConnectTimeout=5",
             f"{info['user']}@{info['host']}"],
            capture_output=True,
            timeout=6,
        )
        return r.returncode == 0
    except subprocess.TimeoutExpired:
        return False


def _master_argv(name, info):
    """argv for the one ControlMaster spawn (`ensure_master` and `setup`)."""
    return (
        ["ssh", "-o", "ControlMaster=yes",
         "-o", f"ControlPath={control_path(name, info)}",
         "-o", f"ControlPersist={info.get('control_persist', 600)}",
         "-o", f"ConnectTimeout={info.get('connect_timeout', 10)}",
         "-o", "IdentitiesOnly=yes",
         "-o", "BatchMode=yes",
         "-o", f"StrictHostKeyChecking={'accept-new' if info.get('accept_new') else 'yes'}",
         "-fN", "-i", os.path.expanduser(info["key"]),
         "-p", str(info.get("port", 22)),
         f"{info['user']}@{info['host']}"]
    )


def _wait_master_up(name, info, tries=10, interval=0.5):
    for _ in range(tries):
        if master_alive(name, info):
            return True
        time.sleep(interval)
    return False


def setup(name, info, quiet=False):
    cp = control_path(name, info)
    if master_alive(name, info):
        if not quiet:
            print(f"[persist-ssh] {name}: master already alive ({cp})")
        return True
    r = subprocess.run(_master_argv(name, info), capture_output=True, text=True)
    if r.returncode != 0:
        err = (r.stderr or r.stdout or "").lower()
        hint = ""
        if "kex_exchange_identification" in err or "connection reset" in err:
            hint = (
                "\n  -> Looks like sshd MaxStartups exhaustion on the target."
                " Wait ~30-60s and retry, or fix permanently with the cloud-init"
                " snippet in the persistent-ssh skill (MaxStartups 500:30:1000)."
            )
        elif "permission denied" in err:
            hint = (
                "\n  -> Permission denied. If this key worked before, the box may be"
                " thrashing MaxStartups (transient false denial). Wait and retry."
            )
        sys.exit(f"[persist-ssh] setup failed for {name}: {r.stderr.strip()}{hint}")
    # Verify the master actually came up before claiming success
    if _wait_master_up(name, info):
        if not quiet:
            print(f"[persist-ssh] {name}: master up ({cp})")
        return True
    sys.exit(f"[persist-ssh] {name}: master socket did not come up after setup")


def run_command(name, info, cmd, timeout=None):
    setup(name, info, quiet=True)
    cp = control_path(name, info)
    args = ssh_base_args(info, cp) + [f"{info['user']}@{info['host']}"] + cmd
    try:
        return subprocess.run(args, timeout=timeout)
    except subprocess.TimeoutExpired:
        sys.exit(f"[persist-ssh] command timed out after {timeout}s (host {name})")


def transfer(name, info, src, dst, direction):
    setup(name, info, quiet=True)
    cp = control_path(name, info)
    base = ["scp", "-o", f"ControlPath={cp}", "-i", os.path.expanduser(info["key"]),
            "-P", str(info.get("port", 22))]
    target = f"{info['user']}@{info['host']}"
    if direction == "upload":
        args = base + [src, f"{target}:{dst}"]
    else:
        args = base + [f"{target}:{src}", dst]
    return subprocess.run(args)


def do_list():
    cfg = load_config()
    sockets = sorted(glob.glob(os.path.expanduser("~/.ssh/cm-*")))
    if not sockets:
        print("[persist-ssh] no ControlMaster sockets found")
        return
    print(f"{'name':<12} {'socket':<45} alive")
    print("-" * 75)
    for sock in sockets:
        base = os.path.basename(sock)
        # cm-<name>-<user>@<host>:<port>  ->  strip the cm- prefix for display
        display = base[3:]
        name = display.split("-")[0]
        info = cfg.get("hosts", {}).get(name)
        alive = "?"
        if info:
            alive = "yes" if master_alive(name, info) else "no (stale)"
        print(f"{name:<12} {display:<45} {alive}")


# --------------------------------------------------------------------------
# agssh executor (spec: sections 5.3, 5.5, 6, 7, 8, 10)
# --------------------------------------------------------------------------

ALIAS_RE = re.compile(r"[a-z][a-z0-9-]{0,30}")

OUTPUT_CAP_CHARS = 96_000
OUTPUT_HEAD_CHARS = 57_600
OUTPUT_TAIL_CHARS = 38_400
CAPTURE_MAX_CHARS = 2_000_000
DEFAULT_TIMEOUT_S = 180
MAX_TIMEOUT_S = 600

AUDIT_ROTATE_BYTES = 5_242_880
LOCK_POLL_S = 0.05
LOCK_GIVE_UP_S = 20.0
WATCHDOG_SLACK_S = 3

# The audit `via` field is "tool" or "cli". The CLI leaves the default; the
# plugin sets this to "tool" once when it loads the executor.
AGSSH_VIA = "cli"

RUN_DEPRECATION_DATE = "2026-11-14"
RUN_DEPRECATION_LINE = (
    "[persist-ssh] run still forwards argv; agssh <alias> -- <command> is the"
    f" byte-exact path. run will call execute on {RUN_DEPRECATION_DATE}."
)


class ConnectError(Exception):
    """Transport/setup failure carrying the classifier bucket and the exact
    public error sentence for the envelope."""

    def __init__(self, class_name, public_error):
        super().__init__(public_error)
        self.class_name = class_name
        self.public_error = public_error


def _hermes_home():
    return os.path.expanduser(os.environ.get("HERMES_HOME") or "~/.hermes")


def _audit_log_path():
    return os.path.join(_hermes_home(), "logs", "agssh.log")


def _spill_dir():
    return os.path.join(_hermes_home(), "cache", "agssh")


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


def audit_call(host, exit_code, duration_ms, chars, truncated, via, command):
    """B15: one line per call, including denials, under a lock, one-generation
    rotation at AUDIT_ROTATE_BYTES. Never raises into the call path."""
    try:
        log_path = _audit_log_path()
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
        flat = str(command)[:200].replace("\n", "\\n")
        host = str(host).replace("\n", "\\n")
        stamp = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
        line = (f"{stamp} {host} {exit_code} {int(duration_ms)} {chars} "
                f"{'true' if truncated else 'false'} {via} {flat}\n")
        lock_fd = os.open(log_path + ".lock", os.O_CREAT | os.O_WRONLY, 0o600)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            try:
                if os.path.getsize(log_path) >= AUDIT_ROTATE_BYTES:
                    os.replace(log_path, log_path + ".1")
            except OSError:
                pass
            with open(log_path, "a") as f:
                f.write(line)
        finally:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(lock_fd)
    except OSError:
        pass


def quote_shell(text):
    """The one and only shlex.quote in the codebase. Called only from
    build_remote_command."""
    return shlex.quote(str(text))


def build_remote_command(command, *, workdir, timeout_s, login_shell, sentinel):
    """Return the single argv element passed after `user@host`.

    `command` is either the raw shell string (quoted once) or an argv sequence
    (each element quoted, then joined - this is how read/find verbs keep their
    patterns byte-exact). Either way quote_shell is only ever called here.
    """
    if not isinstance(command, str):
        command = " ".join(quote_shell(part) for part in command)
    inner = quote_shell(command)
    payload = ""
    if workdir:
        payload += f"cd -- {quote_shell(workdir)} && "
    payload += f"timeout -k 2 {int(timeout_s)}s bash -c {inner} -- {sentinel}"
    flag = "-lc" if login_shell else "-c"
    return f"bash {flag} {quote_shell(payload)}"


def classify_failure(output, returncode):
    """B14: 124 is always a timeout. Marker classes are only meaningful on
    rc 255 (ssh's own diagnostics); a remote command whose output happens to
    contain marker text keeps its real status (R3)."""
    if returncode == 124:
        return "timeout"
    if returncode == 255:
        low = (output or "").lower()
        if "kex_exchange_identification" in low or "connection reset" in low:
            return "maxstartups"
        if "permission denied" in low and "publickey" in low:
            return "publickey"
        if ("controlsocket" in low or "mux_client" in low
                or "already exists" in low):
            return "mux"
        return "connect"
    return "remote"


def _socket_lock_path(name):
    return os.path.expanduser(f"~/.ssh/cm-{name}.lock")


def _acquire_socket_lock(name):
    """fcntl.flock LOCK_EX|LOCK_NB polled at 50ms, give up at 20s. Returns an
    open fd the caller releases with _release_socket_lock."""
    fd = os.open(_socket_lock_path(name), os.O_CREAT | os.O_RDWR, 0o600)
    try:
        os.fchmod(fd, 0o600)
    except OSError:
        pass
    deadline = time.monotonic() + LOCK_GIVE_UP_S
    while True:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return fd
        except OSError as exc:
            if exc.errno not in (errno.EACCES, errno.EAGAIN):
                os.close(fd)
                raise
            if time.monotonic() >= deadline:
                os.close(fd)
                raise ConnectError(
                    "lock",
                    f"connect failed for '{name}': control socket lock held for 20s",
                )
            time.sleep(LOCK_POLL_S)


def _release_socket_lock(fd):
    try:
        fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def purge_socket(name, info):
    """Remove exactly control_path(name, info); nothing else."""
    try:
        os.remove(control_path(name, info))
    except FileNotFoundError:
        pass


def _socket_signature(cp):
    try:
        st = os.stat(cp)
        return (st.st_dev, st.st_ino)
    except OSError:
        return None


def _purge_socket_locked(name, info):
    """purge_socket under the alias flock; raises ConnectError('socket_dir')
    when the control path is a directory (left in place)."""
    fd = _acquire_socket_lock(name)
    try:
        dir_err = _socket_dir_error(name, info)
        if dir_err is not None:
            raise dir_err
        purge_socket(name, info)
    finally:
        _release_socket_lock(fd)


def _confirm_dead_mid(name, info, sig):
    """A transport failure on the in-flight command is dead_mid iff the
    socket that carried it died: the file vanished, was replaced, or is the
    same dead file. Runs under the flock so a peer cannot resurrect a new
    master between our probe and the verdict (the re-run ban is absolute)."""
    fd = _acquire_socket_lock(name)
    try:
        cp = control_path(name, info)
        now = _socket_signature(cp)
        if sig is None:
            # No socket carried this command; ssh could not have run it.
            # Absent-absent is a cold failure; a dead appeared-then-died file
            # is ambiguous, so it stays dead_mid.
            if now is None:
                return False
            return not master_alive(name, info)
        if now is None:
            return True
        if now != sig:
            if not os.path.isdir(cp) and not master_alive(name, info):
                try:
                    os.remove(cp)
                except OSError:
                    pass
            return True
        if master_alive(name, info):
            return False
        if not os.path.isdir(cp):
            try:
                os.remove(cp)
            except OSError:
                pass
        return True
    finally:
        _release_socket_lock(fd)


def socket_state(name, info):
    """absent | alive | stale, probed under the same per-alias flock."""
    try:
        fd = _acquire_socket_lock(name)
    except ConnectError:
        return "stale"
    try:
        if not os.path.exists(control_path(name, info)):
            return "absent"
        return "alive" if master_alive(name, info) else "stale"
    finally:
        _release_socket_lock(fd)


def _socket_dir_error(name, info):
    cp = control_path(name, info)
    if os.path.isdir(cp):
        return ConnectError(
            "socket_dir", f"control socket for '{name}' is a directory: {cp}")
    return None


def _spawn_and_verify(name, info):
    """Run the -fN master spawn once; verify with the 10x0.5s loop.

    Returns None when the master came up, else (returncode, stderr_text).
    """
    try:
        r = subprocess.run(
            _master_argv(name, info), capture_output=True, text=True,
            timeout=int(info.get("connect_timeout", 10)) + 15)
    except subprocess.TimeoutExpired:
        return (-1, "ssh master spawn timed out locally")
    if r.returncode == 0 and _wait_master_up(name, info):
        return None
    return (r.returncode, (r.stderr or r.stdout or ""))


def _spawn_setup_error(name, info, returncode, err):
    low = (err or "").lower()
    cls = classify_failure(err, returncode)
    if cls == "maxstartups":
        return ConnectError(
            "maxstartups",
            f"connect failed for '{name}': sshd refused the connection"
            " (MaxStartups); retried once after 30s",
        )
    if cls == "publickey":
        key_path = os.path.expanduser(info.get("key") or "")
        return ConnectError(
            "publickey",
            f"connect failed for '{name}': permission denied (publickey)"
            f" for key {key_path}; not retried",
        )
    if cls == "mux":
        return ConnectError(
            "mux",
            f"connect failed for '{name}': control socket failed twice;"
            " not retried",
        )
    return ConnectError(
        "connect",
        f"connect failed for '{name}' after {info.get('connect_timeout', 10)}s:"
        f" ssh exit {returncode} (socket purged, retried once on a new master)",
    )


def ensure_master(name, info, deadline):
    """Per-alias control-socket state machine. Returns None when a master is
    ALIVE; raises ConnectError otherwise.

    The flock covers probe, purge and setup only, so concurrent commands share
    one master. A waiter re-checks master_alive after winning the lock and does
    not spawn -fN while another caller holds the lock.
    """
    fd = _acquire_socket_lock(name)
    try:
        if master_alive(name, info):
            return
        cp = control_path(name, info)
        if os.path.exists(cp):
            dir_err = _socket_dir_error(name, info)
            if dir_err is not None:
                raise dir_err
            purge_socket(name, info)
        # STARTING
        maxstartups_retried = False
        already_exists_retried = False
        while True:
            failed = _spawn_and_verify(name, info)
            if failed is None:
                return
            returncode, err = failed
            if returncode == 0:
                # spawn returned 0 but the socket never answered -O check:
                # purge the dead socket and fail (STARTING -> fail).
                purge_socket(name, info)
                raise ConnectError(
                    "mux",
                    f"connect failed for '{name}': control socket failed"
                    " twice; not retried",
                )
            low = (err or "").lower()
            # `ControlPath ... already exists`: someone else's socket file won
            # the race. ALIVE within 5s is fine; otherwise one purge + one setup.
            if "already exists" in low and not already_exists_retried:
                already_exists_retried = True
                t_end = time.monotonic() + 5
                while time.monotonic() < t_end:
                    if master_alive(name, info):
                        return
                    time.sleep(0.25)
                dir_err = _socket_dir_error(name, info)
                if dir_err is not None:
                    raise dir_err
                purge_socket(name, info)
                continue
            cls = classify_failure(err, returncode)
            if (
                cls == "maxstartups"
                and not maxstartups_retried
                and (deadline - time.monotonic()) > 35
            ):
                maxstartups_retried = True
                time.sleep(30)
                continue
            raise _spawn_setup_error(name, info, returncode, err)
    finally:
        _release_socket_lock(fd)


def _command_argv(name, info, remote_element, connect_timeout):
    return [
        "ssh",
        "-o", "ControlMaster=no",
        "-o", f"ControlPath={control_path(name, info)}",
        "-o", "IdentitiesOnly=yes",
        "-o", "BatchMode=yes",
        "-o", f"ConnectTimeout={connect_timeout}",
        "-o", f"StrictHostKeyChecking={'accept-new' if info.get('accept_new') else 'yes'}",
        "-i", os.path.expanduser(info["key"]),
        "-p", str(info.get("port", 22)),
        f"{info['user']}@{info['host']}",
        remote_element,
    ]


def _run_capture(argv, watchdog_s, capture_max):
    """Run argv, stdout+stderr on one pipe, no local shell.

    Stops reading at capture_max bytes and kills the ssh (capture_ceiling), or
    kills it when the local watchdog fires (the remote `timeout -k 2` is the
    primary bound; this is the backstop for a hung mux/ssh).

    Returns (returncode, output_text, hit_ceiling, watchdog_fired).
    """
    proc = subprocess.Popen(
        argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    fd = proc.stdout.fileno()
    os.set_blocking(fd, False)
    buf = bytearray()
    dec = codecs.getincrementaldecoder("utf-8")(errors="replace")
    chars = 0
    hit_ceiling = watchdog = False
    deadline = time.monotonic() + watchdog_s
    while True:
        done = proc.poll() is not None
        while chars < capture_max:
            try:
                chunk = os.read(fd, 65536)
            except (BlockingIOError, OSError):
                chunk = b""
            if not chunk:
                break
            buf += chunk
            chars += len(dec.decode(chunk))
        if done:
            break
        if chars >= capture_max:
            hit_ceiling = True
            proc.kill()
            break
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            watchdog = True
            proc.kill()
            break
        try:
            select.select([fd], [], [], min(0.1, max(0.0, remaining)))
        except (OSError, ValueError):
            break
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        pass
    while not hit_ceiling and chars < capture_max:
        try:
            chunk = os.read(fd, 65536)
        except (BlockingIOError, OSError):
            break
        if not chunk:
            break
        buf += chunk
        chars += len(dec.decode(chunk))
    try:
        proc.stdout.close()
    except OSError:
        pass
    rc = proc.returncode if proc.returncode is not None else -9
    return rc, bytes(buf).decode("utf-8", "replace"), hit_ceiling, watchdog


def _remote_pkill(name, info, sentinel):
    """Best-effort remote kill of the sentinel's process group leftovers.

    `[a]gssh-<rest>` keeps pkill's own argv (and the ssh carrying it) from
    matching the pattern. Runs only when the local watchdog fired, never when
    the remote already reported status 124.
    """
    pattern = "[a]gssh-" + sentinel[len("agssh-"):]
    remote = build_remote_command(
        ["pkill", "-f", pattern], workdir=None, timeout_s=10,
        login_shell=False, sentinel="agssh-pkill")
    argv = _command_argv(name, info, remote,
                         int(info.get("connect_timeout", 10)))
    try:
        subprocess.run(argv, capture_output=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired):
        pass


def _write_spill(host, output):
    """Spill path, mode 0600: ~/.hermes/cache/agssh/{host}-{ts}-{pid}.log"""
    spill_dir = _spill_dir()
    os.makedirs(spill_dir, exist_ok=True)
    stamp = datetime.datetime.now().strftime("%Y%m%dT%H%M%S")
    path = os.path.join(spill_dir, f"{host}-{stamp}-{os.getpid()}.log")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(output)
    return path


def _cap_model_output(output):
    return output[:OUTPUT_HEAD_CHARS] + output[-OUTPUT_TAIL_CHARS:]


def _key_problem(alias, info):
    key_path = os.path.expanduser(info.get("key") or "")
    try:
        st = os.stat(key_path)  # follows symlinks
    except OSError:
        return f"key for host '{alias}' not readable: {key_path} (expected mode 600)"
    if not stat.S_ISREG(st.st_mode) or stat.S_IMODE(st.st_mode) & 0o077:
        return f"key for host '{alias}' not readable: {key_path} (expected mode 600)"
    return None


def _failure_error(name, info, cls, returncode):
    """Terminal (non-retried) failure rows from the section 10 taxonomy."""
    if cls == "mux":
        return (f"connect failed for '{name}': control socket failed twice;"
                " not retried")
    if cls == "connect":
        return (f"connect failed for '{name}' after"
                f" {info.get('connect_timeout', 10)}s: ssh exit {returncode}"
                " (socket purged, retried once on a new master)")
    if cls == "maxstartups":
        return (f"connect failed for '{name}': sshd refused the connection"
                " (MaxStartups); retried once after 30s")
    if cls == "publickey":
        key_path = os.path.expanduser(info.get("key") or "")
        return (f"connect failed for '{name}': permission denied (publickey)"
                f" for key {key_path}; not retried")
    if cls == "timeout":
        return None  # handled by the timeout row
    return None


def _timeout_error(name, timeout_s):
    return (f"timed out after {timeout_s}s on '{name}';"
            " remote process killed (best effort)")


def _command_ok(command):
    if isinstance(command, str):
        return bool(command.strip())
    try:
        return any(str(part).strip() for part in command)
    except TypeError:
        return False


def execute(name, command, *, workdir=None, timeout_s=DEFAULT_TIMEOUT_S,
            capture_max=CAPTURE_MAX_CHARS):
    """Run `command` on host `name` over the shared ControlMaster.

    Returns the envelope dict. Never prints, never sys.exit. `command` may be
    a string or an argv sequence (read/find verbs); quoting happens only in
    build_remote_command.
    """
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            cfg = load_config()
        hosts = cfg.get("hosts", {})
    except (OSError, ValueError) as exc:
        hosts = {}
        cfg_error = exc
    else:
        cfg_error = None
    start = time.monotonic()

    def finish(env):
        audit_call(
            env.get("host") or name or "",
            env.get("exit_code", -1),
            env.get("duration_ms", 0),
            len(env.get("output") or ""),
            env.get("truncated", False),
            AGSSH_VIA,
            command,
        )
        return env

    if cfg_error is not None:
        return finish(_envelope(
            host=name if isinstance(name, str) else str(name or ""),
            error=f"registry unreadable: {cfg_error}"))
    if not isinstance(name, str) or not ALIAS_RE.fullmatch(name):
        return finish(_envelope(
            host=str(name or ""),
            error=f"alias '{name}' rejected: must match [a-z][a-z0-9-]{{0,30}}",
        ))
    if name not in hosts:
        known = ", ".join(sorted(hosts)) or "(none)"
        return finish(_envelope(
            host=name,
            error=f"unknown host '{name}'. Known: {known}.",
        ))
    info = hosts[name] or {}
    if info.get("as_tool", True) is False:
        return finish(_envelope(
            host=name,
            error=f"host '{name}' is registered but as_tool is false",
        ))
    if not _command_ok(command):
        return finish(_envelope(
            host=name, error="command must be a non-empty string"))
    bad_timeout = (
        isinstance(timeout_s, bool)
        or not isinstance(timeout_s, (int, float))
        or int(timeout_s) < 1
        or int(timeout_s) > MAX_TIMEOUT_S
    )
    if bad_timeout:
        return finish(_envelope(
            host=name,
            error=f"timeout must be 1..600 seconds (got {timeout_s})",
        ))
    timeout_s = int(timeout_s)
    eff_workdir = (
        workdir if isinstance(workdir, str) and workdir
        else info.get("default_workdir"))
    cwd = eff_workdir if isinstance(eff_workdir, str) and eff_workdir else None
    key_err = _key_problem(name, info)
    if key_err:
        return finish(_envelope(host=name, error=key_err))
    if shutil.which("ssh") is None:
        return finish(_envelope(
            host=name,
            error=f"connect failed for '{name}': ssh not found on PATH",
        ))
    connect_timeout = int(info.get("connect_timeout", 10))
    login_shell = bool(info.get("login_shell", True))

    sentinel = f"agssh-{uuid.uuid4().hex}"
    hay = (command if isinstance(command, str)
           else " ".join(map(str, command)))
    while sentinel in hay:
        sentinel = f"agssh-{uuid.uuid4().hex}"

    try:
        ensure_master(name, info, start + timeout_s + WATCHDOG_SLACK_S)
    except ConnectError as exc:
        return finish(_envelope(
            host=name, duration_ms=_ms_since(start), error=exc.public_error))
    except OSError as exc:
        return finish(_envelope(
            host=name, duration_ms=_ms_since(start),
            error=f"connect failed for '{name}': {exc}"))

    attempted = 0
    while True:
        attempted += 1
        remote = build_remote_command(
            command, workdir=eff_workdir, timeout_s=timeout_s,
            login_shell=login_shell, sentinel=sentinel)
        argv = _command_argv(name, info, remote, connect_timeout)
        sock_sig = _socket_signature(control_path(name, info))
        t_run = time.monotonic()
        try:
            rc, output, hit_ceiling, watchdog = _run_capture(
                argv, timeout_s + WATCHDOG_SLACK_S, capture_max)
        except OSError as exc:
            return finish(_envelope(
                host=name, duration_ms=_ms_since(t_run),
                error=f"connect failed for '{name}': {exc}"))
        duration_ms = _ms_since(t_run)

        if watchdog:
            _remote_pkill(name, info, sentinel)
            return finish(_envelope(
                output=output, host=name, cwd=cwd, duration_ms=duration_ms,
                error=_timeout_error(name, timeout_s)))
        if hit_ceiling:
            spill = _write_spill(name, output)
            return finish(_envelope(
                output=_cap_model_output(output), exit_code=rc, host=name,
                cwd=cwd, duration_ms=duration_ms, truncated=True,
                full_output_path=spill,
                error=(f"capture stopped at {capture_max} chars on '{name}';"
                       f" full text at {spill}")))

        cls = classify_failure(output, rc)
        if rc == 0 or cls == "remote":
            break

        if cls in ("mux", "connect", "maxstartups") \
                and _confirm_dead_mid(name, info, sock_sig):
            # The socket that carried the command is dead: remote status
            # unknown, never re-run.
            return finish(_envelope(
                output=output, host=name, cwd=cwd, duration_ms=duration_ms,
                error=(f"command on '{name}' lost its control socket mid-run;"
                       " remote status unknown; not retried")))
        if cls == "timeout":
            return finish(_envelope(
                output=output, host=name, cwd=cwd, duration_ms=duration_ms,
                error=_timeout_error(name, timeout_s)))
        if attempted == 1 and cls in ("mux", "maxstartups", "connect") \
                and not output.strip():
            # One retry: purge (locked), ensure_master, re-run, multiplexed.
            try:
                _purge_socket_locked(name, info)
                ensure_master(name, info,
                              time.monotonic() + timeout_s + WATCHDOG_SLACK_S)
            except ConnectError as exc:
                return finish(_envelope(
                    host=name, duration_ms=duration_ms,
                    error=exc.public_error))
            continue
        return finish(_envelope(
            output=output, host=name, cwd=cwd, duration_ms=duration_ms,
            error=_failure_error(name, info, cls, rc)))

    if len(output) > OUTPUT_CAP_CHARS:
        spill = _write_spill(name, output)
        return finish(_envelope(
            output=_cap_model_output(output), exit_code=rc, host=name,
            cwd=cwd, duration_ms=duration_ms, truncated=True,
            full_output_path=spill,
            error=(f"output truncated at {OUTPUT_CAP_CHARS} chars;"
                   f" full text at {spill}")))
    return finish(_envelope(
        output=output, exit_code=rc, host=name, cwd=cwd,
        duration_ms=duration_ms))


def _ms_since(t0):
    return int((time.monotonic() - t0) * 1000)


def read_argv(path, offset, limit):
    """sed argv for agssh-read, unquoted (build_remote_command quotes it)."""
    offset = max(1, int(offset))
    limit = max(1, min(2000, int(limit)))
    return ["sed", "-n", f"{offset},{offset + limit - 1}p", "--", str(path)]


def find_argv(pattern, path, file_glob, context):
    """grep argv for agssh-find, unquoted. -e guards a `-`-leading pattern."""
    argv = ["grep", "-n", "-E", "-r"]
    ctx = int(context or 0)
    if ctx > 0:
        argv += ["-C", str(min(20, ctx))]
    if file_glob:
        argv += ["--include", str(file_glob)]
    argv += ["-e", str(pattern), "--", str(path)]
    return argv


_FIND_MATCH_LINE = re.compile(r"^[^:\n]*:\d+:")


def find_result(envelope, limit):
    """agssh-find envelope remap, shared by the CLI and the plugin handler:
    grep status 1 -> exit 0 with empty output; status >= 2 returned as-is;
    otherwise keep the first `limit` matching lines locally."""
    rc = envelope.get("exit_code", -1)
    if rc == 1:
        envelope["exit_code"] = 0
        envelope["output"] = ""
        envelope["error"] = None
        return envelope
    if rc != 0:
        return envelope
    limit = max(1, min(200, int(limit or 50)))
    kept, matches = [], 0
    for line in (envelope.get("output") or "").splitlines():
        if matches >= limit:
            break
        kept.append(line)
        if _FIND_MATCH_LINE.match(line):
            matches += 1
    envelope["output"] = "\n".join(kept)
    return envelope


def valid_alias(name):
    return isinstance(name, str) and bool(ALIAS_RE.fullmatch(name))


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(
        prog="persist-ssh",
        description="ControlMaster session manager for agent SSH workflows.",
    )
    sub = p.add_subparsers(dest="command", required=True)

    s_setup = sub.add_parser("setup", help="open a background ControlMaster (idempotent)")
    s_setup.add_argument("name")

    s_run = sub.add_parser("run", help="run a command via the shared socket")
    s_run.add_argument("name")
    s_run.add_argument("cmd_args", nargs=argparse.REMAINDER)
    s_run.add_argument("--timeout", type=int, default=None)

    s_status = sub.add_parser("status", help="is the master socket alive?")
    s_status.add_argument("name")

    s_list = sub.add_parser("list", help="all master sockets + alive state")

    s_close = sub.add_parser("close", help="close the master socket")
    s_close.add_argument("name")

    s_scp = sub.add_parser("scp", help="upload a file via the shared socket")
    s_scp.add_argument("name")
    s_scp.add_argument("local")
    s_scp.add_argument("remote")

    s_fetch = sub.add_parser("fetch", help="download a file via the shared socket")
    s_fetch.add_argument("name")
    s_fetch.add_argument("remote")
    s_fetch.add_argument("local")

    s_add = sub.add_parser("add-host", help="register a host alias")
    s_add.add_argument("name")
    s_add.add_argument("--host", required=True)
    s_add.add_argument("--user", default="ubuntu")
    s_add.add_argument("--key", default="~/.ssh/id_ed25519")
    s_add.add_argument("--port", type=int, default=22)
    s_add.add_argument("--persist", type=int, default=3600)

    args = p.parse_args()
    cfg = load_config()

    if args.command == "setup":
        setup(args.name, get_host(cfg, args.name))
    elif args.command == "run":
        if not args.cmd_args or (len(args.cmd_args) == 1 and args.cmd_args[0] == "--"):
            sys.exit("error: run requires a command: persist-ssh run <name> -- <cmd>")
        cmd = [c for c in args.cmd_args if c != "--"]
        print(RUN_DEPRECATION_LINE, file=sys.stderr)
        r = run_command(args.name, get_host(cfg, args.name), cmd, timeout=args.timeout)
        sys.exit(r.returncode)
    elif args.command == "status":
        info = get_host(cfg, args.name)
        print("alive" if master_alive(args.name, info) else "dead")
    elif args.command == "list":
        do_list()
    elif args.command == "close":
        info = get_host(cfg, args.name)
        cp = control_path(args.name, info)
        r = subprocess.run(
            ["ssh", "-O", "exit", "-o", f"ControlPath={cp}",
             f"{info['user']}@{info['host']}"],
            capture_output=True, text=True,
        )
        print(f"[persist-ssh] {args.name}: closed" if r.returncode == 0
              else f"[persist-ssh] {args.name}: nothing to close ({r.stderr.strip()})")
    elif args.command == "scp":
        sys.exit(transfer(args.name, get_host(cfg, args.name),
                          args.local, args.remote, "upload").returncode)
    elif args.command == "fetch":
        sys.exit(transfer(args.name, get_host(cfg, args.name),
                          args.remote, args.local, "download").returncode)
    elif args.command == "add-host":
        if not valid_alias(args.name):
            sys.exit(
                f"error: alias '{args.name}' rejected: must match"
                " [a-z0-9][a-z0-9-]{0,30}")
        cfg.setdefault("hosts", {})[args.name] = {
            "host": args.host, "user": args.user, "key": args.key,
            "port": args.port, "control_persist": args.persist,
            "accept_new": True,
        }
        save_config(cfg)
        print(f"[persist-ssh] registered '{args.name}' -> {args.user}@{args.host}")


if __name__ == "__main__":
    main()
