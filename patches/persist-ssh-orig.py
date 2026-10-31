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
"""

import argparse
import glob
import json
import os
import subprocess
import sys
import time

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


def setup(name, info, quiet=False):
    cp = control_path(name, info)
    if master_alive(name, info):
        if not quiet:
            print(f"[persist-ssh] {name}: master already alive ({cp})")
        return True
    args = [
        "ssh", "-o", "ControlMaster=yes",
        "-o", f"ControlPath={cp}",
        "-o", f"ControlPersist={info.get('control_persist', 600)}",
        "-o", f"ConnectTimeout={info.get('connect_timeout', 10)}",
        "-o", "IdentitiesOnly=yes",
        "-o", "BatchMode=yes",
        "-o", f"StrictHostKeyChecking={'accept-new' if info.get('accept_new') else 'yes'}",
        "-fN", "-i", os.path.expanduser(info["key"]),
        "-p", str(info.get("port", 22)),
        f"{info['user']}@{info['host']}",
    ]
    r = subprocess.run(args, capture_output=True, text=True)
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
    for _ in range(10):
        if master_alive(name, info):
            break
        time.sleep(0.5)
    else:
        sys.exit(f"[persist-ssh] {name}: master socket did not come up after setup")
    if not quiet:
        print(f"[persist-ssh] {name}: master up ({cp})")
    return True


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
        cfg.setdefault("hosts", {})[args.name] = {
            "host": args.host, "user": args.user, "key": args.key,
            "port": args.port, "control_persist": args.persist,
            "accept_new": True,
        }
        save_config(cfg)
        print(f"[persist-ssh] registered '{args.name}' -> {args.user}@{args.host}")


if __name__ == "__main__":
    main()
