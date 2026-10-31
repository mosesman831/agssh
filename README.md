# agssh

Per-host remote execution tools for AI agents. A machine in your registry becomes a tool with the
same call shape, result shape and exit semantics as the agent's local `terminal` tool, so the model
never builds an `ssh '...'` string again.

**Status: spec stage. Nothing is built yet.** The spec is written and gated; implementation starts at
milestone M0.

## The problem

Measured over one real agent session operating a production host:

- 78 terminal calls: 37 ssh, 31 file read/search through the shell, 8 run/build, 2 network
- 32,615 characters of command text (~8.1k tokens), of which 8,986 characters were
  `cd X && grep -n ... -A 20` pipelines
- 2 calls failed on nested quoting; 1 used the wrong key
- 0 of 37 exit codes survived, because every call ended `2>&1 | tail -20`

The transport was being assembled by the model, per call, as a shell string. That is the bug.

## The shape

```
~/.config/persist-ssh.json      one registry, shared by the human and the agent
        │
        ├── agssh <alias> -- <command>        CLI, remote exit code passthrough
        ├── agssh-<alias>(command=...)        native tool, one per registered host
        ├── agssh-read(host, path, ...)       read_file parity over the registry
        └── agssh-find(host, pattern, ...)    search_files parity over the registry
```

A call goes from this:

```python
terminal(command="ssh -i ~/.ssh/k -o BatchMode=yes ubuntu@10.0.0.1 'cd /srv/x && sudo systemctl stop app; ... 2>&1 | tail -20'")
```

to this:

```python
agssh_fat1(command="systemctl stop app")
```

## Design rules

- The command is transmitted as exactly one argv element, quoted once, so it arrives byte-exact.
- The tool's exit code is the remote command's exit code. Timeouts kill the remote process.
- Output is capped inside the tool, which makes the `| tail` habit pointless.
- One executor, three front doors: the CLI and the tools share one code path, so behaviour cannot
  drift between what a human types and what the agent calls.
- Reuses the existing `persist-ssh` control-master machinery instead of a second SSH stack.

## Non-goals

No sftp or file sync, no port forwarding, no remote policy engine, no PTY, no background jobs in
v1, no second SSH implementation, no new config format.

## Documentation

`agssh-SPEC-EXTREME.md` and the draft it rewrote are kept locally and deliberately **not committed**
(spec documents are ignored by `.gitignore`). Ask the maintainer if you need them.

## Licence

Not yet chosen.