"""A11 replay harness for the amended agssh spec (agssh-SPEC-EXTREME.md §12).

Pure-stdlib, pytest-free module: constants and pure functions the acceptance
test file calls to replay the synthetic corpus through the executor at
``plugin/agssh/executor.py``. The corpus was real session evidence until
M5; it now ships generic infrastructure vocabulary only (see
tests/fixtures/replay_corpus.jsonl).

    FIXTURE_PATH / load_corpus        committed JSONL replay corpus
    DANGEROUS_SUBSTRINGS              spec §12 skip list
    POLICY_PATTERNS / classify_row    flagged|dangerous|policy|exec
    model_command                     strip `| tail` segments (A11.3)
    VOLATILE_PATTERNS / normalize     mask non-deterministic output tokens
    is_transport_error                envelope error -> transport class
    READSEARCH_VERBS / iter_pipelines A11.4 read/search lane splitting
    is_readsearch / route_segment     pipeline -> agssh-read/-find call
    route_row / route_calls           per-row read/search lane map
    FIXTURE_TREE / tree_write_argv    /tmp/agssh-a11 fixture tree on the
                                      AGSSH_TEST_HOST integration host
    remap_path / route_to_call        corpus paths -> fixture tree paths

The module never runs commands itself; the test file owns execute().
"""

import json
import re
import shlex
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_PATH = REPO_ROOT / "tests" / "fixtures" / "replay_corpus.jsonl"
EXECUTOR_PATH = REPO_ROOT / "plugin" / "agssh" / "executor.py"


# ---------------------------------------------------------------------------
# Corpus loading (item 1)
# ---------------------------------------------------------------------------

def load_corpus(path=FIXTURE_PATH):
    """Read the replay corpus JSONL into a list of {command, skip} dicts.

    A11 fails closed on a missing fixture: raise FileNotFoundError with a
    clear message rather than returning an empty list. Malformed lines raise
    ValueError naming the line number.
    """
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(
            f"A11 replay corpus missing: {p} (expected the committed fixture "
            "tests/fixtures/replay_corpus.jsonl; A11 fails closed when the "
            "fixture is absent)")
    rows = []
    for lineno, line in enumerate(
            p.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"A11 corpus line {lineno} is not JSON: {exc}") from exc
        if (not isinstance(row, dict)
                or not isinstance(row.get("command"), str)
                or not isinstance(row.get("skip"), bool)):
            raise ValueError(
                f"A11 corpus line {lineno} is not "
                '{"command": str, "skip": bool}')
        rows.append({"command": row["command"], "skip": row["skip"]})
    return rows


# ---------------------------------------------------------------------------
# Row classification (item 2)
# ---------------------------------------------------------------------------

# Spec §12 skip list: substrings that count a row as skipped even when the
# corpus forgets to flag it.
DANGEROUS_SUBSTRINGS = ("rm -rf", "mkfs", "shutdown", "reboot", "dd ",
                      "> /dev/")

# Stricter test-host policy applied on top of the spec skip list. The
# AGSSH_TEST_HOST machine is an integration host, not a scratch VM: replay
# tolerates read-only probes and writes under /tmp only. Anything that
# mutates system state, package state, docker state, or files outside /tmp
# classifies "policy" and is not executed.
POLICY_PATTERNS = [
    re.compile(r"\bsudo\b"),
    re.compile(r"\bdocker\b"),
    re.compile(r"\bsystemctl\b"),
    re.compile(r"\bsed -i\b"),
    re.compile(r"\btee\b"),
    re.compile(r"\bchown\b"),
    re.compile(r"\bchmod\b"),
    re.compile(r"\bgit (pull|checkout|fetch|push|clone|commit)\b"),
    re.compile(r"\b(apt|apt-get|pip|pip3|npm) install\b"),
    re.compile(r"\bmv\b"),
    re.compile(r"\bcp\b"),
    re.compile(r"\bmkfs\b"),
    re.compile(r"\bshutdown\b"),
    re.compile(r"\breboot\b"),
    re.compile(r"\bdd\b"),
]


def classify_row(row):
    """flagged | dangerous | policy | exec, in that precedence order.

    flagged    - corpus row has skip: true
    dangerous  - command contains a spec §12 skip substring
    policy     - command trips the stricter test-host policy
    exec       - safe to replay on the test host
    """
    if row.get("skip"):
        return "flagged"
    command = row.get("command") or ""
    if any(s in command for s in DANGEROUS_SUBSTRINGS):
        return "dangerous"
    if any(p.search(command) for p in POLICY_PATTERNS):
        return "policy"
    return "exec"


# ---------------------------------------------------------------------------
# Model-authored command (item 3, A11.3)
# ---------------------------------------------------------------------------

# A `| tail ...` pipeline segment at end-of-line or before `;`/newline. The
# pipe character is required, so docker's `--tail` flag never matches, and
# `| head -N` is not affected. Flag arguments must start with `-`, so
# `| tail -n 5`-style operands outside the corpus shape stop the match.
_TAIL_PIPE_RE = re.compile(r"\|\s*tail(?:\s+-[^\s|]+)*\s*(?=[;\n]|$)")


def model_command(command):
    """The command as the model authors it under agssh.

    Removes `| tail ...` / `| tail -N` pipeline segments. agssh captures full
    remote output, so model-authored commands carry no remote `tail`. `ssh `,
    `-i ` and `user@` transport tokens are already absent from corpus rows.
    Returns the transformed string.
    """
    return _TAIL_PIPE_RE.sub("", command)


# ---------------------------------------------------------------------------
# Output normalization (item 4)
# ---------------------------------------------------------------------------

# Non-deterministic output tokens masked so a remote-vs-local byte compare is
# meaningful. Applied in order; later patterns see earlier replacements.
VOLATILE_PATTERNS = (
    (r"elapsed \d+s", "elapsed <T>s"),          # elapsed timers
    (r"\b\d{10,13}\b", "<TS>"),                 # unix epochs (s or ms)
    (r"\d+ms", "<MS>"),                         # millisecond counters
    (r"http \d{3}", "http <HTTP>"),             # curl -w "%{http_code}"
    (r"bytes \d+", "bytes <N>"),                # curl -w "%{size_download}"
    (r"HEAD [0-9a-f]{7,}.*", "HEAD <GIT>"),     # git log -1 --format="HEAD %h %s"
    (r"[\d.]+%", "<STAT>"),                     # docker stats CPUPerc
    (r"[\d.]+[KMGT]?i?B / [\d.]+[KMGT]?i?B", "<STAT>"),  # docker stats MemUsage
    (r"0\.0\d+", "<D>"),                        # curl sub-second timings
    (r"\b\d+\.\d+ms\b", "<MS>"),                # fractional ms
    (r"\b\d+\.\d+s\b", "<D>"),                  # N.Ms second timings
    (r"\b\d+\.\d+\b", "<D>"),                   # other N.M decimal timings
    (r"^\S+: line \d+:", "<SH>: line <N>:"),    # $0 differs: `--` vs `bash`
)
_VOLATILE_RES = tuple((re.compile(p), r) for p, r in VOLATILE_PATTERNS)


def normalize(text):
    """Mask volatile output tokens so two runs byte-compare equal."""
    out = text if isinstance(text, str) else str(text)
    for rx, rep in _VOLATILE_RES:
        out = rx.sub(rep, out)
    return out


# ---------------------------------------------------------------------------
# Transport error detection (item 5, A11.1)
# ---------------------------------------------------------------------------

# Error-envelope substrings naming a transport class (persist_ssh_ext
# ConnectError public_error / _failure_error / _timeout_error / dead-mid
# rows), as opposed to a remote command that ran and failed.
TRANSPORT_MARKERS = (
    "connect failed",
    "control socket",
    "lost its control socket",
    "permission denied (publickey)",
    "maxstartups",
    "timed out after",
    "lock held",
)


def is_transport_error(error):
    """True when an execute() error string names a transport class.

    Case-insensitive: ssh stderr capitalizes "Permission denied" while the
    executor's own strings are lowercase.
    """
    if not error:
        return False
    low = str(error).lower()
    return any(m in low for m in TRANSPORT_MARKERS)


# ---------------------------------------------------------------------------
# Read/search lane (item 6, A11.4)
# ---------------------------------------------------------------------------

READSEARCH_VERBS = ("cd", "grep", "sed", "cat", "ls", "head", "tail", "find")

_HEREDOC_RE = re.compile(r"<<-?\s*[\"']?([A-Za-z_]\w*)")
_SET_RE = re.compile(r"^set\s+[+-][A-Za-z]+(?:\s+\S+)*$")
_SPLIT_RE = re.compile(r"[;\n]+")

# Context prefixes stripped for classification only: `sudo`, leading env
# assignments (`S=$(cat x)`, `A=b`), `command`/`builtin`/`env` wrappers, and
# `cd <path> &&` workdir prologues.
_CONTEXT_RES = (
    re.compile(r"^cd\s+\S+\s*&&\s*"),
    re.compile(r"^sudo\s+"),
    re.compile(r"^(?:command|builtin|env)\s+"),
    re.compile(r"^[A-Za-z_]\w*=\S+\s+"),
)

_QUOTED_RE = re.compile(r"'[^']*'|\"(?:\\.|[^\"\\])*\"")

# Redirections stripped before tokenizing (outside quotes only).
_REDIR_RE = re.compile(
    r"<<-?\s*[\"']?\w+[\"']?"   # heredoc opener
    r"|\d?>&\d"                  # 2>&1
    r"|\d?>>?\s*\S+"             # > f, >> f, 2> f, >/dev/null
    r"|<\s*\S+"                  # < f
)

_WORD_RE = re.compile(r"\S+")


def iter_pipelines(command):
    """Split a corpus command into candidate pipeline strings.

    Splits on newlines and `;` (corpus rows carry no materially quoted `;`).
    Each segment is stripped; empties, comments, `set -e`/`set -a`/`set +a`
    lines, and heredoc bodies (lines between `<<EOF`/`<<"PY"`/`<<JSON ...`
    and their matching terminator) are dropped entirely. The `<<...` opener
    line itself remains a segment - it is the command that reads the body.
    """
    segments = []
    end = None
    for line in str(command).split("\n"):
        if end is not None:
            if line.strip() == end:
                end = None
            continue                      # heredoc body + terminator lines
        m = _HEREDOC_RE.search(line)
        if m is not None:
            end = m.group(1)
        for seg in _SPLIT_RE.split(line):
            seg = seg.strip()
            if not seg or seg.startswith("#") or _SET_RE.match(seg):
                continue
            segments.append(seg)
    return segments


def _strip_context(seg):
    """Strip leading sudo / env-assignment / cd <path> && prefixes."""
    s = seg.strip()
    while True:
        prev = s
        for rx in _CONTEXT_RES:
            s = rx.sub("", s).lstrip()
        if s == prev:
            return s


def _first_verb(seg):
    """The segment's effective first word after context stripping."""
    m = _WORD_RE.match(_strip_context(seg))
    return m.group(0).strip("'\"") if m else ""


def is_readsearch(seg):
    """True when the segment's effective first word is a read/search verb."""
    return _first_verb(seg) in READSEARCH_VERBS


def _unrouteable(reason):
    return {"tool": None, "unrouteable": True, "reason": reason}


def _mask_quotes(s):
    """Replace quoted spans with same-length blanks so `|`/`;` inside
    quotes do not read as syntax. Positions are preserved."""
    return _QUOTED_RE.sub(lambda m: " " * len(m.group(0)), s)


def _strip_redirs(seg):
    """Blank out redirection operators outside quotes (`, `>`, `>>`, `2>`,
    `2>&1`, `<<EOF`) so they are not tokenized as operands."""
    out = []
    i, n, quote = 0, len(seg), None
    while i < n:
        c = seg[i]
        if quote is not None:
            out.append(c)
            if c == quote:
                quote = None
            i += 1
            continue
        if c in ("'", '"'):
            quote = c
            out.append(c)
            i += 1
            continue
        m = _REDIR_RE.match(seg, i)
        if m is not None:
            out.append(" ")
            i = m.end()
            continue
        out.append(c)
        i += 1
    return "".join(out)


def _tokens(seg):
    s = _strip_redirs(seg)
    try:
        return shlex.split(s)
    except ValueError:
        return s.split()


def _to_int(v, default):
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return default


def _arg(args, i):
    """The argument consumed by a long/short flag that takes a separate
    value token."""
    return args[i + 1] if i + 1 < len(args) else ""


_READ_LIMIT = 2000  # agssh-read DEFAULT_READ_LIMIT / maximum


def _route_grep(tokens):
    """grep [flags] <pattern> <path> -> agssh-find."""
    pattern = None
    paths = []
    context = 0
    file_glob = None
    fixed = False
    word = False
    whole_line = False
    args = tokens[1:]
    i = 0
    positional = False
    while i < len(args):
        a = args[i]
        if positional or a == "-" or not a.startswith("-"):
            if pattern is None:
                pattern = a
            else:
                paths.append(a)
            i += 1
            continue
        if a == "--":
            positional = True
            i += 1
            continue
        if a.startswith("--"):
            name, eq, val = a.partition("=")
            if name == "--include":
                v = val if eq else _arg(args, i)
                if file_glob is None:
                    file_glob = v
                i += 1 if eq else 2
                continue
            if name == "--exclude":
                return _unrouteable(
                    "grep --exclude has no find-call equivalent")
            if name in ("--context", "--after-context", "--before-context"):
                v = val if eq else _arg(args, i)
                context = max(context, _to_int(v, 0))
                i += 1 if eq else 2
                continue
            if name == "--regexp":
                v = val if eq else _arg(args, i)
                pattern = v if pattern is None else f"{pattern}|{v}"
                i += 1 if eq else 2
                continue
            if name in ("--count", "--files-with-matches",
                        "--files-without-match", "--only-matching",
                        "--quiet", "--silent", "--invert-match",
                        "--ignore-case", "--file"):
                return _unrouteable(
                    f"grep {name} has no find-call equivalent")
            if name == "--fixed-strings":
                fixed = True
            i += 1
            continue
        # short flag cluster: -n -iE -hE -ciE -A6 -e ...
        extra = 0
        j = 1
        while j < len(a):
            c = a[j]
            if c == "e":
                v = a[j + 1:] if j + 1 < len(a) else _arg(args, i)
                if j + 1 >= len(a):
                    extra = 1
                pattern = v if pattern is None else f"{pattern}|{v}"
                j = len(a)
            elif c == "f":
                return _unrouteable(
                    "grep -f pattern-file is not a find call")
            elif c == "m":
                if j + 1 >= len(a):
                    extra = 1
                j = len(a)
            elif c in "ABC":
                v = a[j + 1:] if j + 1 < len(a) else _arg(args, i)
                if j + 1 >= len(a):
                    extra = 1
                context = max(context, _to_int(v, 0))
                j = len(a)
            elif c in "icloqv":
                return _unrouteable(
                    f"grep -{c} has no find-call equivalent")
            elif c == "F":
                fixed = True
                j += 1
            elif c == "w":
                word = True
                j += 1
            elif c == "x":
                whole_line = True
                j += 1
            else:
                j += 1          # -n -E -h -H -r -R -s ...: find-compatible
        i += 1 + extra
    if pattern is None:
        return _unrouteable("grep with no pattern operand")
    if not paths:
        return _unrouteable("grep with no path operand (reads stdin)")
    if fixed:
        pattern = re.escape(pattern)
    if word:
        pattern = r"\b(?:" + pattern + r")\b"
    if whole_line:
        pattern = r"^(?:" + pattern + r")$"
    return {
        "tool": "agssh-find",
        "pattern": pattern,
        "path": paths[0],
        "context": context,
        "file_glob": file_glob,
    }


def _route_cat(tokens):
    paths = [t for t in tokens[1:] if not t.startswith("-")]
    if not paths:
        return _unrouteable("cat reads stdin (pipe/heredoc), not a path")
    return {"tool": "agssh-read", "path": paths[0], "offset": 1,
            "limit": _READ_LIMIT}


def _route_sed(tokens):
    """sed -n N[,M]p <path> -> agssh-read; sed -i is a write -> unrouteable."""
    script = None
    paths = []
    in_place = False
    args = tokens[1:]
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--":
            paths.extend(args[i + 1:])
            break
        if a == "-i" or a.startswith("--in-place") or (
                a.startswith("-i") and not a.startswith("--")):
            in_place = True
        elif a in ("-n", "--quiet", "--silent"):
            pass
        elif a in ("-e", "--expression"):
            if script is None:
                script = _arg(args, i)
            i += 2
            continue
        elif a.startswith("-e") and len(a) > 2:
            if script is None:
                script = a[2:]
        elif a.startswith("--expression="):
            if script is None:
                script = a.split("=", 1)[1]
        elif a == "-f" or a.startswith("--file"):
            return _unrouteable("sed -f script file is not a range print")
        elif a.startswith("-"):
            pass                # -r -E -u ...: no read-call impact
        else:
            if script is None:
                script = a
            else:
                paths.append(a)
        i += 1
    if in_place:
        return _unrouteable(
            "sed -i mutates the file; the read lane is read-only")
    if not paths:
        return _unrouteable("sed with no path operand")
    m = re.fullmatch(r"(\d+),(\d+)p", script or "")
    if m:
        offset, last = int(m.group(1)), int(m.group(2))
        return {"tool": "agssh-read", "path": paths[0], "offset": offset,
                "limit": max(1, last - offset + 1)}
    m = re.fullmatch(r"(\d+)p", script or "")
    if m:
        return {"tool": "agssh-read", "path": paths[0],
                "offset": int(m.group(1)), "limit": 1}
    if script == "p":
        return {"tool": "agssh-read", "path": paths[0], "offset": 1,
                "limit": _READ_LIMIT}
    return _unrouteable("sed program is not a range print")


def _route_headtail(verb, tokens):
    """head [-n] N <path> / tail [-n] N <path> -> agssh-read."""
    n = 10
    path = None
    args = tokens[1:]
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--":
            if i + 1 < len(args):
                path = args[i + 1]
            break
        if a.startswith("--bytes") or a == "-c" or a.startswith("-c") and len(a) > 2:
            return _unrouteable("byte-count read is not a line range")
        if a == "-n" or a == "--lines":
            n = _to_int(_arg(args, i), n)
            i += 2
            continue
        if a.startswith("--lines="):
            n = _to_int(a.split("=", 1)[1], n)
        elif a.startswith("-n") and len(a) > 2:
            n = _to_int(a[2:], n)
        elif re.fullmatch(r"-\d+", a):
            n = int(a[1:])
        elif a.startswith("-"):
            pass                # -q -v -z ...: no read-call impact
        elif path is None:
            path = a
        i += 1
    if path is None:
        return _unrouteable(f"{verb} reads stdin, not a path")
    return {"tool": "agssh-read", "path": path, "offset": 1,
            "limit": max(1, n)}


def _route_ls(tokens):
    paths = [t for t in tokens[1:] if not t.startswith("-")]
    return {"tool": "agssh-read",
            "path": paths[0] if paths else ".",
            "offset": 1, "limit": _READ_LIMIT}


def _route_find(tokens):
    args = [t for t in tokens[1:]]
    path = args[0] if args and not args[0].startswith("-") else "."
    return {"tool": "agssh-read", "path": path, "offset": 1,
            "limit": _READ_LIMIT}


def route_segment(seg):
    """Map one read/search segment to an agssh tool call.

    Returns a call dict, a `{"tool": None, ...}` dict for workdir context or
    unrouteable segments (with a reason), or None when the segment's first
    word is not a read/search verb at all.
    """
    verb = _first_verb(seg)
    if verb not in READSEARCH_VERBS:
        return None
    if verb == "cd":
        return {"tool": None, "note": "workdir context, not a call"}
    rest = _strip_context(seg)
    masked = _mask_quotes(rest)
    pipe = masked.find("|")
    if pipe >= 0:
        if verb == "grep":
            # grep <pat> <path> | head/tail: the grep still reads a path;
            # the pipe only shapes its output. Parse the grep stage.
            rest = rest[:pipe]
        else:
            stages = rest[pipe + 1:].split("|")
            if any(_first_verb(st) == "grep" for st in stages):
                return _unrouteable("grep reads piped input, not a path")
            return _unrouteable(
                "pipeline stage is not a single-file read")
    tokens = _tokens(rest)
    if verb in tokens:
        tokens = tokens[tokens.index(verb):]
    if not tokens or tokens[0] != verb:
        return _unrouteable(f"could not tokenize {verb!r} segment")
    if verb == "grep":
        return _route_grep(tokens)
    if verb == "cat":
        return _route_cat(tokens)
    if verb == "sed":
        return _route_sed(tokens)
    if verb in ("head", "tail"):
        return _route_headtail(verb, tokens)
    if verb == "ls":
        return _route_ls(tokens)
    if verb == "find":
        return _route_find(tokens)
    return _unrouteable(f"no route for verb {verb!r}")


def route_row(command):
    """Map every read/search segment of a corpus row to a call dict."""
    return [route_segment(s) for s in iter_pipelines(command)
            if is_readsearch(s)]


# ---------------------------------------------------------------------------
# Fixture tree on the integration host (item 7)
# ---------------------------------------------------------------------------

TREE_DIR = "/tmp/agssh-a11"

# Small files (<2KB each) letting routed read/find calls succeed on the
# integration host. Everything lives under /tmp/agssh-a11/ per the test-host
# policy (read-only probes + /tmp writes only). Contents are synthetic,
# matching the corpus vocabulary.
FIXTURE_TREE = {
    TREE_DIR + "/docker-compose.yml":
        "services:\n"
        "  web:\n"
        "    image: myapp:staging-partlevel3\n"
        "    restart: unless-stopped\n"
        "    ports:\n"
        "      - \"3001:3000\"\n"
        "    env_file:\n"
        "      - override.env\n"
        "  worker:\n"
        "    image: myapp:staging-partlevel3\n"
        "    env_file:\n"
        "      - override.env\n",
    TREE_DIR + "/override.env":
        "AI_MODEL_CHEAP=vendor/model-k-free\n"
        "AI_MODEL_SECOND=vendor/model-c-free\n"
        "AI_MAX_PARALLEL=60\n"
        "AI_MAX_PARALLEL_PER_PROVIDER=30\n"
        "GEN_CONCURRENCY=60\n"
        "MAX_RUN_QUESTIONS=300\n",
    TREE_DIR + "/app.log":
        "2030-01-01T10:02:11Z INFO  task run started"
        " runId=0f6b4d7a-2c8e\n"
        "2030-01-01T10:02:19Z WARN  provider latency high"
        " model=model-i-free\n"
        "2030-01-01T10:02:41Z ERROR Upstream error from provider: 429"
        " rate_limit exceeded maxRetries=3\n"
        "2030-01-01T10:02:44Z WARN  retrying request attempt=2 backoff=4s\n"
        "2030-01-01T10:03:02Z ERROR task failed type=long_answer"
        " reason=timeout\n"
        "2030-01-01T10:03:15Z INFO  task run complete kept=241"
        " rejected=59\n",
    TREE_DIR + "/burst.json":
        '{"slug":"bench-synthetic","nodeIds":["n_alpha",'
        '"n_beta","n_gamma","n_delta","n_epsilon","n_zeta"],'
        '"countPerTopic":50,"marksMin":3,"marksMax":9,"count":300}\n',
    TREE_DIR + "/q2.json":
        '{"items":[{"type":"long_answer","marks":6,'
        '"createdAt":"2030-01-01T09:00:00Z",'
        '"modelAnswer":"Applies the bench scoring rule to the sample.",'
        '"stem":"Explain the synthetic scoring step for the sample.",'
        '"markScheme":{"points":[{"marks":2,"text":"states the rule"},'
        '{"marks":2,"text":"applies the rule to the sample"},'
        '{"marks":2,"text":"links the rule to the outcome"}]},'
        '"parts":[{"label":"a","marks":3,"commandWord":"Explain",'
        '"format":"structured","solution":"...","specNodeId":"n_alpha",'
        '"source":"synthetic-set","isAiAssisted":true}]}],"questions":[]}\n',
    TREE_DIR + "/models.json":
        '{"data":[{"id":"vendor/model-c-free",'
        '"pricing":{"prompt":"0","completion":"0"}},'
        '{"id":"model-i-free",'
        '"pricing":{"prompt":"0.0001","completion":"0.0002"}},'
        '{"id":"model-h-free",'
        '"pricing":{"prompt":"0","completion":"0"}}]}\n',
}


def tree_write_argv():
    """Shell commands that materialize FIXTURE_TREE via execute().

    Each command is <4KB, printf-based, and writes only under
    /tmp/agssh-a11/ - safe under the test-host policy.
    """
    argv = ["mkdir -p " + TREE_DIR]
    for path, content in FIXTURE_TREE.items():
        lines = content.split("\n")
        if lines and lines[-1] == "":
            lines = lines[:-1]      # printf adds the trailing newline
        args = " ".join(shlex.quote(ln) for ln in lines) or "''"
        argv.append(f"printf '%s\\n' {args} > {shlex.quote(path)}")
    return argv


def remap_path(path):
    """Map a corpus path onto the fixture tree by basename.

    docker-compose.yml -> the tree's docker-compose.yml, override.env ->
    override.env, *.json -> the matching fixture by basename, anything
    else -> the tree directory itself.
    """
    base = str(path).rstrip("/").rsplit("/", 1)[-1]
    target = f"{TREE_DIR}/{base}" if base else ""
    return target if target in FIXTURE_TREE else TREE_DIR


def route_to_call(seg):
    """route_segment() with the path remapped onto the fixture tree."""
    call = route_segment(seg)
    if isinstance(call, dict) and isinstance(call.get("path"), str):
        call = dict(call)
        call["path"] = remap_path(call["path"])
    return call


def route_calls(command):
    """route_row() variant whose call paths are already remapped."""
    return [route_to_call(s) for s in iter_pipelines(command)
            if is_readsearch(s)]
