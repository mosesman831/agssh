"""Shared fixtures for the agssh pytest suite.

Import discipline (per agssh-SPEC-EXTREME section 11):
  * the repo ``plugin/`` dir is put on ``sys.path`` so ``import agssh``,
    ``import agssh.guard`` and ``import agssh.handlers`` resolve once the
    plugin lands (``plugin/agssh/__init__.py`` etc.).
  * ``~/.hermes/hermes-agent`` is put on ``sys.path`` so the plugin's real
    imports (``tools.approval_detection``, ``tools.approval``,
    ``agent.redact``) resolve exactly as they do for the plugin host.
  * the executor is a plain script, not a package; ``load_executor`` loads it
    with ``importlib.util.spec_from_file_location`` — the same mechanism the
    plugin and the CLI use.
"""

import copy
import importlib.util
import json
import os
import sys
import types

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PLUGIN_DIR = os.path.join(REPO_ROOT, "plugin")
HERMES_AGENT_DIR = os.path.expanduser("~/.hermes/hermes-agent")
LIVE_REGISTRY_PATHS = (
    os.path.expanduser("~/.config/agssh/hosts.json"),
    os.path.expanduser("~/.config/persist-ssh.json"),
)
# The vendored in-plugin executor is canonical for tests: it is what a
# fresh install resolves, with no operator skill path required.
DEFAULT_EXECUTOR_PATH = os.path.join(REPO_ROOT, "plugin", "agssh", "executor.py")

# Integration host parameterisation: tests that need a real SSH host are
# skipped unless AGSSH_TEST_HOST names an alias in a live registry.
TEST_ALIAS = os.environ.get("AGSSH_TEST_HOST") or None
requires_host = pytest.mark.skipif(
    not TEST_ALIAS,
    reason="AGSSH_TEST_HOST unset — no integration host configured")


def _live_hosts():
    merged = {}
    for path in LIVE_REGISTRY_PATHS:
        try:
            with open(path) as f:
                merged.update(json.load(f).get("hosts") or {})
        except (OSError, ValueError):
            continue
    return merged

for _path in (PLUGIN_DIR, HERMES_AGENT_DIR):
    if _path not in sys.path:
        sys.path.insert(0, _path)


# --------------------------------------------------------------------------
# hermes-agent import fallback
#
# Under a fully provisioned interpreter the three imports below just work. The
# bare system interpreter used for pytest here lacks ``ruamel`` (a transitive
# dependency of ``tools.approval`` via ``utils`` -> ``hermes_yaml``), so
# ``tools.approval`` cannot be imported at all. A plugin that does
# ``from tools.approval import request_tool_approval`` at module top would then
# be untestable for reasons unrelated to its correctness.
#
# The fallback installs a *minimal* stand-in into ``sys.modules`` and ONLY when
# the real import already failed. ``request_tool_approval`` returns the same
# {"action": "approve"} shape ``_run_approval_gate`` yields on the approve path
# (spec section 3, Q6). ``tools.approval_detection`` gets the same treatment for
# symmetry (it currently imports fine, but costs nothing to guard).
# ``agent.redact`` is deliberately NOT stubbed: spec section 5.2 defines its own
# failure path, which tests may need to observe.
# --------------------------------------------------------------------------

def _install_stub(module_name, attrs):
    """Register a stub module only if the real one cannot be imported."""
    try:
        __import__(module_name)
        return False
    except ImportError:
        pass
    stub = types.ModuleType(module_name)
    for key, value in attrs.items():
        setattr(stub, key, value)
    sys.modules[module_name] = stub
    parent_name, _, child_name = module_name.rpartition(".")
    if parent_name in sys.modules:
        setattr(sys.modules[parent_name], child_name, stub)
    return True


def _stub_request_tool_approval(tool_name, description, rule_key=None, **kwargs):
    # Real _run_approval_gate shape: {"approved": bool, "message": ...}
    return {"approved": True, "message": "approved (tools.approval stub)"}


def _stub_detect_hardline_command(command):
    return False, ""


def _stub_detect_dangerous_command(command):
    return False, "", ""


_install_stub("tools.approval", {"request_tool_approval": _stub_request_tool_approval})
_install_stub("tools.approval_detection", {
    "detect_hardline_command": _stub_detect_hardline_command,
    "detect_dangerous_command": _stub_detect_dangerous_command,
})


# --------------------------------------------------------------------------
# Executor loading
# --------------------------------------------------------------------------

def load_executor(path=None):
    """Load the executor script as a fresh module object.

    Resolution order: explicit ``path`` -> ``AGSSH_EXECUTOR`` env ->
    the vendored ``plugin/agssh/executor.py``.
    """
    path = path or os.environ.get("AGSSH_EXECUTOR") or DEFAULT_EXECUTOR_PATH
    path = os.path.abspath(path)
    spec = importlib.util.spec_from_file_location("persist_ssh", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def ex(tmp_path, monkeypatch):
    """A freshly loaded executor module, pinned to an isolated HERMES_HOME.

    ``HERMES_HOME`` is repointed so audit lines and spill files from any
    ``execute`` call land under ``tmp_path``, never in the real ``~/.hermes``.
    ``AGSSH_EXECUTOR`` is exported so a plugin/CLI that honours the same
    override resolves this exact file.
    """
    mod = load_executor()
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "hermes_home"))
    monkeypatch.setenv("AGSSH_EXECUTOR", os.path.abspath(mod.__file__))
    return mod


# --------------------------------------------------------------------------
# Registry fixtures
#
# The executor reads the registry path from the module-level ``CONFIG_PATH``
# (bound from ``PERSIST_SSH_CONFIG`` at import time). To re-point an already
# loaded module, ``tmp_registry.write`` patches ``ex.CONFIG_PATH`` directly AND
# exports ``PERSIST_SSH_CONFIG`` so any module loaded afterwards (e.g. the
# plugin's own executor instance) picks the temp registry too.
# --------------------------------------------------------------------------

def test_host_entry():
    """The AGSSH_TEST_HOST registry entry, read from a live registry.

    Infrastructure details (IPs, key paths) never live in tracked files —
    they come from the operator's local registry at run time."""
    if not TEST_ALIAS:
        return None
    info = _live_hosts().get(TEST_ALIAS)
    return copy.deepcopy(info) if isinstance(info, dict) else None


class TmpRegistry:
    """A writable ``persist-ssh.json``-style registry under ``tmp_path``."""

    def __init__(self, path, monkeypatch, executor):
        self.path = str(path)
        self._monkeypatch = monkeypatch
        self._ex = executor

    def write(self, hosts):
        """Write ``{"hosts": hosts}``, re-point env + executor, return the path."""
        with open(self.path, "w") as f:
            json.dump({"hosts": hosts}, f, indent=2)
        self._monkeypatch.setenv("PERSIST_SSH_CONFIG", self.path)
        self._monkeypatch.setattr(self._ex, "CONFIG_PATH", self.path)
        return self.path

    # Alias matching the ``set_hosts(hosts_dict) -> path`` factory form.
    set_hosts = write


@pytest.fixture
def tmp_registry(tmp_path, monkeypatch, ex):
    return TmpRegistry(tmp_path / "persist-ssh.json", monkeypatch, ex)


@pytest.fixture
def test_host():
    """The AGSSH_TEST_HOST registry entry (a fresh copy per test)."""
    info = test_host_entry()
    if info is None:
        pytest.skip("AGSSH_TEST_HOST unset or unknown alias")
    return info


# --------------------------------------------------------------------------
# Prod-host guard: integration targets are dev boxes only. The production
# alias, a notes field containing "prod", or an operator-supplied
# AGSSH_PROD_IP refuses the whole run. (The literal production IP must not
# live in a tracked file - set it via the env var on the operator's box.)
# --------------------------------------------------------------------------

PROD_ALIAS = "fat1"
PROD_IP = os.environ.get("AGSSH_PROD_IP", "")


@pytest.fixture(autouse=True)
def prod_guard():
    hosts = _live_hosts()
    for alias, info in hosts.items():
        info = info or {}
        notes = str(info.get("notes") or "")
        if (alias == PROD_ALIAS
                or (PROD_IP and info.get("host") == PROD_IP)
                or "prod" in notes.lower()):
            pytest.exit("refusing: prod host in registry")


# --------------------------------------------------------------------------
# Fake plugin context + helpers
# --------------------------------------------------------------------------

class FakeCtx:
    """Minimal stand-in for hermes_cli PluginContext.

    ``register_tool`` captures ``{"name", "schema", "handler", "kw"}`` per call;
    ``register_hook`` captures ``{"name", "callback"}``; ``get_config`` reads
    ``self.settings`` with a default.
    """

    def __init__(self):
        self.tools = []
        self.hooks = []
        self.settings = {}

    def register_tool(self, name, toolset, schema, handler, **kw):
        entry = {"name": name, "schema": schema, "handler": handler, "kw": kw}
        self.tools.append(entry)
        return entry

    def register_hook(self, name, cb):
        entry = {"name": name, "callback": cb}
        self.hooks.append(entry)
        return entry

    def get_config(self, key, default=None):
        return self.settings.get(key, default)


@pytest.fixture
def fake_ctx():
    return FakeCtx()


@pytest.fixture
def make_key(tmp_path):
    """Factory: create a fake private-key file, mode 0600, return its path."""

    def _make(name="id_test_key"):
        path = tmp_path / name
        path.write_text("fake-private-key-material\n")
        os.chmod(path, 0o600)
        return str(path)

    return _make
