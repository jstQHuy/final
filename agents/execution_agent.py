import sys
import os
import json
import re
import logging
import subprocess
import time
import shlex
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple, Optional
from dotenv import load_dotenv
from pathlib import Path

# Load .env from repo root regardless of current working directory
load_dotenv(dotenv_path=Path(__file__).resolve().parents[1] / ".env")

# Ensure project root is in sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from utils.config_loader import load_config, get_runtime_section
from utils.model_manager import get_model

try:
    from langchain_core.messages import HumanMessage, AIMessage
    from langchain_core.chat_history import InMemoryChatMessageHistory
except Exception as e:
    raise RuntimeError(
        "Thiếu langchain_core. Hãy cài trong .venv:\n"
        "  source .venv/bin/activate\n"
        "  python -m pip install langchain-core langchain-community langchain\n"
        f"\nChi tiết lỗi: {e}"
    )

logger = logging.getLogger(__name__)
logging.basicConfig(
    format="%(asctime)s %(levelname)-8s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    filename="execution_agent.log",
    level=logging.INFO,
)

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CONFIG_PATH = os.path.join(PROJECT_ROOT, "configs", "config.yaml")


# -----------------------------
# Guard / Policy (no CommandPolicy)
# -----------------------------
@dataclass
class ExecGuard:
    enable_autorun: bool
    allowed_cmd_regex: List[str]
    denied_cmd_regex: List[str]
    timeout_sec: int
    max_output_chars: int

    # Safety toggles
    block_chaining: bool = True  # blocks && ; |
    allow_pipes: bool = False    # if True, '|' won't be blocked when block_chaining=True


def _compile_patterns(patterns: List[str]) -> List[re.Pattern]:
    out: List[re.Pattern] = []
    for p in patterns or []:
        try:
            out.append(re.compile(p))
        except re.error:
            logger.warning("Invalid regex pattern ignored: %s", p)
    return out


def _check_command(cmd: str, guard: ExecGuard, allowlist: List[re.Pattern], denylist: List[re.Pattern]) -> Tuple[bool, str]:
    if not guard.enable_autorun:
        return False, "Autorun is disabled (runtime.execution.enable_autorun=false)"

    c = (cmd or "").strip()
    if not c:
        return False, "Empty command"

    # Block chaining / piping unless you explicitly allow it
    if guard.block_chaining:
        if "&&" in c or ";" in c:
            return False, "Command chaining is not allowed (contains && or ;)"
        if ("|" in c) and (not guard.allow_pipes):
            return False, "Piping is not allowed (contains |)"

    for pat in denylist:
        if pat.search(c):
            return False, f"Matched denied_cmd_regex: {pat.pattern}"

    # If allowlist is configured, command must match at least one pattern
    if allowlist:
        for pat in allowlist:
            if pat.search(c):
                return True, "OK"
        return False, "Did not match any allowed_cmd_regex"

    return True, "OK"


def _safe_topic(topic: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_.-]+", "-", topic) if topic else "default_topic"


def _load_plan_for_topic(topic: str) -> Tuple[str, List[Dict[str, Any]]]:
    safe = _safe_topic(topic)
    base = os.path.join(PROJECT_ROOT, "data", "threads", safe)

    for name in ("plan_ec.json", "plan.json"):
        p = os.path.join(base, name)
        if os.path.exists(p):
            try:
                with open(p, "r", encoding="utf-8") as f:
                    obj = json.load(f)
                if isinstance(obj, list):
                    return p, obj
            except Exception:
                continue

    return "", []


def _pick_best_entry(plan: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not plan:
        return None

    def score_of(x: Dict[str, Any]) -> float:
        s = x.get("score")
        if isinstance(s, (int, float)):
            return float(s)
        return 0.0

    return sorted(plan, key=score_of, reverse=True)[0]


def _extract_json(text: str) -> Optional[Dict[str, Any]]:
    if not text:
        return None
    # Allow fenced ```json
    m = re.search(r"```json\s*(\{.*?\})\s*```", text, re.DOTALL)
    if m:
        text = m.group(1)
    # Or any {...}
    m2 = re.search(r"(\{.*\})", text, re.DOTALL)
    if m2:
        text = m2.group(1)
    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            return obj
    except Exception:
        return None
    return None


def _normalize_executable(executable: Any) -> List[str]:
    """
    Accept:
      - "None" / None -> []
      - string -> [string]
      - list[str] -> list[str]
    Anything else -> []
    """
    if executable is None:
        return []
    if isinstance(executable, str):
        exe = executable.strip()
        if not exe or exe.lower() == "none":
            return []
        return [exe]
    if isinstance(executable, list):
        cmds: List[str] = []
        for x in executable:
            if isinstance(x, str) and x.strip():
                if x.strip().lower() != "none":
                    cmds.append(x.strip())
        return cmds
    return []


def _slug(s: str) -> str:
    s = (s or "").strip().lower()
    s = re.sub(r"[^a-z0-9]+", "-", s).strip("-")
    return s or "poc"


def _tokenize(cmd: str) -> List[str]:
    # Best-effort tokenize for analysis (not for execution)
    try:
        return shlex.split(cmd)
    except Exception:
        return (cmd or "").split()


def _find_go_file_dir(cmd: str, cwd: Optional[str]) -> Optional[str]:
    """
    If cmd references a .go file (absolute or resolvable relative), return its directory.
    """
    tokens = _tokenize(cmd)
    base = cwd or os.getcwd()
    for t in tokens:
        if not isinstance(t, str):
            continue
        if t.endswith(".go"):
            if os.path.isabs(t) and os.path.isfile(t):
                return os.path.dirname(t)
            candidate = os.path.abspath(os.path.join(base, t))
            if os.path.isfile(candidate):
                return os.path.dirname(candidate)
    return None


def _is_go_cmd(cmd: str) -> bool:
    c = (cmd or "").strip()
    return c.startswith("go " ) or c == "go"


def _module_path_for_dir(dirpath: str) -> str:
    # You can customize this prefix if you want
    name = _slug(os.path.basename(dirpath))
    return f"example.com/{name}"


def _ensure_go_module(
    guard: ExecGuard,
    allowlist: List[re.Pattern],
    denylist: List[re.Pattern],
    cwd: str,
    history: InMemoryChatMessageHistory,
) -> List[Tuple[str, str]]:
    """
    Ensure go.mod exists in cwd.
    Returns list of (cmd, output) executed.
    """
    executed: List[Tuple[str, str]] = []
    gomod = os.path.join(cwd, "go.mod")
    if os.path.isfile(gomod):
        return executed

    module_path = _module_path_for_dir(cwd)
    cmds = [f"go mod init {module_path}", "go mod tidy"]

    for cmd in cmds:
        out, _ = _run_shell(
            guard=guard,
            allowlist=allowlist,
            denylist=denylist,
            cmd=cmd,
            cwd=cwd,
        )
        executed.append((cmd, out))
        # Save to history for LLM awareness
        history.add_message(HumanMessage(content=f"[AUTO] Command: {cmd}\nOutput:\n{out}"))

        # If blocked, stop early; user needs to adjust allowlist
        if out.startswith("[BLOCKED]"):
            break

    return executed


def _rewrite_go_mod_init_if_missing_path(cmd: str, cwd: Optional[str]) -> str:
    """
    If cmd is exactly `go mod init` (no args), rewrite with module path based on cwd.
    """
    if re.match(r"^\s*go\s+mod\s+init\s*$", cmd or ""):
        base = cwd or os.getcwd()
        return f"go mod init {_module_path_for_dir(base)}"
    return cmd


def _run_shell(
    guard: ExecGuard,
    allowlist: List[re.Pattern],
    denylist: List[re.Pattern],
    cmd: str,
    cwd: Optional[str] = None,
) -> Tuple[str, Optional[str]]:
    """
    Run a shell command with guardrails.
    Returns (output, new_cwd_if_cd_else_None).

    NOTE:
    - 'cd <dir>' is handled internally by updating cwd, because 'cd' won't persist across subprocess calls.
    """
    cmd = (cmd or "").strip()
    if not cmd:
        return "[SKIP] Empty command", None

    # Handle 'cd' explicitly (do not send to subprocess)
    m = re.match(r"^\s*cd\s+(.+?)\s*$", cmd)
    if m:
        target = m.group(1).strip().strip('"').strip("'")
        base = cwd or os.getcwd()
        new_dir = target if os.path.isabs(target) else os.path.abspath(os.path.join(base, target))
        if os.path.isdir(new_dir):
            return f"[OK] Changed directory to: {new_dir}", new_dir
        return f"[ERROR] cd failed: directory not found: {new_dir}", None

    # Make python/pip executions deterministic: always use the interpreter that is
    # currently running ExecutionAgent (typically the active virtualenv).
    cmd = _rewrite_python_and_pip(cmd)

    ok, reason = _check_command(cmd, guard, allowlist, denylist)
    if not ok:
        return f"[BLOCKED] {reason}. Command: {cmd}", None

    try:
        r = subprocess.run(
            cmd,
            shell=True,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=guard.timeout_sec,
            cwd=cwd,
        )
        out = (r.stdout or "") + (("\n" + r.stderr) if r.stderr else "")
        out = out[: guard.max_output_chars]
        return out, None
    except subprocess.CalledProcessError as e:
        out = (e.stdout or "") + (("\n" + e.stderr) if e.stderr else "")
        out = out[: guard.max_output_chars]
        return out or f"Command failed with returncode={getattr(e, 'returncode', '?')}", None
    except subprocess.TimeoutExpired:
        return f"Command timed out after {guard.timeout_sec} seconds", None


def _rewrite_python_and_pip(cmd: str) -> str:
    """Ensure pip installs and python runs happen in the same environment.

    Why this exists:
    - LLMs often emit '/usr/bin/python3 ...' even when the agent is executed inside a venv.
    - That leads to: pip installs into venv, but script runs with system python (ImportError).

    Strategy:
    - Rewrite leading 'python3' or '/usr/bin/python3' (and common variants) to sys.executable.
    - Rewrite leading 'pip' / 'pip3' to: '<sys.executable> -m pip'.
    """

    c = (cmd or "").strip()
    if not c:
        return cmd

    py = shlex.quote(sys.executable)

    # If the user/LLM already uses `python -m pip`, do not rewrite.
    if re.match(r"^\s*python(\d+(\.\d+)*)?\s+-m\s+pip(\s+|$)", c):
        return cmd

    # Rewrite pip invocations.
    m = re.match(r"^\s*(?P<pip>(?:/usr/bin/)?pip3?|(?:\./)?pip3?)(?P<rest>\s+.*|$)", c)
    if m:
        rest = (m.group("rest") or "").lstrip()
        return f"{py} -m pip {rest}".rstrip()

    # Rewrite python invocations.
    m = re.match(r"^\s*(?P<py>(?:/usr/bin/)?python3|python3|python)(?P<rest>\s+.*|$)", c)
    if m:
        rest = (m.group("rest") or "").lstrip()
        return f"{py} {rest}".rstrip()

    return cmd


def main():
    config = load_config(CONFIG_PATH, expand_env=False)

    recon_cfg = get_runtime_section(config, "recon") or {}
    exec_cfg = get_runtime_section(config, "execution") or {}

    topic = (recon_cfg.get("current_topic") or exec_cfg.get("current_topic") or "default_topic").strip()

    plan_path, plan = _load_plan_for_topic(topic)
    if not plan:
        print(f"[Execution] No plan found for topic={topic}. Looked under data/threads/<topic>/plan*.json")
        return

    best = _pick_best_entry(plan)
    if not best:
        print(f"[Execution] Plan is empty or malformed: {plan_path}")
        return

    model_name = exec_cfg.get("model", "openai")
    llm = get_model(model_name)
    if llm is None:
        raise RuntimeError(
            f"Model init failed (got None). Check runtime.execution.model='{model_name}' "
            f"and your .env (OPENAI_API_KEY or other provider credentials)."
        )

    guard = ExecGuard(
        enable_autorun=bool(exec_cfg.get("enable_autorun", False)),
        allowed_cmd_regex=list(exec_cfg.get("allowed_cmd_regex", []) or []),
        denied_cmd_regex=list(exec_cfg.get("denied_cmd_regex", []) or []),
        timeout_sec=int(exec_cfg.get("command_timeout_sec", 60)),
        max_output_chars=int(exec_cfg.get("max_output_chars", 20000)),
        block_chaining=True,
        allow_pipes=bool(exec_cfg.get("allow_pipes", False)),
    )

    allowlist = _compile_patterns(guard.allowed_cmd_regex)
    denylist = _compile_patterns(guard.denied_cmd_regex)

    history = InMemoryChatMessageHistory()

    # Strengthen guidance so LLM produces better multi-step lists
    guidance = {
        "rules": [
            "Return ONLY valid JSON (no markdown).",
            "Field 'executable' MUST be either a string command or a list of string commands.",
            "Do NOT use '&&' or ';' to chain commands. If you need multiple steps, use a list.",
            "Prefer using local paths already present in the plan entry, if any.",
            "If you need to clone, use a repo URL that appears in the plan entry. If none exists, set executable to 'None' and explain.",
            "When running python or installing Python deps, prefer: python ... and python -m pip ... (do NOT hardcode /usr/bin/python3).",
            "If executing Go commands, cd into the directory containing the .go file first, and ensure a go.mod exists (go mod init <module> + go mod tidy).",
        ]
    }

    history.add_message(
        HumanMessage(
            content=(
                "You are an execution agent.\n"
                "Here is the selected exploit plan entry (JSON):\n"
                f"{json.dumps(best, indent=2, ensure_ascii=False)}\n\n"
                "Guidance:\n"
                f"{json.dumps(guidance, indent=2)}\n\n"
                "Now generate the next action.\n"
                "Return JSON with fields: analysis (string), next_step (string), executable (string or list of strings or 'None')."
            )
        )
    )

    max_steps = int(exec_cfg.get("max_steps", 8) or 8)
    cwd: Optional[str] = None

    for _ in range(max_steps):
        resp = llm.invoke(history.messages, timeout=30)
        text = getattr(resp, "content", str(resp))

        obj = _extract_json(text)
        if not obj:
            history.add_message(AIMessage(content=text))
            history.add_message(HumanMessage(content="Your previous response is not valid JSON. Return ONLY valid JSON now."))
            print("[WARN] LLM returned non-JSON. Retrying.")
            continue

        print(json.dumps(obj, indent=2, ensure_ascii=False))
        history.add_message(AIMessage(content=json.dumps(obj, ensure_ascii=False)))

        cmds = _normalize_executable(obj.get("executable"))
        if not cmds:
            break

        for raw_cmd in cmds:
            cmd = raw_cmd

            # (B1) If command is Go-related and references a .go file, auto-adjust cwd to that file's directory
            if _is_go_cmd(cmd):
                go_dir = _find_go_file_dir(cmd, cwd)
                if go_dir and os.path.isdir(go_dir):
                    cwd = go_dir

            # (B2) If LLM outputs "go mod init" without module path, rewrite it
            if _is_go_cmd(cmd):
                cmd = _rewrite_go_mod_init_if_missing_path(cmd, cwd)

            # (B3) Proactive: if Go command and cwd has no go.mod, auto create it before running
            if _is_go_cmd(cmd) and cwd and os.path.isdir(cwd):
                _ensure_go_module(guard, allowlist, denylist, cwd, history)

            out, new_cwd = _run_shell(
                guard=guard,
                allowlist=allowlist,
                denylist=denylist,
                cmd=cmd,
                cwd=cwd,
            )

            print("[Command]\n", cmd)
            print("[Command Output]\n", out)

            if new_cwd:
                cwd = new_cwd

            history.add_message(HumanMessage(content=f"Command: {cmd}\nOutput:\n{out}"))

            # (B4) Reactive recovery: if Go build fails due to module issue, auto-init module + retry once
            if _is_go_cmd(cmd) and ("cannot find main module" in out or "go: cannot find main module" in out):
                if cwd and os.path.isdir(cwd):
                    _ensure_go_module(guard, allowlist, denylist, cwd, history)
                    retry_out, _ = _run_shell(
                        guard=guard,
                        allowlist=allowlist,
                        denylist=denylist,
                        cmd=cmd,
                        cwd=cwd,
                    )
                    print("[AUTO-RETRY]\n", cmd)
                    print("[AUTO-RETRY OUTPUT]\n", retry_out)
                    history.add_message(HumanMessage(content=f"[AUTO-RETRY] Command: {cmd}\nOutput:\n{retry_out}"))

        time.sleep(0.5)


if __name__ == "__main__":
    main()


