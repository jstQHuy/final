#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Recon Agent (patched for: stable forced-recon, resume, dedupe, clean stop)
- Fixes: NameError _choose, UnboundLocalError last_analysis, broken try/except blocks
- Adds: command dedupe, resume re-anchor with RECON_INIT, sane stop condition to produce summary
- Keeps: your ExecGuard, JSON-only protocol, read-only recon posture
"""

import sys
import os
import json
import subprocess
import re
import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple

import dotenv

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.append(PROJECT_ROOT)

from utils.prompt import PentestAgentPrompt
from utils.model_manager import get_model
from utils.config_loader import load_config, get_runtime_section

from pydantic import BaseModel, Field

# Optional: LangChain imports (required by your current model_manager/get_model)
try:
    from langchain_core.messages import HumanMessage, AIMessage, BaseMessage
    from langchain_core.chat_history import InMemoryChatMessageHistory
except Exception as e:
    raise RuntimeError(
        "Thiếu langchain_core trong môi trường hiện tại.\n"
        "Hãy chạy đúng trong virtualenv (.venv) rồi cài:\n"
        "  . .venv/bin/activate\n"
        "  python -m pip install -U pip\n"
        "  python -m pip install langchain-core langchain-community langchain\n"
        f"\nChi tiết lỗi: {e}"
    )

# ----------------------------
# Logging
# ----------------------------
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")

if not logger.handlers:
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    file_handler = logging.FileHandler("recon_agent.log")
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

CONFIG_PATH = os.path.join(PROJECT_ROOT, "configs", "config.yaml")

# ----------------------------
# Lightweight Command Guard
# ----------------------------
@dataclass
class ExecGuard:
    enable: bool
    allowed_cmd_regex: List[str]
    denied_cmd_regex: List[str]
    timeout_sec: int
    max_output_chars: int
    block_chaining: bool = False
    allow_pipes: bool = True


def _compile_patterns(patterns: List[str]) -> List[re.Pattern]:
    out: List[re.Pattern] = []
    for p in patterns or []:
        try:
            out.append(re.compile(p))
        except re.error:
            logger.warning("Invalid regex pattern ignored: %s", p)
    return out

def deep_merge_dict(dst: dict, src: dict) -> dict:
    """Recursively merge src into dst (in-place) and return dst."""
    for k, v in (src or {}).items():
        if isinstance(v, dict) and isinstance(dst.get(k), dict):
            deep_merge_dict(dst[k], v)
        else:
            dst[k] = v
    return dst

def is_blank_recon_analysis(a: dict) -> bool:
    """Heuristic: treat an 'analysis' payload as blank if it carries no evidence/signals."""
    if not isinstance(a, dict) or not a:
        return True
    # common schema fields
    ports = a.get("ports") or {}
    web = a.get("web") or {}
    planning = a.get("planning") or {}
    # any non-empty evidence?
    if web.get("evidence") or web.get("fingerprints") or web.get("interesting_paths") or web.get("virtual_hosts"):
        return False
    # any port fingerprint (product/version/banner/cves)
    for _, p in (ports.items() if isinstance(ports, dict) else []):
        if not isinstance(p, dict):
            continue
        if (p.get("product") or p.get("version") or p.get("banner_evidence") or p.get("notes")):
            return False
        if p.get("cves") or p.get("cve_candidates"):
            return False
    # planning filled?
    if any(planning.get(x) for x in ["keyword","app","version","vuln_type","rationale"]) or (planning.get("planning_keywords") or planning.get("cve_ids")):
        return False
    # target notes/hostnames/os_guess
    tgt=a.get("target") or {}
    if tgt.get("os_guess") not in (None,"","N/A") or tgt.get("hostnames") or tgt.get("notes"):
        return False
    return True




def _check_cmd(cmd: str, guard: ExecGuard, allowlist: List[re.Pattern], denylist: List[re.Pattern]) -> Tuple[bool, str]:
    if not guard.enable:
        return False, "Autorun is disabled (runtime.recon.enable_autorun=false)"

    c = (cmd or "").strip()
    if not c:
        return False, "Empty command"

    if guard.block_chaining:
        if "&&" in c or ";" in c:
            return False, "Command chaining is not allowed (contains && or ;)"
        if ("|" in c) and (not guard.allow_pipes):
            return False, "Piping is not allowed (contains |)"

    for pat in denylist:
        if pat.search(c):
            return False, f"Matched denied_cmd_regex: {pat.pattern}"

    if allowlist:
        for pat in allowlist:
            if pat.search(c):
                return True, "OK"
        return False, "Did not match any allowed_cmd_regex"

    return True, "OK"


# ----------------------------
# Models
# ----------------------------
class ReconResponse(BaseModel):
    analysis: Any = Field(description="Analysis of the previous step")
    next_step: str = Field(description="What to do next")
    executable: str = Field(description="Command to execute, or 'None' if no command needed")


# ----------------------------
# Helper functions
# ----------------------------
def _extract_json_data(text: str) -> Optional[dict]:
    """Best-effort extraction of a JSON object from arbitrary LLM text.

    - Prefers JSON inside ```json fences if present.
    - Otherwise scans for balanced {...} objects and returns the first one that parses.
    - Falls back to a greedy regex only as a last resort.
    """
    if not text:
        return None

    # 1) Code-fence JSON
    fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, flags=re.DOTALL | re.IGNORECASE)
    if fence:
        try:
            return json.loads(fence.group(1))
        except Exception:
            pass

    # 2) Balanced-brace scan (fast enough for our typical LLM outputs)
    s = text
    starts = [i for i, ch in enumerate(s) if ch == '{']
    for start in starts:
        depth = 0
        in_str = False
        esc = False
        for j in range(start, len(s)):
            ch = s[j]
            if in_str:
                if esc:
                    esc = False
                elif ch == '\\':
                    esc = True
                elif ch == '"':
                    in_str = False
                continue
            else:
                if ch == '"':
                    in_str = True
                    continue
                if ch == '{':
                    depth += 1
                elif ch == '}':
                    depth -= 1
                    if depth == 0:
                        candidate = s[start:j+1].strip()
                        # Skip obviously huge candidates that are unlikely to be the intended JSON
                        if len(candidate) > 200_000:
                            break
                        try:
                            return json.loads(candidate)
                        except Exception:
                            break  # move to next '{' start
        # continue to next start

    # 3) Last resort: greedy-ish regex
    m = re.search(r"(\{.*\})", text, flags=re.DOTALL)
    if m:
        try:
            return json.loads(m.group(1))
        except Exception:
            return None
    return None


def _normalize_llm_payload(obj: Any) -> Dict[str, Any]:
    """Normalize multiple possible LLM schemas into the agent's expected schema.

    Expected schema:
      {
        "analysis": <dict>,
        "next_step": <str>,
        "executable": <str|null>
      }

    The model sometimes emits alternate schemas like:
      {"command":"curl","url":"http://..."}
      {"cmd":"curl http://..."}
      {"title":"...", "content":"..."}  # analysis-only
    """
    out: Dict[str, Any] = {"analysis": {}, "next_step": "", "executable": None}

    if not isinstance(obj, dict):
        out["analysis"] = {"raw": str(obj)}
        return out

    # Already in expected-ish schema
    if any(k in obj for k in ("analysis", "next_step", "executable")):
        out["analysis"] = obj.get("analysis") or {}
        out["next_step"] = obj.get("next_step") or ""
        out["executable"] = obj.get("executable", None)
        for k, v in obj.items():
            if k not in out:
                out[k] = v
        return out

    # Alternate direct command schema
    if isinstance(obj.get("cmd"), str):
        out["analysis"] = obj.get("analysis") or {}
        out["next_step"] = obj.get("next_step") or ""
        out["executable"] = obj["cmd"]
        for k, v in obj.items():
            if k not in out:
                out[k] = v
        return out

    if "command" in obj:
        cmd = str(obj.get("command") or "").strip()
        args = obj.get("args", "")
        if isinstance(args, list):
            args = " ".join(map(str, args))
        if cmd.lower() == "curl":
            url = obj.get("url") or obj.get("target") or obj.get("uri") or ""
            flags = obj.get("flags") or ""
            # Some prompts output {"command":"curl","url":"http://x"}; build a basic curl.
            built = "curl"
            if flags:
                built += f" {flags}"
            if url:
                built += f" {url}"
            out["executable"] = built.strip()
        elif cmd.lower() == "nmap":
            target = obj.get("target") or obj.get("ip") or ""
            opts = obj.get("opts") or obj.get("options") or ""
            out["executable"] = f"nmap {opts} {target}".strip()
        else:
            out["executable"] = " ".join([cmd, str(args)]).strip() if cmd else None

        out["analysis"] = obj.get("analysis") or {}
        out["next_step"] = obj.get("next_step") or ""
        for k, v in obj.items():
            if k not in out:
                out[k] = v
        return out

    # Analysis-only schema (used by ANALYZE commands)
    if "title" in obj and "content" in obj:
        out["analysis"] = obj
        return out

    # Default: treat as analysis blob
    out["analysis"] = obj
    return out


def _normalize_keyword(raw: str) -> str:
    s = (raw or "").strip()
    if not s:
        return ""
    low = s.lower()
    low = re.sub(r"[\s_\-]+", " ", low).strip()
    if "activemq" in low and (
        "web console" in low
        or "webconsole" in low
        or ("web" in low and "console" in low)
        or "console" in low
    ):
        return "ActiveMQ"
    s = re.sub(r"\s+", " ", s).strip()
    return s


def _normalize_keywords_list(keywords: List[str]) -> List[str]:
    out: List[str] = []
    seen = set()
    for k in keywords or []:
        nk = _normalize_keyword(str(k))
        if not nk:
            continue
        if nk.lower() in seen:
            continue
        seen.add(nk.lower())
        out.append(nk)
    return out


def _post_enrich_summary(parsed: Dict[str, Any]) -> Dict[str, Any]:
    """Best-effort enrichment to stabilize reports for common surfaces.

    This adds *hypothesis* items only when directly supported by observed paths/patterns
    in the snapshot. It is intentionally conservative and evidence-first.
    """
    if not isinstance(parsed, dict):
        return parsed
    analysis = parsed.get("analysis")
    if not isinstance(analysis, dict):
        return parsed

    web = analysis.get("web") or {}
    ports = analysis.get("ports") or {}
    planning = analysis.get("planning") or {}
    triage = analysis.get("triage") or {"issues": [], "cve_candidates": []}

    if not isinstance(web, dict):
        web = {}
    if not isinstance(planning, dict):
        planning = {}
    if not isinstance(triage, dict):
        triage = {"issues": [], "cve_candidates": []}

    issues = triage.get("issues") or []
    cands = triage.get("cve_candidates") or []
    if not isinstance(issues, list):
        issues = []
    if not isinstance(cands, list):
        cands = []

    # Collect observed paths
    paths = set()
    for pth in (web.get("interesting_paths") or []):
        try:
            paths.add(str(pth))
        except Exception:
            pass
    for ev in (web.get("evidence") or []):
        if isinstance(ev, dict) and ev.get("path"):
            paths.add(str(ev.get("path")))

    def has_issue(issue_id: str) -> bool:
        return any(isinstance(i, dict) and i.get("id") == issue_id for i in issues)

    def add_issue(obj: Dict[str, Any]) -> None:
        if not has_issue(obj.get("id", "")):
            issues.append(obj)

    # Heuristic: Struts-style .action endpoints
    action_paths = [p for p in paths if p.lower().endswith(".action")]
    if action_paths:
        # Planning hints
        if not planning.get("app"):
            planning["app"] = "Apache Struts 2 (hypothesis)"
        if not planning.get("planning_keywords"):
            planning["planning_keywords"] = [
                "Struts2 .action endpoint surface",
                "CVE-2017-5638",
                "CVE-2017-9805",
                "CVE-2018-11776",
                "CVE-2019-0230",
                "CVE-2020-17530",
            ]
        if not planning.get("rationale"):
            planning["rationale"] = (
                "Observed one or more '.action' endpoints (common in Struts2 apps). "
                "Treat as hypothesis; verify stack/version with safe header/error-signature checks."
            )

        # More specific: Monitoring + Welcome.action pattern
        mon_welcome = None
        for pth in action_paths:
            if "monitoring" in pth.lower() and "welcome.action" in pth.lower():
                mon_welcome = pth
                break

        if mon_welcome:
            add_issue(
                {
                    "id": "SIG_STRUTS2_MONITORING_WELCOME_ACTION",
                    "title": "Monitoring + Welcome.action pattern (Stratosphere-style surface)",
                    "vuln_type": "Known-CVE hypothesis (Struts2 action endpoint)",
                    "confidence": 0.75,
                    "cve_hints": ["CVE-2017-5638", "CVE-2018-11776"],
                    "evidence": [
                        f"Observed Struts-style endpoint under Monitoring: {mon_welcome}",
                    ],
                    "matched": {"matched_path": mon_welcome},
                }
            )
            # Candidates
            for cve_id in ["CVE-2017-5638", "CVE-2018-11776"]:
                cands.append(
                    {
                        "cve_id": cve_id,
                        "confidence": 0.75,
                        "source": "SIG_STRUTS2_MONITORING_WELCOME_ACTION",
                        "evidence": [f"Observed endpoint: {mon_welcome}"],
                    }
                )

        add_issue(
            {
                "id": "SIG_STRUTS2_ACTION_ENDPOINT",
                "title": "Struts-style .action endpoint observed (candidate set)",
                "vuln_type": "Known-CVE hypothesis (Apache Struts2 surface)",
                "confidence": 0.6,
                "cve_hints": ["CVE-2017-5638", "CVE-2018-11776", "CVE-2019-0230", "CVE-2020-17530"],
                "evidence": [f"Found .action endpoint(s): {', '.join(sorted(action_paths))}"],
                "matched": {"matched_path": mon_welcome or action_paths[0]},
            }
        )

        # Dedup cve candidates (keep best confidence)
        best = {}
        for c in cands:
            if not isinstance(c, dict) or not c.get("cve_id"):
                continue
            cid = str(c["cve_id"])
            conf = float(c.get("confidence", 0.0) or 0.0)
            if cid not in best or conf > float(best[cid].get("confidence", 0.0) or 0.0):
                best[cid] = c
        cands = list(best.values())

    # Heuristic: Tomcat Manager exposure
    mgr_paths = [p for p in paths if p.rstrip("/").lower().endswith("/manager") or "manager" in p.lower()]
    if mgr_paths and not has_issue("SIG_TOMCAT_MANAGER_EXPOSED"):
        add_issue(
            {
                "id": "SIG_TOMCAT_MANAGER_EXPOSED",
                "title": "Tomcat Manager/Host-Manager paths observed",
                "vuln_type": "Administrative surface exposure (verify auth, avoid brute-force)",
                "confidence": 0.55,
                "cve_hints": [],
                "evidence": [f"Observed admin paths: {', '.join(sorted(mgr_paths)[:6])}"],
                "matched": {"matched_path": sorted(mgr_paths)[0]},
            }
        )

    triage["issues"] = issues
    triage["cve_candidates"] = cands
    analysis["planning"] = planning
    analysis["triage"] = triage
    parsed["analysis"] = analysis
    return parsed



def _add_user(history: InMemoryChatMessageHistory, content: str) -> None:
    history.add_message(HumanMessage(content=content))


def _add_ai(history: InMemoryChatMessageHistory, content: str) -> None:
    history.add_message(AIMessage(content=content))


def _get_messages(history: InMemoryChatMessageHistory) -> List[BaseMessage]:
    return list(getattr(history, "messages", []))


def _parse_http_status(output: str) -> Optional[int]:
    if not output:
        return None
    m = re.search(r"HTTP/\S+\s+(\d{3})", output)
    if not m:
        return None
    try:
        return int(m.group(1))
    except ValueError:
        return None


def _extract_meta_refresh_url(html: str) -> Optional[str]:
    if not html:
        return None
    # META HTTP-EQUIV="Refresh" CONTENT="0;URL=example/Welcome.action"
    m = re.search(r'http-equiv=["\']refresh["\']\s+content=["\']\s*\d+\s*;\s*url=([^"\']+)["\']', html, re.I)
    if m:
        return m.group(1).strip()
    m2 = re.search(r'content=["\']\s*\d+\s*;\s*url=([^"\']+)["\']', html, re.I)
    if m2:
        return m2.group(1).strip()
    return None


def _join_url(base: str, path: str) -> str:
    base = base.rstrip("/")
    if not path.startswith("/"):
        path = "/" + path
    return base + path


def _extract_gobuster_paths(output: str, max_items: int = 50) -> List[str]:
    """Parse gobuster dir output lines like: /Monitoring/ (Status: 200) [Size: 123]."""
    paths: List[str] = []
    if not output:
        return paths
    for line in output.splitlines():
        line = line.strip()
        m = re.match(r"^(/[^\s]+)\s+\(Status:\s*(\d{3})\)", line)
        if not m:
            continue
        p = m.group(1)
        if p and p not in paths:
            paths.append(p)
        if len(paths) >= max_items:
            break
    return paths


def _extract_location_header(headers_text: str) -> Optional[str]:
    if not headers_text:
        return None
    for line in headers_text.splitlines():
        if line.lower().startswith("location:"):
            return line.split(":", 1)[1].strip()
    return None


def _learn_from_command_result(cmd: str, output: str, state: Dict[str, Any]) -> None:
    """Best-effort parsing of command output to drive generic forced recon (no target-specific hardcoding)."""
    c = (cmd or "").strip()
    low = c.lower()
    out = output or ""

    # Track high-level steps
    if low.startswith("nmap ") and "-p-" in low:
        state["port_discovery_done"] = True
    if low.startswith("nmap ") and ("-sc" in low and "-sv" in low):
        state["version_scan_done"] = True
    if low.startswith("curl ") and " -i" in (" " + low):
        state["did_any_http_headers"] = True
    if low.startswith("whatweb "):
        state["did_whatweb"] = True
    if low.startswith("gobuster dir "):
        state["did_root_gobuster"] = True

    # Parse gobuster results
    if low.startswith("gobuster dir "):
        discovered = state.setdefault("discovered_paths", [])
        for p in _extract_gobuster_paths(out):
            if p not in discovered:
                discovered.append(p)

    # Parse META refresh from curl body
    if low.startswith("curl ") and (" -i" not in (" " + low)):
        mr = _extract_meta_refresh_url(out)
        if mr:
            m = re.search(r"(https?://[^\s]+)", c)
            if m:
                url = m.group(1)
                mm = re.match(r"^(https?://[^/]+)(/.*)?$", url)
                if mm:
                    base = mm.group(1)
                    req_path = mm.group(2) or "/"
                    if mr.startswith(("http://", "https://")):
                        resolved = mr
                    else:
                        if not req_path.endswith("/"):
                            req_dir = req_path.rsplit("/", 1)[0] + "/"
                        else:
                            req_dir = req_path
                        resolved = base + req_dir + mr.lstrip("/")
                    targets = state.setdefault("meta_refresh_targets", [])
                    if resolved not in targets:
                        targets.append(resolved)
                    if resolved.lower().endswith(".action"):
                        state["saw_action_endpoint"] = True

    # Parse Location header from curl -I output
    if low.startswith("curl ") and " -i" in (" " + low):
        loc = _extract_location_header(out)
        if loc and loc.lower().endswith(".action"):
            state["saw_action_endpoint"] = True

# ----------------------------
# State hydration & dedupe
# ----------------------------
def _hydrate_state_from_history(history: InMemoryChatMessageHistory, state: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Rebuild minimal progress state from persisted chat history."""
    executed: set = set()
    last_analysis: Optional[Dict[str, Any]] = None

    for m in _get_messages(history):
        if isinstance(m, AIMessage):
            obj = _extract_json_data(m.content)
            if not isinstance(obj, dict):
                continue

            analysis = obj.get("analysis")
            if isinstance(analysis, dict) and not is_blank_recon_analysis(analysis):
                if not isinstance(last_analysis, dict) or not last_analysis:
                    last_analysis = analysis
                else:
                    deep_merge_dict(last_analysis, analysis)

            exe = obj.get("executable")
            if isinstance(exe, str) and exe and exe != "None":
                executed.add(exe.strip())

    state["executed_cmds"] = executed

    # Derive coarse progress flags from executed commands
    for c in list(executed):
        low = str(c).lower()
        if low.startswith("nmap ") and "-p-" in low:
            state["port_discovery_done"] = True
        if low.startswith("nmap ") and ("-sc" in low and "-sv" in low):
            state["version_scan_done"] = True
        if low.startswith("curl ") and " -i" in (" " + low):
            state["did_any_http_headers"] = True
        if low.startswith("whatweb "):
            state["did_whatweb"] = True
        if low.startswith("gobuster dir ") and "common_directories.txt" in low:
            state["did_root_gobuster"] = True

    # Derive signals from last_analysis
    if isinstance(last_analysis, dict):
        ports = last_analysis.get("ports") or {}
        state["ports_seen"] = bool(isinstance(ports, dict) and ports)

        web = last_analysis.get("web") or {}
        if isinstance(web, dict):
            state["web_started"] = bool(web.get("base_urls"))
            interesting = web.get("interesting_paths") or []
            if isinstance(interesting, list) and any(str(p).lower().endswith(".action") for p in interesting):
                state["saw_action_endpoint"] = True

        planning = last_analysis.get("planning") or {}
        if isinstance(planning, dict):
            pk = planning.get("planning_keywords") or []
            kw = planning.get("keyword") or ""
            if (isinstance(pk, list) and pk) or (isinstance(kw, str) and kw.strip()):
                state["has_planning"] = True

    return last_analysis

# ----------------------------
# KB triage enrichment (best-effort)
# ----------------------------
def _enrich_artifact_with_kb(artifact_path: str) -> None:
    try:
        kb_query_candidates = [
            os.path.join(PROJECT_ROOT, "kb", "tools", "kb_query.py"),
            os.path.join(PROJECT_ROOT, "tools", "kb_query.py"),
        ]
        sig_candidates = [
            os.path.join(PROJECT_ROOT, "kb", "signatures.yaml"),
            os.path.join(PROJECT_ROOT, "kb", "signatures", "signatures.yaml"),
        ]
        kb_query = next((p for p in kb_query_candidates if os.path.exists(p)), None)
        sig_path = next((p for p in sig_candidates if os.path.exists(p)), None)

        if not kb_query or not sig_path:
            logger.info("[KB] Skipping triage enrichment (kb_query or signatures not found).")
            return
        if not artifact_path or not os.path.exists(artifact_path):
            logger.info("[KB] Skipping triage enrichment (artifact not found): %s", artifact_path)
            return

        triage_raw = subprocess.check_output(
            ["python", kb_query, "--artifact", artifact_path, "--signatures", sig_path],
            text=True
        )
        triage_obj = json.loads(triage_raw) if triage_raw else {}
        triage = triage_obj.get("triage", {}) if isinstance(triage_obj, dict) else {}

        artifact = json.loads(Path(artifact_path).read_text(encoding="utf-8"))

        # Merge triage into BOTH common shapes:
        # 1) artifact["analysis"]  (what planning expects)
        # 2) artifact["final_ai_message_json"]["analysis"] (debug wrapper)
        if isinstance(artifact, dict):
            # Top-level analysis
            top_analysis = artifact.get("analysis") or {}
            if not isinstance(top_analysis, dict):
                top_analysis = {}
                artifact["analysis"] = top_analysis
            top_analysis["triage"] = triage

            # Nested analysis
            if isinstance(artifact.get("final_ai_message_json"), dict):
                final = artifact.get("final_ai_message_json") or {}
                nested_analysis = final.get("analysis") or {}
                if not isinstance(nested_analysis, dict):
                    nested_analysis = {}
                    final["analysis"] = nested_analysis
                nested_analysis["triage"] = triage
                artifact["final_ai_message_json"] = final

        Path(artifact_path).write_text(json.dumps(artifact, indent=2, ensure_ascii=False), encoding="utf-8")
        logger.info("[KB] Merged triage into artifact: %s", artifact_path)

    except Exception as e:
        logger.warning("[KB] Failed to enrich artifact with KB triage: %s", e)


# ----------------------------
# Forced recon command selection (dedup-aware)
# ----------------------------
def _forced_next_cmd(target_ip: str, state: Dict[str, Any], last_analysis: Optional[Dict[str, Any]]) -> Optional[str]:
    """Generic, dedupe-aware fallback recon.

    This is a safety net when the LLM returns executable=None too early.
    Target-/vulnerability-specific playbooks must live in prompts (recon_init) and/or the offline KB.
    """
    executed = state.setdefault("executed_cmds", set())

    def pick(cmd: str) -> Optional[str]:
        c = (cmd or "").strip()
        if not c:
            return None
        if c in executed:
            return None
        executed.add(c)
        return c

    if not target_ip or target_ip == "unknown_ip":
        return None

    # Budget to avoid infinite loops
    forced_steps = int(state.get("forced_steps", 0))
    if forced_steps >= int(state.get("forced_steps_budget", 8)):
        return None

    # Prefer stopping if we already have planning + baseline discovery
    if state.get("has_planning") and state.get("port_discovery_done") and (state.get("version_scan_done") or not state.get("ports_seen")):
        if state.get("did_any_http_headers") or not state.get("http_seen"):
            return None

    ports: Dict[str, Any] = {}
    web: Dict[str, Any] = {}
    if isinstance(last_analysis, dict):
        ports = last_analysis.get("ports") or {}
        web = last_analysis.get("web") or {}

    http_present = False
    open_ports: List[str] = []
    if isinstance(ports, dict):
        for p, info in ports.items():
            if isinstance(info, dict) and str(info.get("accessibility", "")).lower() == "open":
                open_ports.append(str(p))
                svc = str(info.get("service") or "").lower()
                if svc in ("http", "https", "http-proxy"):
                    http_present = True

    state["http_seen"] = http_present
    state["ports_seen"] = bool(ports)

    base_urls: List[str] = []
    if isinstance(web, dict):
        base_urls = [str(u) for u in (web.get("base_urls") or []) if str(u).startswith("http")]
    if not base_urls:
        base_urls = [f"http://{target_ip}", f"http://{target_ip}:8080"]
    chosen = next((u for u in base_urls if ":8080" in u), base_urls[0])

    # 1) Port discovery
    if not state.get("port_discovery_done"):
        cmd = pick(f"nmap -Pn -p- --min-rate 2000 -T4 --max-retries 1 --host-timeout 240s {target_ip}")
        if cmd:
            state["forced_steps"] = forced_steps + 1
        return cmd

    # 2) Version scan on discovered open ports
    if open_ports and not state.get("version_scan_done"):
        ports_csv = ",".join(sorted(set(open_ports), key=lambda x: int(x) if x.isdigit() else 99999))
        cmd = pick(f"nmap -Pn -p {ports_csv} -T4 -sC -sV {target_ip}")
        if cmd:
            state["forced_steps"] = forced_steps + 1
        return cmd

    # 3) HTTP headers + fingerprints
    if http_present and not state.get("did_any_http_headers"):
        cmd = pick(f"curl -sS -I {chosen}/")
        if cmd:
            state["forced_steps"] = forced_steps + 1
        return cmd

    if http_present and not state.get("did_whatweb"):
        cmd = pick(f"whatweb {chosen}/")
        if cmd:
            state["forced_steps"] = forced_steps + 1
        return cmd

    # 4) Root directory discovery
    if http_present and not state.get("did_root_gobuster"):
        cmd = pick(f"gobuster dir -u {chosen} -w /home/pentestagent/SecLists/Discovery/Web-Content/common_directories.txt -t 30 -q -b 404")
        if cmd:
            state["forced_steps"] = forced_steps + 1
        return cmd

    # 5) Follow META refresh targets if observed
    targets: List[str] = [str(u) for u in state.get("meta_refresh_targets", []) if str(u).startswith("http")]
    if targets and not state.get("did_follow_meta_refresh"):
        cmd = pick(f"curl -sS -I {targets[0]}")
        if cmd:
            state["did_follow_meta_refresh"] = True
            state["forced_steps"] = forced_steps + 1
        return cmd

    # 6) Probe one new discovered path
    discovered_paths: List[str] = state.get("discovered_paths", []) or []
    probed: set = set(state.get("probed_paths", []) or [])
    for p in discovered_paths:
        if p in probed:
            continue
        cmd = pick(f"curl -sS -I -L {chosen}{p}")
        if cmd:
            probed.add(p)
            state["probed_paths"] = list(probed)
            state["forced_steps"] = forced_steps + 1
        return cmd

    return None


# ----------------------------
# Agent
# ----------------------------


def _clip_for_llm(text: str, max_chars: int = 4000) -> str:
    """Clip / sanitize large command outputs before sending back into LLM context.

    Key goals:
      - Prevent prompt blow-ups (e.g., embedded base64 images, huge minified JS/CSS)
      - Keep enough signal for reasoning (headers, paths, version strings, errors)
    """
    t = text or ""

    # Drop embedded base64 data URIs (they are high-token / low-signal)
    # Example: data:image/jpg;base64,AAAA....
    t = re.sub(r"data:[^;\s]+;base64,[A-Za-z0-9+/=]+", "[base64 omitted]", t)

    # Compact consecutive whitespace a bit (keeps diffs readable, reduces tokens)
    t = re.sub(r"[ \t]{3,}", "  ", t)

    if len(t) <= max_chars:
        return t
    return t[:max_chars] + f"\n...[clipped, total_chars={len(t)}]"



def _operator_gate(mode: str) -> Optional[str]:
    """
    Operator-guided control:
      - returns None to continue automatically
      - returns 'stop' to stop execution
      - returns instruction string to inject at highest priority
    """
    mode = (mode or "auto").strip().lower()
    if mode == "auto":
        return None

    print("\n[GUIDED MODE] Enter next instruction (auto/stop/or your instruction):")
    user = input("> ").strip()
    if not user:
        return None
    if user.lower() == "auto":
        return None
    if user.lower() == "stop":
        return "stop"
    return user



def _parse_operator_input(raw: Optional[str]) -> tuple[str, str]:
    """Parse operator input prefixes.
    Returns (intent, payload)
      - intent in {"AUTO","STOP","CMD","ASK","SUMMARY","TASK","RAW"}
    """
    if raw is None:
        return ("AUTO", "")
    s = raw.strip()
    if not s:
        return ("AUTO", "")
    low = s.lower()
    if low == "auto":
        return ("AUTO", "")
    if low == "stop":
        return ("STOP", "")
    # Prefix forms
    for prefix, intent in [("cmd:", "CMD"), ("ask:", "ASK"), ("summary:", "SUMMARY"), ("task:", "TASK")]:
        if low.startswith(prefix):
            return (intent, s[len(prefix):].strip())
    # convenience: a bare 'summary'
    if low == "summary":
        return ("SUMMARY", "")
    return ("RAW", s)


def _format_operator_summary(last_analysis: Any, rolling_summary: str) -> str:
    """Human-friendly summary printed to console; does not call LLM."""
    lines = []
    if rolling_summary:
        lines.append("Rolling summary:")
        lines.append(rolling_summary.strip())
    if isinstance(last_analysis, dict):
        target = last_analysis.get("target") or {}
        ip = ""
        if isinstance(target, dict):
            ip = str(target.get("ip") or "")
        ports = last_analysis.get("ports") or {}
        if isinstance(ports, dict) and ports:
            lines.append("")
            lines.append("Open services:")
            for p, info in ports.items():
                if not isinstance(info, dict):
                    continue
                acc = str(info.get("accessibility", "")).lower()
                if acc and acc != "open":
                    continue
                svc = str(info.get("service") or "")
                prod = str(info.get("product") or "")
                ver = str(info.get("version") or "")
                cands = info.get("cve_candidates") or []
                cands_txt = ""
                if isinstance(cands, list) and cands:
                    cands_txt = " | CVE candidates: " + ", ".join([str(x) for x in cands[:6]])
                lines.append(f"- {p}/tcp {svc} {prod} {ver}".strip() + cands_txt)
        web = last_analysis.get("web") or {}
        if isinstance(web, dict):
            base_urls = web.get("base_urls") or []
            ips = web.get("interesting_paths") or []
            if base_urls:
                lines.append("")
                lines.append("Base URLs: " + ", ".join([str(u) for u in base_urls[:6]]))
            if ips:
                lines.append("Interesting paths: " + ", ".join([str(p) for p in ips[:12]]))
        if ip and not lines:
            lines.append(f"Target: {ip}")
    if not lines:
        return "No findings yet."
    return "\n".join(lines).strip()

def _build_slim_messages(
    prompt_init: str,
    rolling_summary: str,
    history: InMemoryChatMessageHistory,
    last_k: int,
    operator_instruction: Optional[str],
) -> List[BaseMessage]:
    """
    Build a slim message list for LLM to reduce tokens:
      - Recon init reminder
      - Rolling summary (authoritative)
      - Tail of chat history (last_k messages)
      - Operator instruction (highest priority)
    """
    msgs: List[BaseMessage] = []
    msgs.append(HumanMessage(content=prompt_init))

    if rolling_summary:
        msgs.append(
            HumanMessage(
                content="ROLLING_SUMMARY (authoritative; do not contradict):\n" + rolling_summary
            )
        )

    tail = _get_messages(history)[-last_k:] if last_k and last_k > 0 else []
    msgs.extend(tail)

    if operator_instruction:
        msgs.append(
            HumanMessage(
                content="OPERATOR_INSTRUCTION (highest priority): " + operator_instruction
            )
        )

    return msgs


def _update_rolling_summary_from_analysis(prev: str, analysis: Any, max_chars: int = 6000) -> str:
    """Lightweight rule-based rolling summary to keep context small and stable."""
    lines: List[str] = []
    if isinstance(analysis, dict):
        ports = analysis.get("ports") or {}
        if isinstance(ports, dict) and ports:
            open_ports = []
            for p, info in ports.items():
                if isinstance(info, dict) and str(info.get("accessibility", "")).lower() == "open":
                    svc = str(info.get("service") or "")
                    prod = str(info.get("product") or "")
                    ver = str(info.get("version") or "")
                    open_ports.append(f"{p}/{svc} {prod} {ver}".strip())
            if open_ports:
                lines.append("Open ports: " + ", ".join(open_ports[:20]))

        web = analysis.get("web") or {}
        if isinstance(web, dict):
            base_urls = web.get("base_urls") or []
            if isinstance(base_urls, list) and base_urls:
                lines.append("Base URLs: " + ", ".join([str(u) for u in base_urls[:4]]))
            paths = web.get("interesting_paths") or []
            if isinstance(paths, list) and paths:
                lines.append("Interesting paths: " + ", ".join([str(p) for p in paths[:12]]))

        planning = analysis.get("planning") or {}
        if isinstance(planning, dict):
            app = str(planning.get("app") or "")
            ver = str(planning.get("version") or "")
            kw = str(planning.get("keyword") or "")
            if app or kw:
                lines.append(f"Planning: app={app} version={ver} keyword={kw}".strip())

    new_block = "\n".join([l for l in lines if l])
    if not new_block:
        return (prev or "")[-max_chars:] if prev else ""

    merged = (prev + "\n" + new_block).strip() if prev else new_block
    if len(merged) > max_chars:
        merged = merged[-max_chars:]
    return merged

class ReconAgent:
    def __init__(self, recon_cfg: Dict[str, Any]):
        self.recon_cfg = recon_cfg
        self.memory_dir = recon_cfg.get("memory_dir", "recon_memory")
        if not os.path.isabs(self.memory_dir):
            self.memory_dir = os.path.join(PROJECT_ROOT, self.memory_dir)
        os.makedirs(self.memory_dir, exist_ok=True)

        # Load env vars from repo root
        dotenv_path = os.path.join(PROJECT_ROOT, ".env")
        if os.path.exists(dotenv_path):
            dotenv.load_dotenv(dotenv_path=dotenv_path, override=False)
        else:
            dotenv.load_dotenv(override=False)

        model_name = recon_cfg.get("model", "openai")
        self.llm = get_model(model_name)

        self.memory_map: Dict[str, InMemoryChatMessageHistory] = {}

        self.guard = ExecGuard(
            enable=bool(recon_cfg.get("enable_autorun", False)),
            allowed_cmd_regex=list(recon_cfg.get("allowed_cmd_regex", []) or []),
            denied_cmd_regex=list(recon_cfg.get("denied_cmd_regex", []) or []),
            timeout_sec=int(recon_cfg.get("command_timeout_sec", 60)),
            max_output_chars=int(recon_cfg.get("max_output_chars", 20000)),
            block_chaining=bool(recon_cfg.get("block_chaining", False)),
            allow_pipes=bool(recon_cfg.get("allow_pipes", True)),
        )
        self._allowlist = _compile_patterns(self.guard.allowed_cmd_regex)
        self._denylist = _compile_patterns(self.guard.denied_cmd_regex)

        self.cwd: Optional[str] = None

    def get_memory(self, topic: str) -> InMemoryChatMessageHistory:
        if topic not in self.memory_map:
            self.memory_map[topic] = InMemoryChatMessageHistory()
        return self.memory_map[topic]

    def init_thread(self, topic: str) -> None:
        _ = self.get_memory(topic)

    def send_message(self, topic: str, msg_content: str) -> None:
        history = self.get_memory(topic)
        _add_user(history, msg_content)

    def get_last_message(self, topic: str) -> str:
        history = self.get_memory(topic)
        msgs = _get_messages(history)
        return msgs[-1].content if msgs else ""

    def run_thread(self, topic: str, messages_override: Optional[List[BaseMessage]] = None) -> Optional[str]:
        history = self.get_memory(topic)
        msgs = messages_override if messages_override is not None else _get_messages(history)
        if not msgs:
            return None

        max_retries = 3
        for attempt in range(max_retries):
            try:
                response = self.llm.invoke(msgs, timeout=30)
                response_content = getattr(response, "content", str(response))
                # Persist AI reply in full history for resume/debugging
                _add_ai(history, response_content)
                return response_content
            except Exception as e:
                s = str(e)
                logger.error(f"API call failed (attempt {attempt+1}/{max_retries}): {s}")
            # checkpoint save on LLM failure
            try:
                self.save_memory_to_file(topic)
            except Exception:
                pass
                # If rate limit, backoff a bit but do not spin forever
                if "rate limit" in s.lower() or "429" in s:
                    time.sleep(20)
                else:
                    time.sleep(2 * (attempt + 1))
        return None

    def run_shell_command(self, command: str) -> str:
        cmd = (command or "").strip()
        if not cmd:
            return "[SKIP] Empty command"

        m = re.match(r"^\s*cd\s+(.+?)\s*$", cmd)
        if m:
            target = m.group(1).strip().strip('"').strip("'")
            base = self.cwd or os.getcwd()
            new_dir = target if os.path.isabs(target) else os.path.abspath(os.path.join(base, target))
            if os.path.isdir(new_dir):
                self.cwd = new_dir
                return f"[OK] Changed directory to: {new_dir}"
            return f"[ERROR] cd failed: directory not found: {new_dir}"

        ok, reason = _check_cmd(cmd, self.guard, self._allowlist, self._denylist)
        if not ok:
            msg = f"[BLOCKED] {reason}. Command: {cmd}"
            logger.warning(msg)
            return msg

        try:
            result = subprocess.run(
                cmd,
                shell=True,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=self.guard.timeout_sec,
                cwd=self.cwd,
            )
            out = (result.stdout or "") + (("\n" + result.stderr) if result.stderr else "")
            return out[: self.guard.max_output_chars]
        except subprocess.CalledProcessError as e:
            err = (e.stdout or "") + (("\n" + e.stderr) if e.stderr else "")
            err = err[: self.guard.max_output_chars]
            return err or f"Command failed with returncode={getattr(e, 'returncode', '?')}"
        except subprocess.TimeoutExpired:
            return f"Command timed out after {self.guard.timeout_sec} seconds"

    def save_memory_to_file(self, topic: str) -> str:
        history = self.get_memory(topic)
        messages = _get_messages(history)
        memory_file = os.path.join(self.memory_dir, f"{topic}.json")

        payload: List[Dict[str, Any]] = []
        for m in messages:
            if isinstance(m, HumanMessage):
                payload.append({"type": "human", "data": {"content": m.content}})
            elif isinstance(m, AIMessage):
                payload.append({"type": "ai", "data": {"content": m.content}})
            else:
                payload.append({"type": "unknown", "data": {"content": getattr(m, "content", str(m))}})

        with open(memory_file, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)

        logger.info(f"Saved {len(messages)} messages to {memory_file}")
        return memory_file

    def load_memory_from_file(self, topic: str) -> bool:
        memory_file = os.path.join(self.memory_dir, f"{topic}.json")
        if not os.path.exists(memory_file):
            return False

        history = self.get_memory(topic)
        try:
            raw = json.loads(Path(memory_file).read_text(encoding="utf-8"))
            if not isinstance(raw, list):
                return False
            for item in raw:
                t = item.get("type")
                content = (item.get("data") or {}).get("content", "")
                if not content:
                    continue
                if t == "human":
                    _add_user(history, content)
                elif t == "ai":
                    _add_ai(history, content)
            logger.info("[Recon] Resumed %d messages from %s", len(_get_messages(history)), memory_file)
            return True
        except Exception as e:
            logger.warning("[Recon] Failed to resume history: %s", e)
            return False

    def write_recon_artifact(self, topic: str, final_ai_text: str) -> str:
        artifact_path = os.path.join(self.memory_dir, f"{topic}_artifact.json")
        obj = _extract_json_data(final_ai_text) or {"raw": final_ai_text}

        if isinstance(obj, dict):
            analysis = obj.get("analysis")
            if isinstance(analysis, dict):
                pk = analysis.get("planning", {}).get("planning_keywords")
                # normalize if present (older schemas may place it differently)
                if isinstance(pk, list):
                    original = [str(x) for x in pk]
                    normalized = _normalize_keywords_list(original)
                    analysis["planning"]["planning_keywords_original"] = original
                    analysis["planning"]["planning_keywords"] = normalized

        payload = {
            "topic": topic,
            "captured_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "final_ai_message_raw": final_ai_text,
            "final_ai_message_json": obj,
        }
        with open(artifact_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)

        _enrich_artifact_with_kb(artifact_path)
        logger.info("Wrote recon artifact: %s", artifact_path)
        return artifact_path


    def write_recon_artifact_single(self, topic: str, parsed_obj: Dict[str, Any], raw_text: str) -> str:
        """Write a single recon artifact file (no separate summary file).
    
        The artifact is intended to be consumed by downstream agents. It keeps a single
        canonical copy of analysis/next_step/executable at the top-level to avoid
        duplicated JSON blobs.
    
        Payload shape:
          {
            "topic": ...,
            "captured_at": ...,
            "analysis": {...},
            "next_step": "...",
            "executable": "None",
            "final_ai_message_raw": "<raw LLM JSON>"
          }
        """
        artifact_path = os.path.join(self.memory_dir, f"{topic}_artifact.json")
        obj = parsed_obj if isinstance(parsed_obj, dict) else {}
        analysis = obj.get("analysis") if isinstance(obj, dict) else None
        if not isinstance(analysis, dict):
            analysis = {}
    
        # Normalize planning keywords if present
        try:
            planning = analysis.get("planning") or {}
            if isinstance(planning, dict):
                pk = planning.get("planning_keywords")
                if isinstance(pk, list):
                    original = [str(x) for x in pk]
                    normalized = _normalize_keywords_list(original)
                    planning["planning_keywords_original"] = original
                    planning["planning_keywords"] = normalized
                    analysis["planning"] = planning
        except Exception:
            pass
    
        payload = {
            "topic": topic,
            "captured_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "analysis": analysis,
            "next_step": str(obj.get("next_step", "") or ""),
            "executable": str(obj.get("executable", "None") or "None"),
            "final_ai_message_raw": raw_text,
        }
    
        with open(artifact_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)
    
        # Optional KB enrichment (best-effort)
        _enrich_artifact_with_kb(artifact_path)
        logger.info("Wrote recon artifact: %s", artifact_path)
        return artifact_path
    
    
        def write_recon_summary_artifact(self, topic: str, analysis: Dict[str, Any]) -> str:
            """Export a recon summary artifact WITHOUT calling the LLM.
            Produces:
              - <topic>_recon_summary.json  (plain: {"analysis": ...})
              - <topic>_artifact.json      (wrapper compatible with existing planning reader)
            """
            analysis = analysis if isinstance(analysis, dict) else {}
            # Ensure schema keys exist
            analysis.setdefault("target", {"ip": "", "os_guess": "N/A", "hostnames": [], "notes": []})
            analysis.setdefault("ports", {})
            analysis.setdefault(
                "web",
                {
                    "base_urls": [],
                    "redirects": [],
                    "fingerprints": [],
                    "interesting_paths": [],
                    "virtual_hosts": [],
                    "evidence": [],
                },
            )
            analysis.setdefault(
                "planning",
                {
                    "keyword": "",
                    "app": "",
                    "version": "",
                    "vuln_type": "",
                    "planning_keywords": [],
                    "planning_keywords_original": [],
                    "cve_ids": [],
                    "rationale": "",
                },
            )
    
            # Normalize planning keywords (keep original)
            try:
                pk = (analysis.get("planning") or {}).get("planning_keywords")
                if isinstance(pk, list):
                    original = [str(x) for x in pk]
                    normalized = _normalize_keywords_list(original)
                    analysis["planning"]["planning_keywords_original"] = original
                    analysis["planning"]["planning_keywords"] = normalized
            except Exception:
                pass
    
            # 1) Plain summary file
            summary_path = os.path.join(self.memory_dir, f"{topic}_recon_summary.json")
            with open(summary_path, "w", encoding="utf-8") as f:
                json.dump({"analysis": analysis}, f, indent=2, ensure_ascii=False)
    
            # 2) Wrapper artifact (backward compatible)
            artifact_path = os.path.join(self.memory_dir, f"{topic}_artifact.json")
            # NOTE: planning_agent historically expects `analysis` at the top-level.
            # Keep a small wrapper for debugging/backward compatibility, but always
            # duplicate the canonical fields at the root.
            payload = {
                "analysis": analysis,
                "next_step": "",
                "executable": "None",
                "topic": topic,
                "captured_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "final_ai_message_raw": "[LOCAL SUMMARY] Exported without LLM.",
                "final_ai_message_json": {"analysis": analysis, "next_step": "", "executable": "None"},
            }
            with open(artifact_path, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2, ensure_ascii=False)
    
            # KB triage enrichment (best-effort)
            _enrich_artifact_with_kb(summary_path)
            _enrich_artifact_with_kb(artifact_path)
    
            logger.info("Wrote recon summary: %s", summary_path)
            logger.info("Wrote recon artifact: %s", artifact_path)
            return summary_path
    
    
    
def main() -> None:
    config = load_config(CONFIG_PATH, expand_env=False)
    recon_config = get_runtime_section(config, "recon")
    cfg = recon_config  # backward-compatible alias (some older code uses cfg)
    if not recon_config:
        raise KeyError("Missing runtime.recon section in configs/config.yaml")

    start_time = time.time()
    recon_agent = ReconAgent(recon_config)

    curr_topic = (recon_config.get("current_topic") or "default_topic").strip()
    target_ip = (recon_config.get("target_ip") or "").strip()


    # Operator-guided / context-budgeting knobs
    mode = str(recon_config.get("mode", "auto") or "auto").strip().lower()  # auto|guided|approval
    history_window = int(recon_config.get("history_window", 8) or 8)
    summary_max_chars = int(recon_config.get("summary_max_chars", 6000) or 6000)
    llm_clip_chars = int(recon_config.get("llm_clip_chars", 4000) or 4000)

    if not target_ip:
        raise ValueError("runtime.recon.target_ip is empty in configs/config.yaml")

    # State (persisted by hydration, not to disk)
    state: Dict[str, Any] = {

        "executed_cmds": set(),
        "port_discovery_done": False,
        "version_scan_done": False,
        "ports_seen": False,
        "http_seen": False,

        "web_started": False,
        "did_any_http_headers": False,
        "did_whatweb": False,
        "did_root_gobuster": False,

        "discovered_paths": [],
        "meta_refresh_targets": [],
        "probed_paths": [],

        "saw_action_endpoint": False,
        "has_planning": False,

        "rolling_summary": "",

        "none_streak": 0,
        "forced_steps": 0,
        "forced_steps_budget": 8,
    }

    # Resume if possible
    recon_agent.init_thread(curr_topic)
    resumed = recon_agent.load_memory_from_file(curr_topic)

    # Always re-anchor with recon_init on resume so rules are present
    prompt = PentestAgentPrompt()
    recon_init_message = prompt.recon_init.replace("<Target-Ip>", target_ip)

    if not resumed:
        recon_agent.send_message(curr_topic, recon_init_message)
        recon_agent.send_message(curr_topic, f"I want to recon target host {target_ip} safely (read-only).")
    else:
        # Minimal reminder to avoid re-sending a huge init
        recon_agent.send_message(
            curr_topic,
            "SYSTEM REMINDER: Continue SAFE recon using the same JSON-only schema and the RECON_INIT rules. "
            "Do not brute-force credentials. Prefer following discovered redirects and META refresh to reach real endpoints."
        )

    history = recon_agent.get_memory(curr_topic)
    last_analysis = _hydrate_state_from_history(history, state)

    # Resume anchor: give the model a compact snapshot so it continues correctly after rate-limit/restart.
    if resumed and isinstance(last_analysis, dict):
        try:
            web = last_analysis.get("web") or {}
            planning = last_analysis.get("planning") or {}
            brief = {
                "ports": sorted(list((last_analysis.get("ports") or {}).keys()))[:30],
                "base_urls": list((web.get("base_urls") or []))[:4] if isinstance(web, dict) else [],
                "interesting_paths": list((web.get("interesting_paths") or []))[:12] if isinstance(web, dict) else [],
                "planning_keywords": list((planning.get("planning_keywords") or []))[:12] if isinstance(planning, dict) else [],
                "executed_cmds_count": len(state.get("executed_cmds", [])),
            }
            recon_agent.send_message(
                curr_topic,
                "RESUME_CONTEXT: Continue reconnaissance from the snapshot below. Do NOT repeat executed commands; "
                "instead, proceed to missing playbook steps. "
                + json.dumps(brief, ensure_ascii=False),
            )
        except Exception:
            pass

    max_attempts = int(recon_config.get("max_attempts", 30) or 30)
    attempts = 0

    while attempts < max_attempts:
        # Optional operator guidance (to reduce wandering / token burn)
        op = _operator_gate(mode)
        if op == "stop":
            recon_agent.save_memory_to_file(curr_topic)
            print("Stopped by operator.")
            return
        operator_instruction = op  # None or instruction string

        # Always checkpoint operator input so we can resume even if LLM rate-limits (429) later.
        intent, payload = _parse_operator_input(operator_instruction)
        if operator_instruction and operator_instruction not in ("stop",):
            recon_agent.send_message(curr_topic, f"[OPERATOR] {operator_instruction}")
            recon_agent.save_memory_to_file(curr_topic)

        # Handle local-only command execution without calling LLM (useful during 429).
        if intent == "CMD":
            cmd = payload
            if not cmd:
                print("CMD: empty command; nothing to run.")
                continue
            print("\n==============================")
            print("[Executable Command]\n", cmd)
            print("==============================\n")
            cmd_res = recon_agent.run_shell_command(cmd)
            print("[Command Execution Result]\n", cmd_res, "\n")
            recon_agent.send_message(
                curr_topic,
                "Here is what I got from executing the previous executable command (clipped for context):\n"
                + _clip_for_llm(cmd_res, max_chars=llm_clip_chars),
            )
            recon_agent.save_memory_to_file(curr_topic)
            attempts += 1
            continue

        # SUMMARY: call the LLM to produce a FINAL structured recon report, write ONE artifact file, then stop.
        # - No separate *_recon_summary.json file is written.
        if intent == "SUMMARY":
            # Legacy-style SUMMARY:
            # - Feed the FULL conversation history to the LLM (no slimming / no snapshot-only mode)
            # - Ask the model to output the FINAL JSON using recon_summary prompt
            # - Write exactly one artifact file: <topic>_artifact.json (wrapper with raw + parsed)
            recon_summary_message = prompt.recon_summary.replace("<Target-Ip>", target_ip)

            # Append the finalization instruction into the ongoing thread so the model sees full context.
            recon_agent.send_message(curr_topic, recon_summary_message)

            final_response = recon_agent.run_thread(curr_topic) or ""
            if not final_response:
                recon_agent.save_memory_to_file(curr_topic)
                print("[SUMMARY] LLM did not respond (likely 429/rate-limit). No artifact written.")
                return

            # Persist memory and write the standard artifact wrapper (same shape as the legacy pipeline).
            recon_agent.save_memory_to_file(curr_topic)
            artifact_path = recon_agent.write_recon_artifact(curr_topic, final_response)

            print(f"[SUMMARY] Wrote recon artifact: {artifact_path}")
            return
        if intent == "ASK":
            question = payload or operator_instruction
            msgs = _build_slim_messages(
                prompt_init="You are a helpful assistant. Answer the operator's question. Do NOT output JSON. If helpful, suggest up to 3 read-only evidence-gathering commands (do not execute them).",
                rolling_summary=state.get("rolling_summary", ""),
                history=recon_agent.get_memory(curr_topic),
                last_k=history_window,
                operator_instruction=question,
            )
            ans = recon_agent.run_thread(curr_topic, messages_override=msgs) or ""
            if ans:
                print("\n==============================")
                print("[ASK ANSWER]\n", ans)
                print("==============================\n")
            recon_agent.save_memory_to_file(curr_topic)
            attempts += 1
            continue

        # TASK: strip prefix payload to guide next step more cleanly
        if intent == "TASK":
            operator_instruction = payload or ""

        # Maintain a compact rolling summary to keep LLM context small
        state["rolling_summary"] = _update_rolling_summary_from_analysis(
            state.get("rolling_summary", ""),
            last_analysis,
            max_chars=summary_max_chars,
        )

        slim_msgs = _build_slim_messages(
            prompt_init="SYSTEM REMINDER: Continue SAFE recon using the JSON-only schema and the RECON_INIT rules. "
                        "Do not brute-force credentials. Prefer evidence-based enumeration.",
            rolling_summary=state.get("rolling_summary", ""),
            history=recon_agent.get_memory(curr_topic),
            last_k=history_window,
            operator_instruction=operator_instruction,
        )
        llm_out = recon_agent.run_thread(curr_topic, messages_override=slim_msgs)
        # If the API is rate-limited or fails, do not force more LLM calls.
        # Checkpoint memory and return to guided prompt so the operator can either run CMD: or retry later.
        if llm_out is None:
            recon_agent.save_memory_to_file(curr_topic)
            print("\n[LLM ERROR] No response (likely 429/rate-limit). History checkpointed.\n")
            attempts += 1
            continue

        recon_agent.save_memory_to_file(curr_topic)

        msg = recon_agent.get_last_message(curr_topic)
        parsed = _extract_json_data(msg)

        if not isinstance(parsed, dict):
            recon_agent.send_message(
                curr_topic,
                "The previous message is not valid JSON. Return ONLY a single JSON object with keys analysis,next_step,executable.",
            )
            attempts += 1
            continue

        analysis = parsed.get("analysis")
        next_step = str(parsed.get("next_step", "") or "")
        cmd = str(parsed.get("executable", "None") or "None")

        print("\n==============================")
        print("[LLM Analysis]\n", analysis if analysis is not None else {})
        print("[Next Step]\n", next_step)
        print("[Executable Command]\n", cmd)
        print("==============================\n")

        # Update last_analysis if usable (do not clobber with blank/empty payloads)
        if isinstance(analysis, dict) and not is_blank_recon_analysis(analysis):
            if not isinstance(last_analysis, dict) or not last_analysis:
                last_analysis = analysis
            else:
                deep_merge_dict(last_analysis, analysis)
            # quick flags
            web = analysis.get("web") or {}
            if isinstance(web, dict):
                ips = web.get("interesting_paths") or []
                if isinstance(ips, list) and any(str(p).lower().endswith(".action") for p in ips):
                    state["saw_action_endpoint"] = True
            planning = analysis.get("planning") or {}
            if isinstance(planning, dict):
                if (planning.get("planning_keywords") or []) or (planning.get("keyword") or ""):
                    state["has_planning"] = True

        if cmd and cmd != "None":
            # Dedup: if LLM repeats exact same cmd, block and nudge it
            if cmd.strip() in state["executed_cmds"]:
                recon_agent.send_message(
                    curr_topic,
                    "That command has already been executed. Propose a NEW read-only command that increases evidence.",
                )
                attempts += 1
                continue

            state["executed_cmds"].add(cmd.strip())
            cmd_res = recon_agent.run_shell_command(cmd)
            print("[Command Execution Result]\n", cmd_res)
            _learn_from_command_result(cmd, cmd_res, state)

            # Detect META refresh and update state hints

            recon_agent.send_message(
                curr_topic,
                "Here is what I got from executing the previous executable command (clipped for context).\n" + _clip_for_llm(cmd_res, max_chars=llm_clip_chars),
            )
            attempts += 1
            state["none_streak"] = 0
            continue

        # cmd == None => no executable command proposed.
        state["none_streak"] += 1

        # v7: Never auto-finalize reconnaissance.
        # If the model proposes no command, return control to the operator in guided mode.
        # Only an explicit SUMMARY from the operator should export/finish recon.
        if operator_instruction is not None:
            print("[INFO] No executable command proposed. Use TASK: to request actionable recon, CMD: to run a local command, or SUMMARY to export artifact.")
            recon_agent.save_memory_to_file(curr_topic)
            attempts += 1
            continue

        # Auto-mode fallback: run at most one forced recon step to regain traction, then continue.
        # Otherwise forced recon for one step
        forced = _forced_next_cmd(target_ip, state, last_analysis)
        if forced:
            print("\n==============================")
            print("[Forced Recon]\n", forced)
            print("==============================\n")
            forced_res = recon_agent.run_shell_command(forced)
            print("[Command Execution Result]\n", forced_res)
            _learn_from_command_result(forced, forced_res, state)
            recon_agent.send_message(
                curr_topic,
                "Recon is incomplete. Continue using SAFE read-only recon rules and return valid JSON.\n"
                "Here is what I got from the required recon command.\n" + forced_res,
            )
            attempts += 1
            continue

        # If forced returns None, do NOT auto-finalize. Switch to guided mode and return control to operator.
        print("[INFO] Forced recon has no further safe commands. Switching to guided mode. Use SUMMARY to export artifact.")
        mode = "guided"
        recon_agent.save_memory_to_file(curr_topic)
        attempts += 1
        continue

    # v7: No implicit finalize. Recon artifacts should be exported only via explicit SUMMARY.
    recon_agent.save_memory_to_file(curr_topic)
    print(f"Reconnaissance agent stopped without SUMMARY in {time.time() - start_time:.2f} seconds")
    return

if __name__ == "__main__":
    main()

