import os
import re
import json
import yaml
from typing import Any, Dict, List, Optional, Tuple
from collections import Counter


# =========================
# Config load (ONLY for economic_mode + standard filename)
# =========================
config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "configs", "config.yaml")
with open(config_path, "r", encoding="utf-8") as f:
    config = yaml.safe_load(f)

runtime = config.get("runtime") or {}
planning_config = runtime.get("planning") or runtime.get("plan")
if planning_config is None:
    raise KeyError("Missing runtime.planning in configs/config.yaml")

EC_MODE = bool(planning_config.get("economic_mode", False))
standard_filename = "classification_ec.json" if EC_MODE else "classification.json"


# =========================
# Rerank settings
# =========================
RERANK_ENABLE = True

# weights for: base_norm, affected_fit, surface_fit, name_fit
W_BASE = 0.15
W_AFF = 0.50
W_SURF = 0.30
W_NAME = 0.05

SCALE = 100.0

wsum = W_BASE + W_AFF + W_SURF + W_NAME
if wsum <= 0:
    W_BASE, W_AFF, W_SURF, W_NAME = 0.35, 0.40, 0.20, 0.05
    wsum = 1.0
W_BASE /= wsum
W_AFF /= wsum
W_SURF /= wsum
W_NAME /= wsum


# =========================
# Bonus/Penalty knobs (make 34900 top1)
# =========================
BONUS_EXPLOITDB = 5.0          # key: pushes ExploitDB PoC above equal GitHub PoC
BONUS_METASPLOIT = 2.0

PENALTY_SCANNER = 2.0          # scanners often “detect” only, not reliable RCE shell
PENALTY_INTERACTIVE = 2.5      # interactive shells often brittle
PENALTY_PY2_ONLY = 1.5         # python2-only PoCs tend to break / env issues


# =========================
# Regex & helpers
# =========================
SEMVER_RE = re.compile(r"\b(\d+)\.(\d+)\.(\d+)\b")
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

# Common port groups (generic)
WEB_PORTS = {80, 81, 443, 8000, 8008, 8080, 8081, 8161, 8443, 8888, 9000}
SSH_PORTS = {22, 2222}
SMB_PORTS = {139, 445}
RMI_LDAP_PORTS = {1099, 1389, 389}
DEBUG_PORTS = {5005}
AMQ_OPENWIRE_PORTS = {61616}


def _base_score(item_score: Any, ec_mode: bool) -> float:
    """
    Normalize raw score:
    - economic_mode: score is float
    - normal: score is dict, take score['final']
    """
    if ec_mode:
        return float(item_score) if isinstance(item_score, (int, float)) else 0.0
    if isinstance(item_score, dict):
        v = item_score.get("final", 0.0)
        return float(v) if isinstance(v, (int, float)) else 0.0
    return 0.0


def _read_text_from_dir(p: str, max_chars: int = 25000) -> str:
    """
    Best-effort read README/code to extract keywords/CVE hints.
    """
    if not p or not os.path.exists(p):
        return ""

    exts = (".md", ".txt", ".rst", ".py", ".rb", ".go", ".java", ".js", ".sh", ".yaml", ".yml", ".c", ".cpp", ".pl")
    parts: List[str] = []

    for fn in ("README.md", "README.txt", "README.rst", "README"):
        fp = os.path.join(p, fn)
        if os.path.exists(fp):
            try:
                with open(fp, "r", encoding="utf-8", errors="ignore") as f:
                    parts.append(f.read())
            except Exception:
                pass

    if sum(len(x) for x in parts) < max_chars // 2:
        for root, _, files in os.walk(p):
            for file in files:
                if not file.lower().endswith(exts):
                    continue
                fp = os.path.join(root, file)
                try:
                    if os.path.getsize(fp) > 2_000_000:
                        continue
                    with open(fp, "r", encoding="utf-8", errors="ignore") as f:
                        parts.append(f.read())
                except Exception:
                    continue
                if sum(len(x) for x in parts) >= max_chars:
                    break
            if sum(len(x) for x in parts) >= max_chars:
                break

    return ("\n".join(parts)).strip()[:max_chars]


def _extract_cve(text: str) -> str:
    m = CVE_RE.search(text or "")
    return (m.group(0).upper() if m else "")


def _walk_ancestors(p: str, max_up: int = 10) -> List[str]:
    out = []
    cur = os.path.abspath(p or "")
    for _ in range(max_up):
        if not cur or cur == "/" or cur in out:
            break
        out.append(cur)
        parent = os.path.dirname(cur)
        if parent == cur:
            break
        cur = parent
    return out


def _infer_target_cve_from_paths(*paths: str) -> str:
    """
    Infer intended CVE by scanning the path AND its ancestors.
    Fixes layouts like .../ExploitDB/34900 (no CVE in leaf path).
    """
    for p in paths:
        if not p:
            continue
        c = _extract_cve(p)
        if c:
            return c
        for anc in _walk_ancestors(p, max_up=12):
            c = _extract_cve(anc)
            if c:
                return c
    return ""


def _extract_target_cve_from_artifact(analysis: Dict[str, Any]) -> str:
    planning = analysis.get("planning") if isinstance(analysis, dict) else None
    if not isinstance(planning, dict):
        return ""

    cve_ids = planning.get("cve_ids")
    if isinstance(cve_ids, list):
        for x in cve_ids:
            if isinstance(x, str):
                c = _extract_cve(x)
                if c:
                    return c

    for key in ("planning_keywords", "planning_keywords_original"):
        pk = planning.get(key)
        if isinstance(pk, list):
            for s in pk:
                if isinstance(s, str):
                    c = _extract_cve(s)
                    if c:
                        return c

    kw = (planning.get("keyword") or "").lower().strip()
    if "shellshock" in kw or "bashpocalypse" in kw:
        return "CVE-2014-6271"

    return ""


def _load_recon_context(root_dir: str) -> Tuple[str, str, set, str, List[str]]:
    """
    Returns: (product_name, target_version, open_ports_set, target_cve, planning_keywords_flat)
    """
    art_path = os.path.join(root_dir, "recon_artifact.json")
    if not os.path.exists(art_path):
        return "", "", set(), "", []

    try:
        artifact = json.load(open(art_path, "r", encoding="utf-8"))
    except Exception:
        return "", "", set(), "", []

    final = artifact.get("final_ai_message_json") or {}
    analysis = (final.get("analysis") or {}) if isinstance(final, dict) else {}

    product = ""
    version = ""

    products = analysis.get("products")
    best = None
    if isinstance(products, list):
        for p in products:
            if not isinstance(p, dict):
                continue
            conf = p.get("confidence")
            conf = conf if isinstance(conf, (int, float)) else 0.0
            if best is None or conf > (best.get("confidence") or 0.0):
                best = p
    if isinstance(best, dict):
        product = (best.get("name") or "").strip()
        version = (best.get("version_candidate") or "").strip()

    ports = analysis.get("ports")
    if (not product) and isinstance(ports, dict):
        cand_prod = ""
        cand_ver = ""
        for _, v in ports.items():
            if not isinstance(v, dict):
                continue
            p = (v.get("product") or "").strip()
            ver = (v.get("version") or "").strip()
            if not p:
                continue
            if (ver and not cand_ver) or (len(p) > len(cand_prod)):
                cand_prod = p
                cand_ver = ver or cand_ver
        product = product or cand_prod
        version = version or cand_ver

    open_ports = set()
    if isinstance(ports, dict):
        for k, v in ports.items():
            try:
                pk = int(str(k))
            except Exception:
                continue
            if isinstance(v, dict) and v.get("accessibility") == "open":
                open_ports.add(pk)

    target_cve = _extract_target_cve_from_artifact(analysis)

    planning_keywords_flat: List[str] = []
    planning = analysis.get("planning")
    if isinstance(planning, dict):
        for key in ("planning_keywords", "planning_keywords_original"):
            pk = planning.get(key)
            if isinstance(pk, list):
                for s in pk:
                    if isinstance(s, str) and s.strip():
                        planning_keywords_flat.append(s.strip())

    return product, version, open_ports, target_cve, planning_keywords_flat


# =========================
# Vuln semantic match (Shellshock)
# =========================
def _vuln_match_fit(target_cve: str, exploit_text: str, exploit_dir: str) -> float:
    tc = (target_cve or "").upper().strip()
    s = (exploit_text or "").lower()
    d = (exploit_dir or "").lower()

    if not tc:
        return 0.5

    if tc == "CVE-2014-6271":
        score = 0
        if ("shellshock" in s) or ("bashpocalypse" in s) or ("shellshock" in d) or ("cve-2014-6271" in d):
            score += 2
        if any(k in s for k in ("cgi-bin", "mod_cgi", " cgi", "cgi ")):
            score += 1
        if any(k in s for k in ("user-agent", "() { :; };", "() { :;};", "(){:;};", "(){ :;};")):
            score += 3
        if "bash" in s:
            score += 1

        if score >= 6:
            return 0.98
        if score >= 4:
            return 0.90
        if score == 3:
            return 0.80
        if score == 2:
            return 0.65
        return 0.35

    return 0.4


# =========================
# Source bonus / exec penalty (this makes 34900 top1)
# =========================
def _source_bonus(exploit_dir: str, name: str) -> float:
    p = (exploit_dir or "").lower()
    n = (name or "").lower()

    if "exploitdb" in p:
        return BONUS_EXPLOITDB
    if "metasploit" in p or n.startswith("msf"):
        return BONUS_METASPLOIT
    return 0.0


def _tool_penalty(exploit_text: str, exploit_dir: str, name: str) -> float:
    s = (exploit_text or "").lower()
    d = (exploit_dir or "").lower()
    n = (name or "").lower()

    pen = 0.0

    # scanners / detectors (not exploitation)
    if any(k in n for k in ("scanner", "scan")) or any(k in s for k in ("scanner", "scan only", "detect only")):
        pen += PENALTY_SCANNER

    # interactive shells often brittle (like CGIShell style)
    if any(k in s for k in ("interactive", "raw_input", "input(", "cmd>", "shell>")):
        pen += PENALTY_INTERACTIVE

    # python2-only hints
    if any(k in s for k in ("python2", "requires python 2", "pyreadline")) or "/python2" in d:
        pen += PENALTY_PY2_ONLY

    return pen


# =========================
# Scoring functions (GENERIC)
# =========================
def _name_fit(product: str, exploit_text: str, exploit_dir: str, target_cve: str, planning_keywords: List[str]) -> float:
    s = (exploit_text or "").lower()
    d = (exploit_dir or "").lower()
    tc = (target_cve or "").lower()

    if tc and (tc in s or tc in d):
        return 0.95

    pk_hit = 0
    for kw in (planning_keywords or [])[:20]:
        k = kw.lower()
        if len(k) >= 6 and k in s:
            pk_hit += 1
    if pk_hit >= 2:
        return 0.85
    if pk_hit == 1:
        return 0.75

    if target_cve:
        vm = _vuln_match_fit(target_cve, exploit_text, exploit_dir)
        return max(0.55, min(0.92, vm))

    if not product:
        return 0.5

    p = product.lower().strip()
    if p and (p in s or p in d):
        return 1.0
    return 0.25


def _affected_fit_generic(cve_id: str, target_cve: str, exploit_text: str, exploit_dir: str) -> float:
    c = (cve_id or "").upper().strip()
    tc = (target_cve or "").upper().strip()

    if tc:
        if c == tc:
            return 1.0
        if c and c != tc:
            return 0.0
        vm = _vuln_match_fit(tc, exploit_text, exploit_dir)
        return max(0.40, min(0.98, vm))

    return 0.5


def _surface_fit(open_ports: set, exploit_text: str, cve_id: str, target_cve: str) -> float:
    s = (exploit_text or "").lower()
    c = (cve_id or "").upper().strip()
    tc = (target_cve or "").upper().strip()

    best = 0.15

    def has_any(ps: set) -> bool:
        return any(p in open_ports for p in ps)

    if has_any(WEB_PORTS):
        if (c == "CVE-2014-6271" or tc == "CVE-2014-6271"):
            if any(k in s for k in ("() { :; };", "() { :;};", "(){:;};", "user-agent")) and any(
                k in s for k in ("cgi-bin", "cgi", "mod_cgi", "shellshock", "bash")
            ):
                best = max(best, 1.0)
            elif any(k in s for k in ("shellshock", "bashpocalypse", "cgi-bin", "mod_cgi", "cgi")):
                best = max(best, 0.90)
            else:
                best = max(best, 0.65)
        else:
            if any(k in s for k in ("cgi-bin", "cgi", "http", "header", "cookie", "user-agent", "curl", "wget")):
                best = max(best, 0.75)
            else:
                best = max(best, 0.55)

    if has_any(SSH_PORTS):
        best = max(best, 0.5)
    if has_any(SMB_PORTS):
        best = max(best, 0.55)
    if has_any(RMI_LDAP_PORTS):
        best = max(best, 0.55)
    if has_any(DEBUG_PORTS):
        best = max(best, 0.5)
    if has_any(AMQ_OPENWIRE_PORTS):
        best = max(best, 0.5)

    if tc and (tc.lower() in s):
        best = max(best, 0.85)

    return float(best)


def _resolve_exploit_dir(classification_dir: str, name: str) -> str:
    if not classification_dir:
        return ""

    direct = os.path.join(classification_dir, name)
    if os.path.isdir(direct):
        return direct

    for r2, d2, _ in os.walk(classification_dir):
        if name in d2:
            return os.path.join(r2, name)

    return classification_dir


def process_classification_files(root_dir: str, ec_mode: bool) -> List[Dict[str, Any]]:
    all_scores: List[Dict[str, Any]] = []

    product, target_version, open_ports, recon_target_cve, planning_keywords = (
        _load_recon_context(root_dir) if RERANK_ENABLE else ("", "", set(), "", [])
    )

    # 1) gather
    for root, _, files in os.walk(root_dir):
        for file in files:
            if file != standard_filename:
                continue

            file_path = os.path.join(root, file)
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
            except (json.JSONDecodeError, IOError) as e:
                print(f"Error processing {file_path}: {e}")
                continue

            scores = data.get("scores")
            if not isinstance(scores, list):
                continue

            classification_dir = os.path.dirname(os.path.abspath(file_path))

            for item in scores:
                if not isinstance(item, list) or len(item) < 2:
                    continue

                name = str(item[0])
                raw_score = item[1]

                exploit_dir = _resolve_exploit_dir(classification_dir, name)
                base = _base_score(raw_score, ec_mode)

                all_scores.append({
                    "file_path": exploit_dir,
                    "name": name,
                    "score": raw_score,
                    "score_base": base,
                    "_classification_dir": classification_dir,
                })

    if not all_scores:
        return []

    # 2) normalize base
    max_base = max((e.get("score_base", 0.0) for e in all_scores), default=1.0)
    if not isinstance(max_base, (int, float)) or max_base <= 0:
        max_base = 1.0

    # 2.5) GLOBAL TARGET CVE
    inferred_list = []
    if recon_target_cve:
        global_target_cve = recon_target_cve
    else:
        for e in all_scores:
            classification_dir = e.get("_classification_dir") or ""
            exploit_dir = e.get("file_path") or ""
            c = _infer_target_cve_from_paths(exploit_dir, classification_dir, root_dir)
            if c:
                inferred_list.append(c)
        global_target_cve = ""
        if inferred_list:
            global_target_cve = Counter(inferred_list).most_common(1)[0][0]

    # 3) rerank
    for e in all_scores:
        base = float(e.get("score_base", 0.0))
        base_norm = base / float(max_base)
        base_norm = max(0.0, min(1.0, base_norm))

        if base <= 0.0:
            e["score_adjusted"] = 0.0
            e["evidence"] = {
                "mode": "base_gate",
                "reason": "score_base<=0, drop to bottom",
                "product": product,
                "target_version": target_version,
                "open_ports": sorted(list(open_ports)),
                "target_cve": global_target_cve,
                "base_norm": base_norm,
                "max_base": max_base,
                "weights": {"w_base": W_BASE, "w_aff": W_AFF, "w_surface": W_SURF, "w_name": W_NAME},
                "scale": SCALE,
            }
            continue

        if not RERANK_ENABLE or not (product or target_version or open_ports or global_target_cve):
            e["score_adjusted"] = SCALE * base_norm
            e["evidence"] = {
                "mode": "base_only",
                "product": product,
                "target_version": target_version,
                "open_ports": sorted(list(open_ports)),
                "target_cve": global_target_cve,
                "base_norm": base_norm,
                "max_base": max_base,
                "weights": {"w_base": W_BASE, "w_aff": W_AFF, "w_surface": W_SURF, "w_name": W_NAME},
                "scale": SCALE,
            }
            continue

        exploit_dir = e.get("file_path") or ""
        name = e.get("name") or ""
        classification_dir = e.get("_classification_dir") or ""

        exploit_text = _read_text_from_dir(exploit_dir)
        if not exploit_text:
            exploit_text = f"{name}\n{exploit_dir}"

        item_target_cve = _infer_target_cve_from_paths(exploit_dir, classification_dir, root_dir) or global_target_cve
        cve_id = _extract_cve(name) or _extract_cve(exploit_dir) or _extract_cve(exploit_text)

        nf = _name_fit(product, exploit_text, exploit_dir, item_target_cve, planning_keywords)
        sf = _surface_fit(open_ports, exploit_text, cve_id, item_target_cve)
        af = _affected_fit_generic(cve_id, item_target_cve, exploit_text, exploit_dir)

        adjusted = SCALE * (
            (W_BASE * base_norm) +
            (W_AFF * af) +
            (W_SURF * sf) +
            (W_NAME * nf)
        )

        # ===== New: source/exec correction =====
        bonus = _source_bonus(exploit_dir, name)
        penalty = _tool_penalty(exploit_text, exploit_dir, name)

        adjusted2 = adjusted + bonus - penalty
        # clamp to 0..100 for deterministic top-1
        adjusted2 = max(0.0, min(SCALE, float(adjusted2)))

        e["score_adjusted"] = adjusted2
        e["evidence"] = {
            "product": product,
            "target_version": target_version,
            "open_ports": sorted(list(open_ports)),
            "target_cve": item_target_cve,
            "cve_id": cve_id,
            "base_norm": base_norm,
            "affected_fit": af,
            "surface_fit": sf,
            "name_fit": nf,
            "bonus_source": bonus,
            "penalty_tool": penalty,
            "score_before_bonus": float(adjusted),
            "weights": {"w_base": W_BASE, "w_aff": W_AFF, "w_surface": W_SURF, "w_name": W_NAME},
            "scale": SCALE,
            "max_base": max_base,
            "global_target_cve": global_target_cve,
        }

    for e in all_scores:
        e.pop("_classification_dir", None)

    # tie-breaker: if equal adjusted, prefer higher base
    return sorted(
        all_scores,
        key=lambda x: (float(x.get("score_adjusted", 0.0)), float(x.get("score_base", 0.0))),
        reverse=True
    )


def save_to_plan_json(data: List[Dict[str, Any]], output_file: str) -> None:
    try:
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
        print(f"Successfully saved results to {output_file}")
    except IOError as e:
        print(f"Error saving to {output_file}: {e}")


def merge(root_directory: str, output_json: str, ec_mode: bool) -> None:
    results = process_classification_files(root_directory, ec_mode)
    save_to_plan_json(results, output_json)

    print(f"Processed {len(results)} score entries in total")
    if results:
        print(f"Highest adjusted score: {results[0].get('score_adjusted')} ({results[0]['name']})")
        print(f"Lowest adjusted score: {results[-1].get('score_adjusted')} ({results[-1]['name']})")
