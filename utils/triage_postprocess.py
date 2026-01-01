# utils/triage_postprocess.py
from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

# Simple signals for misconfig/exposure in recon notes
ISSUE_RULES: List[Tuple[re.Pattern, str, str]] = [
    (re.compile(r"\banonymous\b.*\bftp\b|\bftp\b.*\banonymous\b", re.IGNORECASE), "MISCONFIG-FTP-ANON", "misconfig"),
    (re.compile(r"\bguest\b.*\bsmb\b|\bnull session\b", re.IGNORECASE), "MISCONFIG-SMB-NULL", "misconfig"),
    (re.compile(r"\bdistccd\b", re.IGNORECASE), "EXPOSURE-DISTCCD", "exposure"),
    (re.compile(r"\bvsftpd\b.*\b2\.3\.4\b", re.IGNORECASE), "CANDIDATE-VSFTPD-234", "exposure"),
]

def _cap01(x: float) -> float:
    if x < 0.0: return 0.0
    if x > 1.0: return 1.0
    return x

def _product_conf(product: str, version: str, evidence: str) -> float:
    conf = 0.0
    if product: conf += 0.55
    if version: conf += 0.20
    if evidence: conf += 0.15
    return _cap01(conf)

def _candidate_conf(keyword: str, product: str, version: str, evidence: str) -> float:
    kw = (keyword or "").strip()
    ev = (evidence or "").strip().lower()
    conf = 0.45
    if CVE_RE.search(kw):
        conf += 0.10
    if product and product.lower() in ev:
        conf += 0.15
    if version and version.lower() in ev:
        conf += 0.15
    return _cap01(conf)

def derive_triage(final_json: Dict[str, Any], top_k: int = 10) -> Dict[str, Any]:
    """
    Ensure analysis.triage exists and is populated with:
      - products: high-confidence product/version observations
      - cve_candidates: de-duplicated & ranked candidates from per-port candidates
      - issues: simple misconfig/exposure candidates inferred from notes/evidence
    Does NOT claim exploitation or confirmation.
    """
    if not isinstance(final_json, dict):
        return final_json

    analysis = final_json.get("analysis")
    if not isinstance(analysis, dict):
        return final_json

    ports = analysis.get("ports") or {}
    if not isinstance(ports, dict):
        ports = {}

    triage = analysis.get("triage")
    if not isinstance(triage, dict):
        triage = {"products": [], "cve_candidates": [], "issues": []}
        analysis["triage"] = triage

    products_out: List[Dict[str, Any]] = []
    cands_out: List[Dict[str, Any]] = []
    issues_out: List[Dict[str, Any]] = []

    # Collect from ports
    for port, pinfo in ports.items():
        if not isinstance(pinfo, dict):
            continue
        service = (pinfo.get("service") or "").strip()
        product = (pinfo.get("product") or "").strip()
        version = (pinfo.get("version") or "").strip()
        evidence = (pinfo.get("banner_evidence") or "").strip()
        notes = (pinfo.get("notes") or "").strip()

        # Product candidates
        if product:
            products_out.append({
                "name": product,
                "version_candidate": version,
                "evidence": evidence or notes,
                "confidence": float(_product_conf(product, version, evidence or notes)),
                "service": service,
                "port": str(port),
            })

        # CVE candidates (per-port)
        for cand in (pinfo.get("cve_candidates") or []):
            if not isinstance(cand, dict):
                continue
            kw = (cand.get("keyword") or cand.get("id_or_keyword") or "").strip()
            if not kw:
                continue
            cands_out.append({
                "id_or_keyword": kw,
                "service": service,
                "port": str(port),
                "reason": (cand.get("reason") or "").strip(),
                "evidence": (cand.get("evidence") or evidence or "").strip(),
                "confidence": float(_candidate_conf(kw, product, version, cand.get("evidence") or evidence or "")),
            })

        # Confirmed CVEs (if any)
        for cve in (pinfo.get("cves") or []):
            if isinstance(cve, str):
                cid = cve.strip()
                if not cid:
                    continue
                cands_out.append({
                    "id_or_keyword": cid,
                    "service": service,
                    "port": str(port),
                    "reason": "High-confidence CVE listed in per-port cves[]",
                    "evidence": evidence,
                    "confidence": 0.85,
                })
            elif isinstance(cve, dict):
                cid = (cve.get("cve_id") or cve.get("id") or cve.get("cve") or "").strip()
                if not cid:
                    continue
                cands_out.append({
                    "id_or_keyword": cid,
                    "service": service,
                    "port": str(port),
                    "reason": (cve.get("rationale") or cve.get("reason") or "High-confidence CVE listed in per-port cves[]").strip(),
                    "evidence": (cve.get("evidence") or evidence or "").strip(),
                    "confidence": float(cve.get("confidence") or 0.85),
                })

        # Issues (light inference)
        note_blob = " ".join([notes, evidence]).strip()
        if note_blob:
            for pat, issue_id, issue_type in ISSUE_RULES:
                if pat.search(note_blob):
                    issues_out.append({
                        "id": issue_id,
                        "type": issue_type,
                        "service": service,
                        "port": str(port),
                        "description": notes or f"Signal matched: {issue_id}",
                        "evidence": evidence or notes,
                        "confidence": 0.75 if issue_type != "misconfig" else 0.80,
                    })

    # De-duplicate products by (name, version, port)
    seen_p = set()
    prod_dedup = []
    for p in sorted(products_out, key=lambda x: float(x.get("confidence") or 0.0), reverse=True):
        key = (p.get("name"), p.get("version_candidate"), p.get("port"))
        if key in seen_p:
            continue
        seen_p.add(key)
        prod_dedup.append(p)

    # De-duplicate candidates by (id_or_keyword, port)
    seen_c = set()
    cand_dedup = []
    for c in sorted(cands_out, key=lambda x: float(x.get("confidence") or 0.0), reverse=True):
        key = ((c.get("id_or_keyword") or "").upper(), c.get("port"))
        if key in seen_c:
            continue
        seen_c.add(key)
        cand_dedup.append(c)

    # De-duplicate issues by (id, port)
    seen_i = set()
    issue_dedup = []
    for it in issues_out:
        key = (it.get("id"), it.get("port"))
        if key in seen_i:
            continue
        seen_i.add(key)
        issue_dedup.append(it)

    triage["products"] = prod_dedup[:max(5, min(15, len(prod_dedup)))]
    triage["cve_candidates"] = cand_dedup[:top_k]
    triage["issues"] = issue_dedup[:max(10, len(issue_dedup))]

    # Write back
    final_json["analysis"] = analysis
    return final_json
