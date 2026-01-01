"""Lightweight OSINT helpers for ReconAgent.

This module is intended for reconnaissance enrichment, not exploitation.

Design goals:
- Minimal dependencies (stdlib only; `requests` is optional).
- Bounded output suitable for feeding into an LLM loop.
- Prefer local sources first (Exploit-DB via `searchsploit`).
- Keep Google CSE optional.

These helpers never execute exploit payloads. They only surface candidate
information such as exploit titles and referenced CVE IDs.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple


_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")


@dataclass
class SearchsploitHit:
    title: str
    path: str
    cves: List[str]


@dataclass
class OsintBundle:
    keyword: str
    searchsploit_hits: List[SearchsploitHit]
    extracted_cves: List[str]
    google_hits: List[Dict[str, str]]
    errors: List[str]


def _run(cmd: List[str], timeout_sec: int = 30) -> Tuple[int, str, str]:
    """Run a command and return (rc, stdout, stderr)."""
    try:
        p = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout_sec,
            check=False,
        )
        return p.returncode, p.stdout or "", p.stderr or ""
    except FileNotFoundError:
        return 127, "", f"command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return 124, "", f"timeout after {timeout_sec}s"


def _extract_cves(text: str) -> List[str]:
    if not text:
        return []
    return sorted({m.group(0) for m in _CVE_RE.finditer(text)})


def searchsploit_titles(keyword: str, limit: int = 20, timeout_sec: int = 30) -> Tuple[List[SearchsploitHit], List[str]]:
    """Query local Exploit-DB via searchsploit.

    Tries JSON mode first (searchsploit -j), then falls back to parsing the
    table output.

    Returns (hits, errors).
    """
    keyword = (keyword or "").strip()
    if not keyword:
        return [], ["empty keyword"]

    errors: List[str] = []

    # 1) JSON mode (preferred)
    rc, out, err = _run(["searchsploit", "-j", "-t", keyword], timeout_sec=timeout_sec)
    if rc == 0 and out.strip().startswith("{"):
        try:
            obj = json.loads(out)
            results = obj.get("RESULTS_EXPLOIT") or []
            hits: List[SearchsploitHit] = []
            for r in results[: max(0, limit)]:
                title = str(r.get("Title") or "").strip()
                path = str(r.get("Path") or "").strip()
                cves = _extract_cves(title + " " + path)
                hits.append(SearchsploitHit(title=title, path=path, cves=cves))
            return hits, []
        except Exception as e:
            errors.append(f"failed to parse searchsploit -j output: {e}")
    else:
        if err.strip():
            errors.append(err.strip())

    # 2) Fallback: parse table output
    rc2, out2, err2 = _run(["searchsploit", "-t", keyword], timeout_sec=timeout_sec)
    if rc2 != 0:
        errors.append(err2.strip() or f"searchsploit returned rc={rc2}")
        return [], errors

    hits: List[SearchsploitHit] = []
    lines = [ln.rstrip("\n") for ln in out2.splitlines()]
    for ln in lines:
        if "|" not in ln:
            continue
        if ln.strip().startswith("Exploit Title") or ln.strip().startswith("---"):
            continue
        parts = [p.strip() for p in ln.split("|")]
        if len(parts) != 2:
            continue
        title, path = parts
        if not title or not path:
            continue
        cves = _extract_cves(title + " " + path)
        hits.append(SearchsploitHit(title=title, path=path, cves=cves))
        if len(hits) >= limit:
            break

    return hits, errors


def google_cse_search(
    keyword: str,
    api_key: Optional[str] = None,
    cx: Optional[str] = None,
    num: int = 5,
    timeout_sec: int = 15,
) -> Tuple[List[Dict[str, str]], List[str]]:
    """Optional Google Custom Search.

    Requires env vars or explicit parameters:
    - GOOGLE_CSE_API_KEY
    - GOOGLE_CSE_ID (aka cx)

    Returns list of {title, link, snippet}.
    """
    api_key = api_key or os.getenv("GOOGLE_CSE_API_KEY") or os.getenv("GOOGLE_API_KEY")
    cx = cx or os.getenv("GOOGLE_CSE_ID") or os.getenv("GOOGLE_CSE_CX")

    if not api_key or not cx:
        return [], ["google cse not configured (missing GOOGLE_CSE_API_KEY/GOOGLE_CSE_ID)"]

    try:
        import requests  # optional dependency

        url = "https://www.googleapis.com/customsearch/v1"
        params = {"key": api_key, "cx": cx, "q": keyword, "num": max(1, min(int(num), 10))}
        r = requests.get(url, params=params, timeout=timeout_sec)
        if r.status_code != 200:
            return [], [f"google cse http {r.status_code}: {r.text[:200]}"]
        data = r.json()
        items = data.get("items") or []
        hits: List[Dict[str, str]] = []
        for it in items:
            hits.append(
                {
                    "title": str(it.get("title") or "")[:200],
                    "link": str(it.get("link") or "")[:500],
                    "snippet": str(it.get("snippet") or "")[:500],
                }
            )
        return hits, []
    except Exception as e:
        return [], [f"google cse failed: {e}"]


def osint_bundle(keyword: str, cfg: "OSINTConfig | None" = None) -> "OsintBundle":
    """Wrapper kept for historical naming."""
    if cfg is not None and not getattr(cfg, "enable", True):
        return OsintBundle(keyword=keyword, searchsploit=[], google=[], exploitdb=[], github=[], avd=[])

    if cfg is None:
        return build_osint_bundle(keyword=keyword)

    return build_osint_bundle(
        keyword=keyword,
        enable_google=cfg.enable_google,
        searchsploit_limit=cfg.searchsploit_limit,
        google_num=cfg.google_num,
    )



def format_osint_for_llm(bundle: OsintBundle, max_chars: int = 6000) -> str:
    """Format an OsintBundle into a compact, LLM-friendly message."""

    lines: List[str] = []
    lines.append(f"[OSINT] keyword: {bundle.keyword}")

    if bundle.errors:
        lines.append("[OSINT] errors:")
        for e in bundle.errors[:10]:
            lines.append(f"- {e}")

    if bundle.extracted_cves:
        lines.append("[OSINT] CVE IDs observed in local Exploit-DB titles/paths:")
        lines.append(", ".join(bundle.extracted_cves[:50]))

    if bundle.searchsploit_hits:
        lines.append("[OSINT] Top searchsploit hits (title | path):")
        for h in bundle.searchsploit_hits[:15]:
            cves = f" [{', '.join(h.cves)}]" if h.cves else ""
            lines.append(f"- {h.title} | {h.path}{cves}")

    if bundle.google_hits:
        lines.append("[OSINT] Top Google CSE hits:")
        for it in bundle.google_hits[:5]:
            lines.append(f"- {it.get('title','').strip()} | {it.get('link','').strip()}")
            sn = it.get("snippet", "").strip()
            if sn:
                lines.append(f"  snippet: {sn}")

    text = "\n".join(lines)
    if len(text) > max_chars:
        return text[: max_chars - 40] + "\n...[truncated]"
    return text


# ----------------------------
# Backward-compatible exports (ReconAgent expects these names)
# ----------------------------

class OSINTConfig:
    """
    Backward-compatible config holder.

    ReconAgent may call OSINTConfig(enable=..., enable_google=..., searchsploit_limit=..., google_num=...)
    So we accept these names and safely ignore any unknown kwargs.
    """

    def __init__(
        self,
        enable: bool = True,                # <-- NEW: accept enable=
        enable_google: bool = False,
        searchsploit_limit: int = 25,
        google_num: int = 5,
        **kwargs,
    ) -> None:
        self.enable = bool(enable)
        self.enable_google = bool(enable_google)
        self.searchsploit_limit = int(searchsploit_limit)
        self.google_num = int(google_num)
        # swallow anything else recon_agent passes
        self.extra = dict(kwargs)

def format_osint_bundle(bundle) -> str:
    """
    Backward-compatible alias.
    ReconAgent expects format_osint_bundle(bundle) but this module currently exposes format_osint_for_llm().
    """
    return format_osint_for_llm(bundle)
