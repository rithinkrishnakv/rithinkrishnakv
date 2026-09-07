#!/usr/bin/env python3
"""
generate_cyberdaily.py — tiny daily cybersecurity brief for the profile README.

Sources (all free, official, no API key required):
  - CVEs      : CISA Known Exploited Vulnerabilities catalog (JSON, public domain)
                https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
  - Threat    : CISA Cybersecurity Advisories (RSS)
                https://www.cisa.gov/cybersecurity-advisories/all.xml
  - Research  : arXiv cs.CR — Cryptography & Security (RSS, Cornell University)
                https://rss.arxiv.org/rss/cs.CR
  - Tool      : GitHub REST search API (public repos, topic:security-tools)
                https://api.github.com/search/repositories

No LLM is used anywhere in this pipeline — items are picked by straightforward
rules (most recent / highest-starred) and displayed close to verbatim, always
linked back to the original source. Nothing here is summarized or rewritten
by a model, so there is nothing to hallucinate.

Design choices, on purpose (mirrors generate_stats.py):
- Standard library only: urllib + xml.etree + json. No pip installs.
- Every fetch is independently try/except'd. If one source is down, that row
  is simply omitted from the brief instead of failing the whole run — a
  partial, honest brief beats a red workflow or a fabricated placeholder.
- Nothing is invented. If a source returns nothing usable, we show nothing
  for that category rather than making something up.

Usage:
  python3 scripts/generate_cyberdaily.py --svg dist/cyberdaily.svg --archive archive/cyberdaily.jsonl
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CISA_ADVISORIES_RSS = "https://www.cisa.gov/cybersecurity-advisories/all.xml"
ARXIV_CS_CR_RSS = "https://rss.arxiv.org/rss/cs.CR"
GITHUB_SEARCH_API = "https://api.github.com/search/repositories"

MAX_CVES = 2  # within the requested 1-3, kept small to stay compact
ARCHIVE_MAX_LINES = 365  # ~1 year of daily entries, then oldest roll off

UA = {"User-Agent": "rithinkrishnakv-cyberdaily-bot/1.0"}


def http_get(url: str, headers: dict | None = None, timeout: int = 20) -> bytes:
    req = urllib.request.Request(url, headers={**UA, **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def truncate(text: str, limit: int) -> str:
    text = " ".join(text.split())  # collapse whitespace/newlines
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "\u2026"


# ---------------------------------------------------------------- CVEs (KEV)
def fetch_cves() -> list[dict]:
    try:
        data = json.loads(http_get(KEV_URL))
        vulns = data.get("vulnerabilities", [])
        vulns.sort(key=lambda v: v.get("dateAdded", ""), reverse=True)
        out = []
        for v in vulns[:MAX_CVES]:
            cve_id = v.get("cveID", "").strip()
            if not cve_id:
                continue
            name = v.get("vulnerabilityName") or v.get("shortDescription", "")
            out.append(
                {
                    "id": cve_id,
                    "label": truncate(f"{cve_id} \u2014 {name}", 78),
                    "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                }
            )
        return out
    except Exception as exc:  # noqa: BLE001 - a bad source should degrade, not crash
        print(f"warn: KEV fetch failed: {exc}", file=sys.stderr)
        return []


# --------------------------------------------------------- Threat (CISA RSS)
def parse_rss_items(xml_bytes: bytes) -> list[dict]:
    root = ET.fromstring(xml_bytes)
    items = []
    for item in root.iter("item"):
        title_el = item.find("title")
        link_el = item.find("link")
        title = (title_el.text or "").strip() if title_el is not None else ""
        link = (link_el.text or "").strip() if link_el is not None else ""
        if title and link:
            items.append({"title": title, "link": link})
    return items


def fetch_threat() -> dict | None:
    try:
        items = parse_rss_items(http_get(CISA_ADVISORIES_RSS))
        if not items:
            return None
        top = items[0]
        return {"label": truncate(top["title"], 78), "url": top["link"]}
    except Exception as exc:  # noqa: BLE001
        print(f"warn: CISA advisories fetch failed: {exc}", file=sys.stderr)
        return None


# ------------------------------------------------------- Research (arXiv RSS)
_ARXIV_SUFFIX_RE = re.compile(r"\s*\(arXiv:\S+(?:\s*\[[^\]]+\])?\)\s*$")


def fetch_research() -> dict | None:
    try:
        items = parse_rss_items(http_get(ARXIV_CS_CR_RSS))
        if not items:
            return None
        top = items[0]
        title = _ARXIV_SUFFIX_RE.sub("", top["title"]).strip()
        return {"label": truncate(title, 78), "url": top["link"]}
    except Exception as exc:  # noqa: BLE001
        print(f"warn: arXiv fetch failed: {exc}", file=sys.stderr)
        return None


# --------------------------------------------------------- Tool (GitHub API)
def fetch_tool(token: str | None) -> dict | None:
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    today = datetime.date.today()
    fallback_queries = [
        f"topic:security-tools created:>{today - datetime.timedelta(days=30)}",
        f"topic:pentesting created:>{today - datetime.timedelta(days=30)}",
        "topic:security-tools",
    ]
    for q in fallback_queries:
        try:
            url = f"{GITHUB_SEARCH_API}?q={urllib.parse.quote(q)}&sort=stars&order=desc&per_page=1"
            payload = json.loads(http_get(url, headers=headers))
            repos = payload.get("items", [])
            if repos:
                repo = repos[0]
                desc = repo.get("description") or ""
                label = repo["full_name"] + (f" \u2014 {desc}" if desc else "")
                return {"label": truncate(label, 78), "url": repo["html_url"]}
        except Exception as exc:  # noqa: BLE001
            print(f"warn: GitHub search failed for '{q}': {exc}", file=sys.stderr)
            continue
    return None


# --------------------------------------------------------------------- SVG
def esc(s: str) -> str:
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def render_svg(date_str: str, rows: list[tuple[str, str, dict]]) -> str:
    """rows: list of (emoji, category_label, item_dict-or-None)"""
    visible = [(e, c, item) for e, c, item in rows if item]
    row_h = 30
    top = 74
    height = top + len(visible) * row_h + 24
    height = max(height, 140)

    row_svg = []
    for i, (emoji, cat, item) in enumerate(visible):
        y = top + i * row_h
        delay = 0.15 * i
        row_svg.append(
            f'<g opacity="0" style="animation:rowIn .5s ease {delay:.2f}s forwards">'
            f'<a xlink:href="{esc(item["url"])}" target="_blank">'
            f'<text x="40" y="{y}" font-size="14">{emoji}</text>'
            f'<text x="66" y="{y-1}" font-size="9.5" letter-spacing="1.2" fill="#5b6b84">{esc(cat)}</text>'
            f'<text x="66" y="{y+14}" font-size="12" fill="#dbe7f2">{esc(item["label"])}</text>'
            f"</a></g>"
        )

    return f"""<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 700 {height}" width="700" height="{height}" role="img" aria-label="Daily cybersecurity brief">
<defs>
<style type="text/css"><![CDATA[
text{{font-family:'SFMono-Regular',Consolas,'Liberation Mono',Menlo,monospace}}
@keyframes rowIn{{from{{opacity:0;transform:translateX(-4px)}}to{{opacity:1;transform:translateX(0)}}}}
@keyframes blink{{0%,49%{{opacity:1}}50%,100%{{opacity:0}}}}
.cursor{{animation:blink 1s step-start infinite}}
]]></style>
<linearGradient id="bg" x1="0" y1="0" x2="1" y2="1">
<stop offset="0%" stop-color="#0d1420"/><stop offset="100%" stop-color="#080c14"/>
</linearGradient>
<linearGradient id="border" x1="0" y1="0" x2="1" y2="1">
<stop offset="0%" stop-color="#00d9ff"><animate attributeName="stop-color" values="#00d9ff;#a78bfa;#00d9ff" dur="10s" repeatCount="indefinite"/></stop>
<stop offset="100%" stop-color="#a78bfa"><animate attributeName="stop-color" values="#a78bfa;#00d9ff;#a78bfa" dur="10s" repeatCount="indefinite"/></stop>
</linearGradient>
</defs>

<rect width="700" height="{height}" rx="16" fill="url(#bg)"/>
<rect width="700" height="{height}" rx="16" fill="none" stroke="url(#border)" stroke-width="1.6"/>

<circle cx="30" cy="24" r="3" fill="#3d5872"/>
<circle cx="42" cy="24" r="3" fill="#516781"/>
<circle cx="54" cy="24" r="3" fill="#7dd3fc"/>
<text x="70" y="28" font-size="10.5" fill="#3d5872" letter-spacing="1">rimu@kali: ~/cyber_daily.sh</text>
<path d="M20 38 H680" stroke="#173350" stroke-width="1"/>

<text x="40" y="58" font-size="12.5" fill="#00d9ff" font-weight="700">CYBER // DAILY</text>
<text x="660" y="58" text-anchor="end" font-size="11" fill="#5b6b84">\U0001F4C5 {esc(date_str)}</text>
<rect x="46" y="49" width="8" height="14" fill="#00d9ff" class="cursor" opacity=".85"/>

{''.join(row_svg)}

<text x="660" y="{height-14}" font-size="8.5" fill="#2c3d54" text-anchor="end">sources linked \u2022 auto-updated daily</text>
</svg>
"""


# ------------------------------------------------------------------ Archive
def update_archive(path: str, record: dict) -> None:
    lines: list[str] = []
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as fh:
            lines = [ln.rstrip("\n") for ln in fh if ln.strip()]
    lines.append(json.dumps(record, ensure_ascii=False, separators=(",", ":")))
    lines = lines[-ARCHIVE_MAX_LINES:]
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


# ---------------------------------------------------------------------- main
def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--svg", default="dist/cyberdaily.svg")
    parser.add_argument("--archive", default="archive/cyberdaily.jsonl")
    args = parser.parse_args()

    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")

    cves = fetch_cves()
    threat = fetch_threat()
    research = fetch_research()
    tool = fetch_tool(token)

    date_str = datetime.date.today().isoformat()

    rows = []
    for i, cve in enumerate(cves):
        cat = "CVE" if len(cves) == 1 else f"CVE {i+1}"
        rows.append(("\U0001F534", cat, cve))
    rows.append(("\U0001F6E1\uFE0F", "THREAT", threat))
    rows.append(("\U0001F52C", "RESEARCH", research))
    rows.append(("\U0001F9F0", "TOOL", tool))

    svg = render_svg(date_str, rows)
    os.makedirs(os.path.dirname(args.svg) or ".", exist_ok=True)
    with open(args.svg, "w", encoding="utf-8") as fh:
        fh.write(svg)

    record = {
        "date": date_str,
        "cves": cves,
        "threat": threat,
        "research": research,
        "tool": tool,
    }
    update_archive(args.archive, record)

    found = sum(1 for _, _, item in rows if item)
    print(f"wrote {args.svg} and updated {args.archive} — {found}/{len(rows)} rows populated")


if __name__ == "__main__":
    main()
