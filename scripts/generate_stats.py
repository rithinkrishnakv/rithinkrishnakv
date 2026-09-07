#!/usr/bin/env python3
"""
generate_stats.py — self-hosted replacement for third-party GitHub stats cards.

Why this exists
----------------
The old README embedded a third-party Vercel deployment
(github-stats-extended.vercel.app) to render contribution/language stats.
That project's own docs describe the public instance as "best-effort and can
be unreliable due to rate limits and traffic spikes." This script removes
that dependency: it pulls real numbers straight from the GitHub GraphQL API
and renders an SVG in the same visual language as the rest of this profile,
committed to the repo's `output` branch by a GitHub Action on a schedule.

Design choices, on purpose:
- Standard library only (json, urllib). No pip install step, nothing that
  can break because a third-party package changed or was yanked.
- One GraphQL request gets contributions + streaks + language bytes, so the
  script stays cheap to run and easy to re-run by hand.
- Fails loudly (non-zero exit) with a clear message on any error, so a bad
  run shows up as a red X in Actions instead of silently publishing garbage.

Requires:
  STATS_TOKEN     — classic PAT with the `read:user` scope (see README's
                    "Manual setup" section for how to create + add it).
  STATS_USERNAME  — GitHub username to report on (defaults to rithinkrishnakv).

Usage:
  python3 scripts/generate_stats.py [output_path]   # default: dist/stats.svg
"""

from __future__ import annotations

import datetime
import json
import os
import sys
import urllib.error
import urllib.request

API_URL = "https://api.github.com/graphql"

QUERY = """
query($login: String!) {
  user(login: $login) {
    contributionsCollection {
      contributionCalendar {
        totalContributions
        weeks {
          contributionDays {
            date
            contributionCount
          }
        }
      }
    }
    repositories(first: 100, ownerAffiliations: OWNER, isFork: false, privacy: PUBLIC) {
      totalCount
      nodes {
        languages(first: 8, orderBy: {field: SIZE, direction: DESC}) {
          edges {
            size
            node { name color }
          }
        }
      }
    }
  }
}
"""


def fetch(username: str, token: str) -> dict:
    body = json.dumps({"query": QUERY, "variables": {"login": username}}).encode("utf-8")
    req = urllib.request.Request(
        API_URL,
        data=body,
        method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/vnd.github+json",
            "User-Agent": f"{username}-profile-stats-generator",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise RuntimeError(
            f"GitHub API returned HTTP {exc.code}: {exc.read().decode('utf-8', 'ignore')}"
        ) from exc

    if payload.get("errors"):
        raise RuntimeError(f"GitHub GraphQL API returned errors: {payload['errors']}")

    user = payload.get("data", {}).get("user")
    if user is None:
        raise RuntimeError(f"No user data returned for '{username}' — check the username/token.")
    return user


def compute_streaks(days: list[dict]) -> tuple[int, int]:
    """Return (current_streak, longest_streak) in days, from oldest->newest days."""
    longest = run = 0
    for day in days:
        if day["contributionCount"] > 0:
            run += 1
            longest = max(longest, run)
        else:
            run = 0

    today = datetime.date.today()
    current = 0
    for day in reversed(days):
        if day["contributionCount"] > 0:
            current += 1
            continue
        # Today not having a contribution yet doesn't break the streak —
        # the day isn't over. Any other zero-day ends it.
        if datetime.date.fromisoformat(day["date"]) == today:
            continue
        break

    return current, longest


def top_languages(repo_nodes: list[dict], limit: int = 4) -> list[dict]:
    totals: dict[str, int] = {}
    colors: dict[str, str] = {}
    for repo in repo_nodes:
        for edge in repo["languages"]["edges"]:
            name = edge["node"]["name"]
            totals[name] = totals.get(name, 0) + edge["size"]
            colors[name] = edge["node"]["color"] or "#8b98a5"

    total_bytes = sum(totals.values()) or 1
    ranked = sorted(totals.items(), key=lambda kv: kv[1], reverse=True)[:limit]
    return [
        {"name": name, "pct": (size / total_bytes) * 100.0, "color": colors[name]}
        for name, size in ranked
    ]


def esc(text: str) -> str:
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def render_svg(
    *,
    total_contributions: int,
    current_streak: int,
    longest_streak: int,
    languages: list[dict],
    repo_count: int,
    generated_at: str,
) -> str:
    bar_x, bar_w = 40.0, 620.0
    segments = []
    cursor = bar_x
    for lang in languages:
        seg_w = round(bar_w * (lang["pct"] / 100.0), 2)
        segments.append((cursor, seg_w, lang["color"]))
        cursor += seg_w

    seg_rects = "".join(
        f'<rect x="{x:.2f}" y="168" width="{w:.2f}" height="10" fill="{color}"/>'
        for x, w, color in segments
    )

    # Up to 4 language rows laid out 2x2, matching the original hand-authored card.
    row_positions = [(45, 202), (355, 202), (45, 226), (355, 226)]
    lang_rows = ""
    for (cx, ty), lang in zip(row_positions, languages):
        lang_rows += (
            f'<circle cx="{cx}" cy="{ty - 4}" r="4.5" fill="{lang["color"]}"/>'
            f'<text x="{cx + 11}" y="{ty}" font-size="12.5" fill="#dbe7f2">{esc(lang["name"])}</text>'
            f'<text x="{cx + 291}" y="{ty}" font-size="12.5" fill="#5b6b84" text-anchor="end">'
            f'{lang["pct"]:.1f}%</text>'
        )

    lang_label = f"TOP LANGUAGES &#8226; {repo_count} PUBLIC REPOS"

    return f"""<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 700 270" width="700" height="270" role="img" aria-label="Rithin Krishna's live GitHub statistics">
<defs>
<style type="text/css"><![CDATA[
text{{font-family:'SFMono-Regular',Consolas,'Liberation Mono',Menlo,monospace}}
@keyframes popIn{{from{{opacity:0;transform:translateY(6px)}}to{{opacity:1;transform:translateY(0)}}}}
@keyframes fadeIn{{from{{opacity:0}}to{{opacity:1}}}}
.pop{{opacity:0;animation:popIn .6s cubic-bezier(.2,.8,.3,1) forwards}}
.fade{{opacity:0;animation:fadeIn .5s ease forwards}}
]]></style>
<linearGradient id="bg" x1="0" y1="0" x2="1" y2="1">
<stop offset="0%" stop-color="#0d1420"/><stop offset="100%" stop-color="#080c14"/>
</linearGradient>
<linearGradient id="border" x1="0" y1="0" x2="1" y2="1">
<stop offset="0%" stop-color="#00d9ff"><animate attributeName="stop-color" values="#00d9ff;#a78bfa;#00d9ff" dur="10s" repeatCount="indefinite"/></stop>
<stop offset="100%" stop-color="#a78bfa"><animate attributeName="stop-color" values="#a78bfa;#00d9ff;#a78bfa" dur="10s" repeatCount="indefinite"/></stop>
</linearGradient>
</defs>

<rect width="700" height="270" rx="16" fill="url(#bg)"/>
<rect width="700" height="270" rx="16" fill="none" stroke="url(#border)" stroke-width="1.6"/>

<circle cx="30" cy="24" r="3" fill="#3d5872"/>
<circle cx="42" cy="24" r="3" fill="#516781"/>
<circle cx="54" cy="24" r="3" fill="#7dd3fc"/>
<text x="70" y="28" font-size="10.5" fill="#3d5872" letter-spacing="1">rimu@kali: ~/git-log --stat --live</text>
<path d="M20 38 H680" stroke="#173350" stroke-width="1"/>

<g class="pop" style="animation-delay:.10s">
<text x="117" y="86" text-anchor="middle" font-size="34" font-weight="700" fill="#00d9ff">{total_contributions}</text>
<text x="117" y="108" text-anchor="middle" font-size="12" fill="#c3d3e2" letter-spacing=".3">Total Contributions</text>
<text x="117" y="126" text-anchor="middle" font-size="9.5" fill="#4a5b73">past 12 months</text>
</g>
<g class="pop" style="animation-delay:.28s">
<text x="350" y="86" text-anchor="middle" font-size="34" font-weight="700" fill="#a78bfa">{current_streak}</text>
<text x="350" y="108" text-anchor="middle" font-size="12" fill="#c3d3e2" letter-spacing=".3">Current Streak</text>
<text x="350" y="126" text-anchor="middle" font-size="9.5" fill="#4a5b73">day{"s" if current_streak != 1 else ""}</text>
</g>
<line x1="233" y1="46" x2="233" y2="126" stroke="#1b2f47" stroke-width="1"/>
<g class="pop" style="animation-delay:.46s">
<text x="583" y="86" text-anchor="middle" font-size="34" font-weight="700" fill="#00d9ff">{longest_streak}</text>
<text x="583" y="108" text-anchor="middle" font-size="12" fill="#c3d3e2" letter-spacing=".3">Longest Streak</text>
<text x="583" y="126" text-anchor="middle" font-size="9.5" fill="#4a5b73">day{"s" if longest_streak != 1 else ""}</text>
</g>
<line x1="467" y1="46" x2="467" y2="126" stroke="#1b2f47" stroke-width="1"/>

<path d="M40 146 H660" stroke="#173350" stroke-width="1"/>
<text x="40" y="154" font-size="11" letter-spacing="1.5" fill="#5b6b84">{lang_label}</text>
<rect x="40" y="168" width="620" height="10" rx="5" fill="#16273a"/>
{seg_rects}

{lang_rows}

<text x="660" y="262" font-size="8.5" fill="#2c3d54" text-anchor="end">auto-updated {generated_at} UTC</text>
</svg>
"""


def main() -> None:
    username = os.environ.get("STATS_USERNAME", "rithinkrishnakv")
    token = os.environ.get("STATS_TOKEN")
    if not token:
        print(
            "ERROR: STATS_TOKEN is not set. Create a classic PAT with the "
            "'read:user' scope and add it as a repo secret named STATS_TOKEN "
            "(see README > Manual setup).",
            file=sys.stderr,
        )
        sys.exit(1)

    out_path = sys.argv[1] if len(sys.argv) > 1 else "dist/stats.svg"

    user = fetch(username, token)
    calendar = user["contributionsCollection"]["contributionCalendar"]
    total = calendar["totalContributions"]
    days = [d for week in calendar["weeks"] for d in week["contributionDays"]]
    current_streak, longest_streak = compute_streaks(days)

    repo_block = user["repositories"]
    languages = top_languages(repo_block["nodes"])

    svg = render_svg(
        total_contributions=total,
        current_streak=current_streak,
        longest_streak=longest_streak,
        languages=languages,
        repo_count=repo_block["totalCount"],
        generated_at=datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M"),
    )

    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(svg)

    print(
        f"wrote {out_path} — total={total} streak={current_streak}/{longest_streak} "
        f"langs={[l['name'] for l in languages]}"
    )


if __name__ == "__main__":
    main()
