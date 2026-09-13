#!/usr/bin/env python3
"""
generate_stats.py — self-hosted GitHub stats + activity graph for the profile README.

Why this exists
----------------
The old README embedded a third-party Vercel deployment
(github-stats-extended.vercel.app) to render contribution/language stats, and
a third-party Action (maurodesouza/github-readme-activity-graph-action) to
render the separate contribution activity graph. That project's own docs
describe the public stats instance as "best-effort and can be unreliable due
to rate limits and traffic spikes," and running two independent generators
off two independent data pulls meant the stats card and the activity graph
could disagree with each other (and with the real contribution calendar).

This script removes both dependencies: it makes a single GitHub GraphQL
request for the contribution calendar + repository languages, and renders
*both* SVGs from that one response, in the same visual language as the rest
of this profile:

  - stats.svg           total contributions / streaks / top languages
  - activity-graph.svg  a trailing contribution activity line+area chart
                        (~12 months, exactly however many weeks GitHub's
                        contributionCalendar returns — never hardcoded)

Both are committed to the repo's `output` branch by a GitHub Action on a
schedule (see .github/workflows/update-dashboard.yml).

Design choices, on purpose:
- Standard library only (json, urllib). No pip install step, nothing that
  can break because a third-party package changed or was yanked.
- One GraphQL request backs both cards, so they can never disagree.
- Fails loudly (non-zero exit) with a clear message on any error, so a bad
  run shows up as a red X in Actions instead of silently publishing garbage
  or leaving a stale file in place.

Auth:
  STATS_TOKEN   — optional. A classic PAT (read:user scope) if you want the
                  card to read additional/private contribution data.
  GITHUB_TOKEN  — the ambient token GitHub Actions already provides to every
                  workflow run. The data used here (contribution calendar,
                  public repo languages) is exactly what already shows on
                  the public profile page, so no extra scope is needed —
                  this is used automatically when STATS_TOKEN isn't set, and
                  no manually-created secret is required for the common case.

  One of the two must be available or the script fails loudly and explains
  which env vars it checked.

STATS_USERNAME  — GitHub username to report on (defaults to rithinkrishnakv).

Usage:
  python3 scripts/generate_stats.py \\
      --stats-out output/stats.svg \\
      --activity-out output/activity-graph.svg
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import sys
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET

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


def resolve_token() -> tuple[str, str]:
    """Pick the token to authenticate with, and say why.

    Returns (token, description). Prefers STATS_TOKEN (opt-in, wider scope)
    and falls back to the ambient GITHUB_TOKEN Actions already provides —
    the contribution calendar and public repo languages fetched here are
    public data, so the default Actions token is sufficient scope for the
    common case. Only fails if neither is present.
    """
    stats_token = os.environ.get("STATS_TOKEN", "").strip()
    if stats_token:
        return stats_token, "STATS_TOKEN (custom scope)"

    gh_token = os.environ.get("GITHUB_TOKEN", "").strip()
    if gh_token:
        return gh_token, "GITHUB_TOKEN (default Actions token, public data scope)"

    raise RuntimeError(
        "No token available. Set STATS_TOKEN (classic PAT, read:user scope) "
        "for private/additional contribution visibility, or run this in "
        "GitHub Actions where GITHUB_TOKEN is provided automatically."
    )


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
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Could not reach GitHub API: {exc.reason}") from exc

    if payload.get("errors"):
        raise RuntimeError(f"GitHub GraphQL API returned errors: {payload['errors']}")

    user = payload.get("data", {}).get("user")
    if user is None:
        raise RuntimeError(f"No user data returned for '{username}' — check the username/token.")
    return user


def _flatten_days(weeks: list[dict]) -> list[dict]:
    return [d for week in weeks for d in week["contributionDays"]]


def compute_streaks(
    days: list[dict], today: datetime.date | None = None
) -> tuple[int, int]:
    """Return (current_streak, longest_streak) in days.

    `days` must be sorted oldest -> newest, exactly as the GitHub GraphQL API
    returns contributionCalendar.weeks[].contributionDays[]. GitHub's
    contribution calendar is itself UTC-based, so `today` defaults to the
    current UTC date — using the runner's local time here would silently
    miscompute streaks the day a runner isn't UTC (or is run manually from a
    non-UTC machine).
    """
    if today is None:
        today = datetime.datetime.now(datetime.timezone.utc).date()

    parsed = [(datetime.date.fromisoformat(d["date"]), d["contributionCount"]) for d in days]

    # Defensive: the API is not expected to return days after today, but if
    # it ever did, silently including them would corrupt the "today doesn't
    # break the streak yet" rule below. Drop anything past today instead of
    # guessing.
    parsed = [(d, c) for d, c in parsed if d <= today]

    # Defensive: the streak math below assumes exactly one entry per
    # consecutive calendar day. If the API ever returns a gap, fail loudly
    # rather than silently reporting a wrong streak.
    for prev, nxt in zip(parsed, parsed[1:]):
        if (nxt[0] - prev[0]).days != 1:
            raise ValueError(
                f"contribution calendar has a gap or duplicate: {prev[0]} -> {nxt[0]}"
            )

    longest = run = 0
    for _, count in parsed:
        if count > 0:
            run += 1
            longest = max(longest, run)
        else:
            run = 0

    current = 0
    for day, count in reversed(parsed):
        if count > 0:
            current += 1
            continue
        if day == today:
            # Today isn't over yet — a zero so far doesn't break the streak.
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


def weekly_totals(weeks: list[dict]) -> list[tuple[datetime.date, int]]:
    """Collapse each week's contributionDays into a (week_start_date, total)."""
    out = []
    for week in weeks:
        wdays = week["contributionDays"]
        if not wdays:
            continue
        start = datetime.date.fromisoformat(wdays[0]["date"])
        total = sum(d["contributionCount"] for d in wdays)
        out.append((start, total))
    return out


def esc(text: str) -> str:
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


_SVG_HEADER_STYLE = """
text{font-family:'SFMono-Regular',Consolas,'Liberation Mono',Menlo,monospace}
@keyframes popIn{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:translateY(0)}}
@keyframes fadeIn{from{opacity:0}to{opacity:1}}
.pop{opacity:0;animation:popIn .6s cubic-bezier(.2,.8,.3,1) forwards}
.fade{opacity:0;animation:fadeIn .5s ease forwards}
""".strip(
    "\n"
)

_GRADIENTS = """
<linearGradient id="bg" x1="0" y1="0" x2="1" y2="1">
<stop offset="0%" stop-color="#0d1420"/><stop offset="100%" stop-color="#080c14"/>
</linearGradient>
<linearGradient id="border" x1="0" y1="0" x2="1" y2="1">
<stop offset="0%" stop-color="#00d9ff"><animate attributeName="stop-color" values="#00d9ff;#a78bfa;#00d9ff" dur="10s" repeatCount="indefinite"/></stop>
<stop offset="100%" stop-color="#a78bfa"><animate attributeName="stop-color" values="#a78bfa;#00d9ff;#a78bfa" dur="10s" repeatCount="indefinite"/></stop>
</linearGradient>
""".strip(
    "\n"
)


def _terminal_chrome(prompt: str, width: int, height: int) -> str:
    return f"""<rect width="{width}" height="{height}" rx="16" fill="url(#bg)"/>
<rect width="{width}" height="{height}" rx="16" fill="none" stroke="url(#border)" stroke-width="1.6"/>

<circle cx="30" cy="24" r="3" fill="#3d5872"/>
<circle cx="42" cy="24" r="3" fill="#516781"/>
<circle cx="54" cy="24" r="3" fill="#7dd3fc"/>
<text x="70" y="28" font-size="10.5" fill="#3d5872" letter-spacing="1">{esc(prompt)}</text>
<path d="M20 38 H{width - 20}" stroke="#173350" stroke-width="1"/>"""


def render_stats_svg(
    *,
    total_contributions: int,
    current_streak: int,
    longest_streak: int,
    languages: list[dict],
    repo_count: int,
    generated_at: str,
) -> str:
    width, height = 700, 270
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
    chrome = _terminal_chrome("rimu@kali: ~/git-log --stat --live", width, height)

    return f"""<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" width="{width}" height="{height}" role="img" aria-label="Rithin Krishna's live GitHub statistics">
<defs>
<style type="text/css"><![CDATA[
{_SVG_HEADER_STYLE}
]]></style>
{_GRADIENTS}
</defs>

{chrome}

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


_MONTH_ABBR = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
]


def render_activity_svg(
    *,
    weeks: list[tuple[datetime.date, int]],
    generated_at: str,
) -> str:
    width, height = 700, 220
    plot_left, plot_right = 40.0, 660.0
    plot_top, plot_bottom = 70.0, 178.0  # y grows downward; bottom == zero line

    n = len(weeks)
    chrome = _terminal_chrome("rimu@kali: ~/contrib-graph --last-year", width, height)

    if n == 0:
        # No data at all — still return a valid, honestly-empty card rather
        # than crashing the whole workflow over a chart nobody can draw yet.
        body = (
            f'<text x="{(plot_left + plot_right) / 2:.1f}" y="{(plot_top + plot_bottom) / 2:.1f}" '
            f'text-anchor="middle" font-size="12" fill="#4a5b73">no contribution data available</text>'
        )
        points: list[tuple[float, float]] = []
    else:
        totals = [t for _, t in weeks]
        max_val = max(totals) or 1
        step = (plot_right - plot_left) / max(n - 1, 1)

        points = []
        for i, (_, total) in enumerate(weeks):
            x = plot_left + step * i
            y = plot_bottom - (total / max_val) * (plot_bottom - plot_top)
            points.append((x, y))

        line_path = "M" + " L".join(f"{x:.2f} {y:.2f}" for x, y in points)
        area_path = (
            line_path
            + f" L{points[-1][0]:.2f} {plot_bottom:.2f}"
            + f" L{points[0][0]:.2f} {plot_bottom:.2f} Z"
        )

        dots = "".join(
            f'<circle cx="{x:.2f}" cy="{y:.2f}" r="2" fill="#ffffff" opacity=".85"/>'
            for x, y in points
        )

        # Month labels: one per calendar month, placed at that month's first
        # week in the series (skip a label if it would land within 28px of
        # the previous one, so short months near the edge don't overlap).
        month_labels = []
        last_label_x: float | None = None
        prev_month = None
        for i, (week_start, _) in enumerate(weeks):
            if week_start.month == prev_month:
                continue
            prev_month = week_start.month
            x = plot_left + step * i
            if last_label_x is not None and x - last_label_x < 28:
                continue
            last_label_x = x
            month_labels.append(
                f'<text x="{x:.2f}" y="196" font-size="9.5" fill="#5b6b84">'
                f"{_MONTH_ABBR[week_start.month - 1]}</text>"
            )

        body = f"""<path d="{esc(area_path)}" fill="url(#areaFill)" opacity=".55"/>
<path d="{esc(line_path)}" fill="none" stroke="url(#border)" stroke-width="2"/>
{dots}
{''.join(month_labels)}
<line x1="{plot_left}" y1="{plot_bottom}" x2="{plot_right}" y2="{plot_bottom}" stroke="#173350" stroke-width="1"/>"""

    return f"""<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" width="{width}" height="{height}" role="img" aria-label="Rithin Krishna's contribution activity graph">
<defs>
<style type="text/css"><![CDATA[
{_SVG_HEADER_STYLE}
]]></style>
{_GRADIENTS}
<linearGradient id="areaFill" x1="0" y1="0" x2="0" y2="1">
<stop offset="0%" stop-color="#00d9ff" stop-opacity=".45"/>
<stop offset="100%" stop-color="#00d9ff" stop-opacity="0"/>
</linearGradient>
</defs>

{chrome}

<text x="40" y="58" font-size="12.5" fill="#00d9ff" font-weight="700">CONTRIBUTION ACTIVITY</text>
<text x="660" y="58" text-anchor="end" font-size="10" fill="#5b6b84">last {n} weeks</text>

{body}

<text x="660" y="{height - 14}" font-size="8.5" fill="#2c3d54" text-anchor="end">auto-updated {generated_at} UTC</text>
</svg>
"""


def _validate_svg(path: str) -> None:
    """Parse the file we just wrote as XML. A malformed SVG is worse than no
    update at all — it's better to fail the workflow than publish it."""
    try:
        ET.parse(path)
    except ET.ParseError as exc:
        raise RuntimeError(f"generated {path} is not well-formed XML: {exc}") from exc


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stats-out", default="dist/stats.svg")
    parser.add_argument("--activity-out", default="dist/activity-graph.svg")
    parser.add_argument(
        "--username", default=os.environ.get("STATS_USERNAME", "rithinkrishnakv")
    )
    args = parser.parse_args()

    token, token_desc = resolve_token()
    print(f"auth: using {token_desc}")

    user = fetch(args.username, token)

    calendar = user["contributionsCollection"]["contributionCalendar"]
    total = calendar["totalContributions"]
    days = _flatten_days(calendar["weeks"])
    current_streak, longest_streak = compute_streaks(days)

    repo_block = user["repositories"]
    languages = top_languages(repo_block["nodes"])

    generated_at = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M")

    stats_svg = render_stats_svg(
        total_contributions=total,
        current_streak=current_streak,
        longest_streak=longest_streak,
        languages=languages,
        repo_count=repo_block["totalCount"],
        generated_at=generated_at,
    )

    weeks = weekly_totals(calendar["weeks"])
    activity_svg = render_activity_svg(weeks=weeks, generated_at=generated_at)

    for out_path, svg in ((args.stats_out, stats_svg), (args.activity_out, activity_svg)):
        os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write(svg)
        _validate_svg(out_path)

    print(
        f"wrote {args.stats_out} — total={total} streak={current_streak}/{longest_streak} "
        f"langs={[l['name'] for l in languages]}"
    )
    print(f"wrote {args.activity_out} — {len(weeks)} weeks, max weekly total="
          f"{max((t for _, t in weeks), default=0)}")


if __name__ == "__main__":
    main()
