#!/usr/bin/env python3
"""AI crawler log analyzer.

Parses web server access logs (Apache/nginx combined, IIS W3C, Cloudflare
Logpush / generic JSON-lines), isolates AI crawler traffic, verifies claimed
bot identity against vendor-published IP ranges, and emits a Markdown report
plus CSVs suitable for client deliverables.

Stdlib only. Usage:

    python analyze.py --logs <dir-or-file> [--client "Name"] [--out <dir>]
                      [--sitemap <url-or-file>] [--offline] [--refresh-ips]
"""

import argparse
import csv
import gzip
import ipaddress
import json
import re
import sys
import time as _time
import urllib.request
from urllib.parse import unquote_plus
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

TOOL_DIR = Path(__file__).resolve().parent
CACHE_DIR = TOOL_DIR / ".cache"
CACHE_TTL_SECONDS = 7 * 24 * 3600

# --------------------------------------------------------------------------
# Bot registry
#
# category: "training" (model training corpus), "search" (AI search index),
#           "live" (real-time fetch triggered by a user's question)
# verify:   key into RANGE_SOURCES, or None when the vendor publishes no
#           IP ranges (Anthropic confirmed they use cloud-provider IPs and
#           do not publish ranges; several others simply publish nothing).
# --------------------------------------------------------------------------
BOTS = [
    # name,                 ua substring,           category,   vendor,        verify key
    ("GPTBot",              "gptbot",               "training", "OpenAI",      "gptbot"),
    ("OAI-SearchBot",       "oai-searchbot",        "search",   "OpenAI",      "oai-searchbot"),
    ("ChatGPT-User",        "chatgpt-user",         "live",     "OpenAI",      "chatgpt-user"),
    ("ClaudeBot",           "claudebot",            "training", "Anthropic",   None),
    ("Claude-SearchBot",    "claude-searchbot",     "search",   "Anthropic",   None),
    ("Claude-User",         "claude-user",          "live",     "Anthropic",   None),
    ("PerplexityBot",       "perplexitybot",        "search",   "Perplexity",  "perplexitybot"),
    ("Perplexity-User",     "perplexity-user",      "live",     "Perplexity",  "perplexity-user"),
    ("CCBot",               "ccbot",                "training", "Common Crawl", None),
    ("Bytespider",          "bytespider",           "training", "ByteDance",   None),
    ("Meta-ExternalAgent",  "meta-externalagent",   "training", "Meta",        None),
    ("Meta-ExternalFetcher","meta-externalfetcher", "live",     "Meta",        None),
    ("Applebot-Extended",   "applebot-extended",    "training", "Apple",       None),
    ("Applebot",            "applebot",             "search",   "Apple",       None),
    ("Amazonbot",           "amazonbot",            "training", "Amazon",      None),
    ("DuckAssistBot",       "duckassistbot",        "live",     "DuckDuckGo",  None),
    ("MistralAI-User",      "mistralai-user",       "live",     "Mistral",     None),
    ("Google-CloudVertexBot","google-cloudvertexbot","live",     "Google",     None),
    ("cohere-ai",           "cohere",               "training", "Cohere",      None),
    ("AI2Bot",              "ai2bot",               "training", "Ai2",         None),
]
# Longest substring first so e.g. Applebot-Extended wins over Applebot.
BOTS_ORDERED = sorted(BOTS, key=lambda b: len(b[1]), reverse=True)

RANGE_SOURCES = {
    "gptbot":          "https://openai.com/gptbot.json",
    "oai-searchbot":   "https://openai.com/searchbot.json",
    "chatgpt-user":    "https://openai.com/chatgpt-user.json",
    "perplexitybot":   "https://www.perplexity.ai/perplexitybot.json",
    "perplexity-user": "https://www.perplexity.ai/perplexity-user.json",
}

CATEGORY_LABELS = {
    "training": "Training crawler",
    "search":   "AI search indexer",
    "live":     "User-triggered fetcher",
}


# --------------------------------------------------------------------------
# IP range loading / verification
# --------------------------------------------------------------------------

def _fetch(url, timeout=20):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 ai-crawler-logs/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


def _extract_cidrs(obj, found=None):
    """Walk arbitrary JSON and collect anything that parses as an IP network."""
    if found is None:
        found = []
    if isinstance(obj, dict):
        for v in obj.values():
            _extract_cidrs(v, found)
    elif isinstance(obj, list):
        for v in obj:
            _extract_cidrs(v, found)
    elif isinstance(obj, str):
        try:
            found.append(ipaddress.ip_network(obj, strict=False))
        except ValueError:
            pass
    return found


def load_ip_ranges(offline=False, refresh=False):
    """Return {verify_key: [ip_network, ...]}; missing keys mean fetch failed."""
    CACHE_DIR.mkdir(exist_ok=True)
    ranges = {}
    for key, url in RANGE_SOURCES.items():
        cache_file = CACHE_DIR / f"{key}.json"
        body = None
        cache_fresh = (
            cache_file.exists()
            and _time.time() - cache_file.stat().st_mtime < CACHE_TTL_SECONDS
        )
        if cache_fresh and not refresh:
            body = cache_file.read_text(encoding="utf-8")
        elif not offline:
            try:
                body = _fetch(url)
                cache_file.write_text(body, encoding="utf-8")
            except Exception as e:
                print(f"  ! could not fetch {url}: {e}", file=sys.stderr)
                if cache_file.exists():
                    body = cache_file.read_text(encoding="utf-8")
                    print(f"    using stale cache for {key}", file=sys.stderr)
        elif cache_file.exists():
            body = cache_file.read_text(encoding="utf-8")
        if body:
            try:
                nets = _extract_cidrs(json.loads(body))
                if nets:
                    ranges[key] = nets
            except json.JSONDecodeError:
                print(f"  ! {key}: response was not JSON, skipping", file=sys.stderr)
    return ranges


def ip_in_ranges(ip_str, nets):
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return any(ip in n for n in nets)


# --------------------------------------------------------------------------
# Log line parsing
# --------------------------------------------------------------------------

COMBINED_RE = re.compile(
    r'^(?:\S+\s+)?'                                   # optional vhost prefix
    r'(?P<ip>(?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]{3,})\s+'
    r'\S+\s+\S+\s+'
    r'\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)(?:\s+[^"]*)?"\s+'
    r'(?P<status>\d{3})\s+(?:\d+|-)'
    r'(?:\s+"[^"]*"\s+"(?P<ua>[^"]*)")?'
)

APACHE_TIME_RE = re.compile(r"(\d{2})/([A-Za-z]{3})/(\d{4})")
MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}

JSON_IP_KEYS = ["ClientIP", "clientIP", "client_ip", "remote_addr", "remoteIp", "ip", "c-ip"]
JSON_UA_KEYS = ["ClientRequestUserAgent", "user_agent", "http_user_agent", "userAgent", "ua", "cs(User-Agent)"]
JSON_STATUS_KEYS = ["EdgeResponseStatus", "OriginResponseStatus", "status", "sc-status", "response_status"]
JSON_PATH_KEYS = ["ClientRequestURI", "ClientRequestPath", "request_uri", "uri", "path", "url", "cs-uri-stem"]
JSON_TIME_KEYS = ["EdgeStartTimestamp", "timestamp", "@timestamp", "time", "datetime", "date"]


def _first_key(d, keys):
    for k in keys:
        if k in d and d[k] not in (None, ""):
            return d[k]
    return None


def _parse_json_time(val):
    if isinstance(val, (int, float)):
        v = float(val)
        if v > 1e17:      # nanoseconds
            v /= 1e9
        elif v > 1e14:    # microseconds
            v /= 1e6
        elif v > 1e11:    # milliseconds
            v /= 1e3
        try:
            return datetime.fromtimestamp(v, tz=timezone.utc).date().isoformat()
        except (OverflowError, OSError, ValueError):
            return None
    if isinstance(val, str):
        try:
            return datetime.fromisoformat(val.replace("Z", "+00:00")).date().isoformat()
        except ValueError:
            m = re.match(r"(\d{4}-\d{2}-\d{2})", val)
            return m.group(1) if m else None
    return None


def _parse_apache_time(val):
    m = APACHE_TIME_RE.match(val)
    if not m:
        return None
    day, mon, year = m.groups()
    mon_num = MONTHS.get(mon)
    if not mon_num:
        return None
    return f"{year}-{mon_num:02d}-{int(day):02d}"


class W3CState:
    """Tracks the current #Fields ordering inside an IIS W3C log file."""

    def __init__(self):
        self.idx = {}

    def set_fields(self, line):
        fields = line.split(":", 1)[1].split()
        self.idx = {name: i for i, name in enumerate(fields)}

    def parse(self, line):
        if not self.idx:
            return None
        parts = line.split()
        needed = max(self.idx.values())
        if len(parts) <= needed:
            return None

        def get(name):
            i = self.idx.get(name)
            return parts[i] if i is not None else None

        ua = get("cs(User-Agent)")
        date = get("date")
        return {
            "ip": get("c-ip"),
            "ua": unquote_plus(ua) if ua else None,
            "status": get("sc-status"),
            "path": get("cs-uri-stem"),
            "date": date,
        }


def parse_line(line, w3c):
    """Return dict(ip, ua, status, path, date) or None if unparseable."""
    line = line.strip()
    if not line:
        return None
    if line.startswith("#"):
        if line.startswith("#Fields:"):
            w3c.set_fields(line)
        return "meta"
    if line.startswith("{"):
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            return None
        if not isinstance(d, dict):
            return None
        status = _first_key(d, JSON_STATUS_KEYS)
        return {
            "ip": _first_key(d, JSON_IP_KEYS),
            "ua": _first_key(d, JSON_UA_KEYS),
            "status": str(status) if status is not None else None,
            "path": _first_key(d, JSON_PATH_KEYS),
            "date": _parse_json_time(_first_key(d, JSON_TIME_KEYS)),
        }
    m = COMBINED_RE.match(line)
    if m:
        return {
            "ip": m.group("ip"),
            "ua": m.group("ua"),
            "status": m.group("status"),
            "path": m.group("path"),
            "date": _parse_apache_time(m.group("time")),
        }
    if w3c.idx:
        return w3c.parse(line)
    return None


BOT_QUICK_RE = re.compile("|".join(re.escape(b[1]) for b in BOTS_ORDERED), re.IGNORECASE)


def match_bot(ua):
    if not isinstance(ua, str) or not ua or not BOT_QUICK_RE.search(ua):
        return None
    ua_l = ua.lower()
    for name, sub, category, vendor, verify in BOTS_ORDERED:
        if sub in ua_l:
            return (name, category, vendor, verify)
    return None


# --------------------------------------------------------------------------
# Aggregation
# --------------------------------------------------------------------------

class BotStats:
    def __init__(self, name, category, vendor, verify):
        self.name = name
        self.category = category
        self.vendor = vendor
        self.verify = verify
        self.verifiable = False
        self.hits = 0
        self.dates = Counter()
        self.paths = Counter()
        self.statuses = Counter()
        self.ips = Counter()
        self.ip_verdicts = Counter()
        self.verdicts = Counter()
        self.robots_hits = 0

    def add(self, rec, verdict="unverified"):
        self.hits += 1
        self.verdicts[verdict] += 1
        if rec["date"]:
            self.dates[rec["date"]] += 1
        path = rec["path"] or "-"
        base = path.split("?")[0]
        self.paths[base] += 1
        if base.rstrip("/").endswith("robots.txt"):
            self.robots_hits += 1
        self.statuses[rec["status"] or "?"] += 1
        if rec["ip"]:
            self.ips[rec["ip"]] += 1
            self.ip_verdicts[(rec["ip"], verdict)] += 1
        else:
            self.ip_verdicts[("(missing)", verdict)] += 1

    def blocked_pct(self):
        blocked = sum(c for s, c in self.statuses.items() if s in ("401", "403", "429"))
        return 100.0 * blocked / self.hits if self.hits else 0.0


def iter_log_files(root):
    p = Path(root)
    if p.is_file():
        yield p
        return
    exts = {".log", ".gz", ".txt", ".json", ".ndjson", ".jsonl", ""}
    for f in sorted(p.rglob("*")):
        if f.is_file() and (f.suffix.lower() in exts or f.name.endswith(".log.gz")):
            yield f


def open_log(path):
    if path.suffix == ".gz" or path.name.endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, "r", encoding="utf-8", errors="replace")


def analyze(log_root, ranges):
    """Parse logs. Returns (stats, spoofed, totals, all_dates).

    Requests outside an available range go into a separate mismatch bucket.
    Missing or invalid addresses, and bots without available ranges, stay
    unverified. A current IP list does not establish historical ownership.
    """
    stats, spoofed = {}, {}
    totals = {"lines": 0, "parsed": 0, "unparsed": 0, "bot_hits": 0, "files": 0}
    all_dates = Counter()
    ip_verdict_cache = {}  # (verify_key, ip) -> bool
    for f in iter_log_files(log_root):
        totals["files"] += 1
        w3c = W3CState()
        try:
            with open_log(f) as fh:
                for line in fh:
                    totals["lines"] += 1
                    rec = parse_line(line, w3c)
                    if rec == "meta":
                        continue
                    if rec is None:
                        totals["unparsed"] += 1
                        continue
                    totals["parsed"] += 1
                    if rec["date"]:
                        all_dates[rec["date"]] += 1
                    hit = match_bot(rec["ua"])
                    if not hit:
                        continue
                    name, category, vendor, verify = hit
                    totals["bot_hits"] += 1
                    bucket = stats
                    verdict = "unverified"
                    try:
                        ipaddress.ip_address(rec["ip"])
                        valid_ip = True
                    except (ValueError, TypeError):
                        valid_ip = False
                    if verify and verify in ranges and valid_ip:
                        key = (verify, rec["ip"])
                        if key not in ip_verdict_cache:
                            ip_verdict_cache[key] = ip_in_ranges(rec["ip"], ranges[verify])
                        if not ip_verdict_cache[key]:
                            bucket = spoofed
                            verdict = "outside published range"
                        else:
                            verdict = "range match"
                    if name not in bucket:
                        bucket[name] = BotStats(name, category, vendor, verify)
                        bucket[name].verifiable = bool(verify and verify in ranges)
                    bucket[name].add(rec, verdict)
        except OSError as e:
            print(f"  ! cannot read {f}: {e}", file=sys.stderr)
    return stats, spoofed, totals, all_dates


# --------------------------------------------------------------------------
# Sitemap coverage (optional)
# --------------------------------------------------------------------------

def load_sitemap_paths(src, depth=0, allow_network=True):
    """Return a set of URL paths from a sitemap URL or local file."""
    if depth > 2:
        return set()
    try:
        if re.match(r"https?://", str(src)):
            if not allow_network:
                print(f"  ! remote sitemap skipped in offline mode: {src}", file=sys.stderr)
                return set()
            body = _fetch(str(src))
        else:
            body = Path(src).read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        print(f"  ! sitemap {src}: {e}", file=sys.stderr)
        return set()
    try:
        root = ET.fromstring(body)
    except ET.ParseError:
        return set()
    ns = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}
    paths = set()
    if root.tag.endswith("sitemapindex"):
        children = [loc.text.strip() for loc in root.findall(".//sm:loc", ns) if loc.text][:50]
        for child in children:
            paths |= load_sitemap_paths(child, depth + 1, allow_network)
    else:
        for loc in root.findall(".//sm:loc", ns):
            if loc.text:
                m = re.match(r"https?://[^/]+(/.*)?$", loc.text.strip())
                paths.add((m.group(1) or "/") if m else loc.text.strip())
    return paths


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------

def write_csvs(out_dir, stats, spoofed):
    with open(out_dir / "daily_hits.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["date", "bot", "category", "hits"])
        for bot in stats.values():
            for date in sorted(bot.dates):
                w.writerow([date, bot.name, bot.category, bot.dates[date]])
    with open(out_dir / "top_urls.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["bot", "category", "url", "hits"])
        for bot in stats.values():
            for path, count in bot.paths.most_common(200):
                w.writerow([bot.name, bot.category, path, count])
    with open(out_dir / "status_codes.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["bot", "status", "hits"])
        for bot in stats.values():
            for status, count in sorted(bot.statuses.items()):
                w.writerow([bot.name, status, count])
    with open(out_dir / "ips.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["bot", "ip", "hits", "verdict"])
        for bot in stats.values():
            for (ip, verdict), count in bot.ip_verdicts.most_common():
                w.writerow([bot.name, ip, count, verdict])
        for bot in spoofed.values():
            for (ip, verdict), count in bot.ip_verdicts.most_common():
                w.writerow([bot.name, ip, count, verdict])


def _pct(part, whole):
    return f"{100.0 * part / whole:.1f}%" if whole else "-"


def write_report(out_dir, client, stats, spoofed, totals, all_dates, ranges, sitemap_paths, sitemap_src):
    lines = []
    add = lines.append
    date_range = f"{min(all_dates)} to {max(all_dates)}" if all_dates else "unknown"
    bots_sorted = sorted(stats.values(), key=lambda b: -b.hits)

    add(f"# AI Crawler Report — {client}")
    add("")
    add(f"- **Log window:** {date_range}")
    add(f"- **Files parsed:** {totals['files']}  |  **Lines:** {totals['lines']:,} "
        f"(parsed {totals['parsed']:,}, unparseable {totals['unparsed']:,})")
    add(f"- **Requests matching tracked user agents:** {totals['bot_hits']:,} "
        f"({_pct(totals['bot_hits'], totals['parsed'])} of parsed traffic)")
    add(f"- **Generated:** {datetime.now().date().isoformat()} by ai-crawler-logs")
    add("")

    if not bots_sorted and not spoofed:
        add("**No AI crawler traffic found.** Check whether the site sits behind a "
            "CDN/WAF (bot hits may be blocked at the edge and never reach these logs) "
            "and whether the log format includes user-agent strings.")
        (out_dir / "report.md").write_text("\n".join(lines), encoding="utf-8")
        return

    add("## Summary by bot")
    add("")
    add("| Bot | Type | Hits | Days seen | IP-range matches | Unverified | Blocked (401/403/429) | robots.txt fetches |")
    add("|---|---|---:|---:|---:|---:|---:|---:|")
    for b in bots_sorted:
        add(f"| {b.name} | {CATEGORY_LABELS[b.category]} | {b.hits:,} | {len(b.dates)} "
            f"| {b.verdicts['range match']:,} | {b.verdicts['unverified']:,} | {_pct(sum(c for s, c in b.statuses.items() if s in ('401','403','429')), b.hits)} "
            f"| {b.robots_hits} |")
    add("")
    add("Requests outside the available IP ranges are excluded from this table. "
        "Unverified requests have no usable IP or no available range list and rely on "
        "the user agent. Range matches use the list available at analysis time, not necessarily at request time.")
    add("")

    # Category rollup
    cat_totals = Counter()
    for b in bots_sorted:
        cat_totals[b.category] += b.hits
    add("## What this means")
    add("")
    add(f"- **Training crawlers** ({cat_totals['training']:,} hits): requests attributed to crawlers "
        "associated with training; requests alone do not prove content was used for training.")
    add(f"- **AI search indexers** ({cat_totals['search']:,} hits): requests attributed to "
        "AI search crawlers; a request does not establish indexing or citation.")
    add(f"- **User-triggered fetchers** ({cat_totals['live']:,} hits): requests attributed to "
        "fetchers triggered by users or site owners; logs alone do not establish a citation.")
    add("")

    # Blocking alerts
    alerts = [b for b in bots_sorted if b.hits >= 10 and b.blocked_pct() >= 30]
    if alerts:
        add("## ⚠ Blocking alerts")
        add("")
        for b in alerts:
            add(f"- **{b.name}** is blocked on {b.blocked_pct():.0f}% of its requests. "
                "Investigate whether this was intended and where the responses originated.")
        add("")

    # Live retrieval spotlight
    live_bots = [b for b in bots_sorted if b.category == "live" and b.hits]
    if live_bots:
        add("## Live-retrieval spotlight (user-triggered AI fetches)")
        add("")
        add("Pages requested by crawlers categorized as user-triggered fetchers:")
        add("")
        add("| Page | Bot | Fetches |")
        add("|---|---|---:|")
        rows = []
        for b in live_bots:
            for path, count in b.paths.most_common(15):
                rows.append((count, path, b.name))
        for count, path, name in sorted(rows, reverse=True)[:25]:
            add(f"| {path} | {name} | {count} |")
        add("")

    # Top URLs per bot
    add("## Top pages per bot")
    add("")
    for b in bots_sorted:
        add(f"### {b.name} ({b.vendor} — {CATEGORY_LABELS[b.category]})")
        add("")
        for path, count in b.paths.most_common(10):
            add(f"- `{path}` — {count}")
        status_str = ", ".join(f"{s}: {c}" for s, c in sorted(b.statuses.items()))
        add(f"- Status codes: {status_str}")
        add("")

    # Spoofing
    if spoofed:
        add("## Requests outside published IP ranges")
        add("")
        add("These requests claim a listed user agent but their IP does not match the "
            "range list available at analysis time. They are excluded from the bot table; "
            "a mismatch alone does not establish intent or historical ownership.")
        add("")
        for b in sorted(spoofed.values(), key=lambda x: -x.hits):
            top_ips = ", ".join(f"{ip} ({c})" for ip, c in b.ips.most_common(8))
            top_path = b.paths.most_common(1)[0][0] if b.paths else "-"
            add(f"- **{b.name}:** {b.hits:,} hits from {len(b.ips)} IPs — {top_ips}. "
                f"Most-hit path: `{top_path}`")
        add("")

    # Sitemap coverage
    if sitemap_paths:
        add("## Sitemap coverage")
        add("")
        add(f"Sitemap: `{sitemap_src}` — {len(sitemap_paths):,} URLs")
        add("")
        add("| Bot | Sitemap URLs fetched | Coverage |")
        add("|---|---:|---:|")
        for b in bots_sorted:
            crawled = {p.rstrip('/') or '/' for p in b.paths}
            covered = sum(1 for p in sitemap_paths if (p.rstrip('/') or '/') in crawled)
            add(f"| {b.name} | {covered:,} | {_pct(covered, len(sitemap_paths))} |")
        add("")

    add("## Caveats")
    add("")
    add("- **Google AI activity is not comprehensively identifiable from these logs.** "
        "`Google-Extended` is a robots.txt control token, not a distinct request user agent; "
        "other Google fetchers may be distinguishable. Do not infer citations from crawl requests.")
    add("- **Anthropic bots (ClaudeBot, Claude-User, Claude-SearchBot) cannot be IP-verified** — "
        "Anthropic does not publish crawler IP ranges (they crawl from cloud-provider IPs). "
        "Counts for these are user-agent-only and could include impostors.")
    if any(b.verify and b.verify not in ranges for b in bots_sorted):
        add("- Some vendor IP-range lists could not be fetched this run; affected bots were "
            "counted user-agent-only as unverified.")
    add("- If the site sits behind Cloudflare or another CDN, origin logs miss requests "
        "served or blocked at the edge — pull edge logs (or Cloudflare AI Crawl Control "
        "numbers) for the full picture.")
    add("")

    (out_dir / "report.md").write_text("\n".join(lines), encoding="utf-8")


def main():
    ap = argparse.ArgumentParser(description="Analyze server logs for AI crawler behavior.")
    ap.add_argument("--logs", required=True, help="Log file or directory (handles .gz, JSON lines, W3C)")
    ap.add_argument("--client", default="client", help="Client name for the report")
    ap.add_argument("--out", default=None, help="Output directory (default: reports/<client>-<date>)")
    ap.add_argument("--sitemap", default=None, help="Sitemap URL or local XML file for coverage check")
    ap.add_argument("--offline", action="store_true", help="Don't fetch IP ranges; use cache only")
    ap.add_argument("--refresh-ips", action="store_true", help="Force re-fetch of vendor IP ranges")
    args = ap.parse_args()

    if not Path(args.logs).exists():
        ap.error(f"log path does not exist: {args.logs}")
    if args.offline and args.sitemap and re.match(r"https?://", args.sitemap):
        ap.error("--offline cannot be used with a remote sitemap")

    print(f"Loading vendor IP ranges{' (offline)' if args.offline else ''}...")
    ranges = load_ip_ranges(offline=args.offline, refresh=args.refresh_ips)
    for key in RANGE_SOURCES:
        state = f"{len(ranges[key])} ranges" if key in ranges else "UNAVAILABLE"
        print(f"  {key}: {state}")

    print(f"Parsing logs from {args.logs} ...")
    stats, spoofed, totals, all_dates = analyze(args.logs, ranges)
    n_spoofed = sum(b.hits for b in spoofed.values())
    print(f"  {totals['files']} files, {totals['lines']:,} lines, "
          f"{totals['bot_hits']:,} matching requests across {len(stats)} bots "
          f"({n_spoofed:,} outside available IP ranges)")

    sitemap_paths = set()
    if args.sitemap:
        print(f"Loading sitemap {args.sitemap} ...")
        sitemap_paths = load_sitemap_paths(args.sitemap, allow_network=not args.offline)
        print(f"  {len(sitemap_paths):,} URLs")

    slug = re.sub(r"[^\w\-]+", "-", args.client.strip().lower()).strip("-") or "client"
    out_dir = Path(args.out) if args.out else TOOL_DIR / "reports" / f"{slug}-{datetime.now().date().isoformat()}"
    out_dir.mkdir(parents=True, exist_ok=True)

    write_csvs(out_dir, stats, spoofed)
    write_report(out_dir, args.client, stats, spoofed, totals, all_dates, ranges,
                 sitemap_paths, args.sitemap)
    print(f"\nReport: {out_dir / 'report.md'}")
    print(f"CSVs:   daily_hits.csv, top_urls.csv, status_codes.csv, ips.csv in {out_dir}")


if __name__ == "__main__":
    main()
