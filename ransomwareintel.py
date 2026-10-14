#!/usr/bin/env python3
"""
ransomwatch_intel.py - small threat-intelligence collection and analysis tool.

Collects PUBLIC ransomware victim metadata from the Ransomware.live API, preserves
the raw response, normalizes it to CSV, and writes a summary report.

Safety by design:
  * Only talks to the Ransomware.live API host. It never opens leak-site URLs
    and never downloads victim files. Leak-site/victim URLs that appear in the
    data are treated as inert text (and are NOT carried into the CSV by default).
  * Raw evidence is saved byte-for-byte with a SHA-256 hash and a manifest entry.

Usage:
  python ransomwatch_intel.py run                      # collect + normalize + report
  python ransomwatch_intel.py collect --endpoint victims/recent
  python ransomwatch_intel.py analyze                  # re-analyze latest raw file
  python ransomwatch_intel.py run --input-file saved.json   # offline / replay
"""
import argparse
import csv
import hashlib
import json
import sys
import urllib.error
import urllib.request
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

API_BASE = "https://api.ransomware.live/v2"
ALLOWED_HOST = "api.ransomware.live"
DEFAULT_ENDPOINT = "recentvictims"
USER_AGENT = "ransomwatch-intel/1.0 (defensive research; metadata only)"
TIMEOUT = 30
MAX_BYTES = 50 * 1024 * 1024  # refuse absurdly large responses

# Normalized column -> candidate source keys (first match wins).
FIELD_ALIASES = {
    "victim": ["victim", "post_title", "name", "title"],
    "group": ["group", "group_name"],
    "sector": ["activity", "sector", "industry"],
    "country": ["country"],
    "attack_date": ["attackdate", "attack_date", "published"],
    "discovered_date": ["discovered", "discovered_date", "date"],
    "website": ["website", "domain"],
    "description": ["description"],
    "permalink": ["permalink"],  # ransomware.live page, not the criminal site
}
# Deliberately excluded from the CSV: leak-site / onion / file links.
EXCLUDED_KEYS = {"url", "screenshot", "infostealer", "press", "extra"}

CSV_COLUMNS = ["collected_at_utc", "source_endpoint"] + list(FIELD_ALIASES)


def utc_now():
    return datetime.now(timezone.utc)


def stamp(dt):
    return dt.strftime("%Y%m%dT%H%M%SZ")


# ---------------------------------------------------------------- collection
def fetch_raw(endpoint):
    url = f"{API_BASE}/{endpoint.strip('/')}"
    if urlparse(url).hostname != ALLOWED_HOST:
        raise ValueError(f"Refusing to contact non-API host: {url}")
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT,
                                               "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        body = resp.read(MAX_BYTES + 1)
        if len(body) > MAX_BYTES:
            raise ValueError("Response exceeds size limit")
        return url, resp.status, body


def save_evidence(body, endpoint, url, status, collected_at, outdir, source="api"):
    raw_dir = Path(outdir) / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    safe = endpoint.strip("/").replace("/", "_") or "root"
    path = raw_dir / f"{safe}_{stamp(collected_at)}.json"
    path.write_bytes(body)  # original bytes, unmodified
    sha = hashlib.sha256(body).hexdigest()
    manifest = {
        "file": path.name,
        "sha256": sha,
        "bytes": len(body),
        "source_url": url,
        "http_status": status,
        "collection_source": source,
        "collected_at_utc": collected_at.isoformat(),
    }
    with open(raw_dir / "manifest.jsonl", "a", encoding="utf-8") as fh:
        fh.write(json.dumps(manifest) + "\n")
    return path, manifest


# ------------------------------------------------------------- normalization
def pick(record, keys):
    for k in keys:
        v = record.get(k)
        if v not in (None, "", []):
            return str(v).strip()
    return ""


def normalize_date(value):
    """Return YYYY-MM-DD if parseable, else ''."""
    if not value:
        return ""
    v = value.strip().replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(v).date().isoformat()
    except ValueError:
        pass
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d",
                "%d/%m/%Y", "%m/%d/%Y"):
        try:
            return datetime.strptime(value.strip(), fmt).date().isoformat()
        except ValueError:
            continue
    return ""


def extract_records(payload):
    if isinstance(payload, list):
        return [r for r in payload if isinstance(r, dict)]
    if isinstance(payload, dict):
        for key in ("victims", "data", "results"):
            if isinstance(payload.get(key), list):
                return [r for r in payload[key] if isinstance(r, dict)]
        return [payload]
    return []


def normalize(records, endpoint, collected_at):
    rows = []
    for rec in records:
        row = {"collected_at_utc": collected_at.isoformat(),
               "source_endpoint": endpoint}
        for col, aliases in FIELD_ALIASES.items():
            row[col] = pick(rec, aliases)
        for col in ("attack_date", "discovered_date"):
            row[col] = normalize_date(row[col])
        rows.append(row)
    return rows


def write_csv(rows, path):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=CSV_COLUMNS)
        w.writeheader()
        w.writerows(rows)


# ------------------------------------------------------------------ analysis
def top(counter, n=10):
    return counter.most_common(n)


def md_table(title, pairs, total):
    if not pairs:
        return f"### {title}\n\n_Field not present in this dataset._\n"
    lines = [f"### {title}", "", "| Value | Count | Share |", "|---|---:|---:|"]
    for k, c in pairs:
        lines.append(f"| {k} | {c} | {c / total:.1%} |")
    return "\n".join(lines) + "\n"


def analyze(rows, manifest, endpoint):
    total = len(rows)
    out = {"total": total}
    for col in ("group", "sector", "country"):
        out[col] = Counter(r[col] for r in rows if r[col])
    date_col = "attack_date" if any(r["attack_date"] for r in rows) else "discovered_date"
    out["date_col"] = date_col
    out["by_day"] = Counter(r[date_col] for r in rows if r[date_col])
    out["by_month"] = Counter(r[date_col][:7] for r in rows if r[date_col])
    out["coverage"] = {c: sum(1 for r in rows if r[c]) for c in FIELD_ALIASES}
    return out


def build_report(rows, a, manifest, endpoint):
    total = a["total"]
    lines = [
        "# Ransomware Victim Metadata - Summary Report",
        "",
        f"- **Collected (UTC):** {manifest['collected_at_utc']}",
        f"- **Source:** {manifest['source_url']} (HTTP {manifest['http_status']})",
        f"- **Evidence file:** `raw/{manifest['file']}`",
        f"- **SHA-256:** `{manifest['sha256']}`",
        f"- **Records:** {total}",
        f"- **Report generated (UTC):** {utc_now().isoformat()}",
        "",
        "## Field coverage",
        "",
        "| Field | Populated | Coverage |",
        "|---|---:|---:|",
    ]
    for col, n in a["coverage"].items():
        lines.append(f"| {col} | {n} | {n / total:.1%} |" if total else f"| {col} | 0 | 0% |")
    lines.append("")
    if total:
        lines.append(md_table("Top groups", top(a["group"]), total))
        lines.append(md_table("Top sectors", top(a["sector"]), total))
        lines.append(md_table("Top countries", top(a["country"]), total))
        months = sorted(a["by_month"].items())
        lines.append(md_table(f"Victims by month ({a['date_col']})", months, total))
        days = sorted(a["by_day"].items())
        if days:
            lines.append(f"**Date range:** {days[0][0]} to {days[-1][0]}  ")
            busiest = max(days, key=lambda d: d[1])
            lines.append(f"**Busiest day:** {busiest[0]} ({busiest[1]} postings)\n")
    lines += [
        "## Caveats",
        "",
        "- Data are claims posted by criminal groups and aggregated by a third party; "
        "they are **not verified** breaches. Victim names may be wrong, duplicated, or disputed.",
        "- Posting/discovery dates are not breach dates. Counts reflect what leak sites "
        "chose to publish and what the aggregator observed, not true incidence.",
        "- Sector/country values depend on the aggregator's enrichment and may be missing "
        "or inconsistent; coverage is shown above.",
        "- No leak-site or victim-file content was accessed by this tool.",
        "",
    ]
    return "\n".join(lines)


# ----------------------------------------------------------------------- CLI
def do_collect(args):
    collected_at = utc_now()
    if args.input_file:
        body = Path(args.input_file).read_bytes()
        url, status, source = f"file://{Path(args.input_file).name}", 0, "local-replay"
    else:
        try:
            url, status, body = fetch_raw(args.endpoint)
        except (urllib.error.URLError, ValueError) as exc:
            sys.exit(f"Collection failed: {exc}")
        source = "api"
    json.loads(body)  # validate it is JSON before keeping as evidence
    path, manifest = save_evidence(body, args.endpoint, url, status,
                                   collected_at, args.outdir, source)
    print(f"Saved evidence: {path}  sha256={manifest['sha256'][:16]}...")
    return path, manifest, collected_at


def do_normalize_and_report(path, manifest, collected_at, args):
    payload = json.loads(path.read_bytes())
    rows = normalize(extract_records(payload), args.endpoint, collected_at)
    csv_path = Path(args.outdir) / "victims.csv"
    write_csv(rows, csv_path)
    a = analyze(rows, manifest, args.endpoint)
    report = build_report(rows, a, manifest, args.endpoint)
    rep_dir = Path(args.outdir) / "reports"
    rep_dir.mkdir(parents=True, exist_ok=True)
    rep_path = rep_dir / f"summary_{stamp(collected_at)}.md"
    rep_path.write_text(report, encoding="utf-8")
    print(f"Wrote {len(rows)} rows -> {csv_path}")
    print(f"Wrote report -> {rep_path}")


def latest_manifest(outdir):
    mf = Path(outdir) / "raw" / "manifest.jsonl"
    if not mf.exists():
        sys.exit("No evidence found. Run `collect` first.")
    last = json.loads(mf.read_text().strip().splitlines()[-1])
    return Path(outdir) / "raw" / last["file"], last


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("command", choices=["collect", "analyze", "run"])
    p.add_argument("--endpoint", default=DEFAULT_ENDPOINT,
                   help="API path under /v2 (default: recentvictims)")
    p.add_argument("--outdir", default="intel_data")
    p.add_argument("--input-file", help="Use a saved JSON file instead of calling the API")
    args = p.parse_args()

    if args.command == "collect":
        do_collect(args)
    elif args.command == "run":
        path, manifest, ts = do_collect(args)
        do_normalize_and_report(path, manifest, ts, args)
    else:
        path, manifest = latest_manifest(args.outdir)
        ts = datetime.fromisoformat(manifest["collected_at_utc"])
        do_normalize_and_report(path, manifest, ts, args)


if __name__ == "__main__":
    main()