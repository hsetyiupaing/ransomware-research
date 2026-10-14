# ransomwareintel

Collects public ransomware victim metadata from the Ransomware.live API, preserves the raw response, normalizes it to CSV, and writes a summary report. It never contacts leak sites or downloads victim files.

## Requirements

Python 3.8+, no external packages.

## Syntax

```
python3 ransomwareintel.py <command> [--endpoint ENDPOINT] [--outdir OUTDIR] [--input-file FILE]
```

### Commands

| Command   | What it does                                                        |
|-----------|---------------------------------------------------------------------|
| `collect` | Fetch from the API and save the raw JSON plus manifest entry only   |
| `analyze` | Normalize and report on the most recent saved raw file (no network) |
| `run`     | `collect` followed by normalize, CSV, and report                    |

### Options

| Option         | Default         | Description                                          |
|----------------|-----------------|------------------------------------------------------|
| `--endpoint`   | `recentvictims` | API path under `https://api.ransomware.live/v2`     |
| `--outdir`     | `intel_data`    | Output directory                                     |
| `--input-file` | none            | Use a saved JSON file instead of calling the API     |

## Examples

```
python3 ransomwareintel.py run
python3 ransomwareintel.py run --endpoint victims/recent
python3 ransomwareintel.py collect --outdir ./data
python3 ransomwareintel.py analyze --outdir ./data
python3 ransomwareintel.py run --input-file saved.json
```

## Output layout

```
intel_data/
├── raw/
│   ├── <endpoint>_<UTC timestamp>.json   # original response, unmodified
│   └── manifest.jsonl                    # SHA-256, size, URL, status, timestamp
├── victims.csv                           # normalized dataset (overwritten each run)
└── reports/
    └── summary_<UTC timestamp>.md        # distributions, coverage, caveats
```

## CSV columns

`collected_at_utc, source_endpoint, victim, group, sector, country, attack_date, discovered_date, website, description, permalink`

Leak-site URLs, screenshots, and press links are excluded from the CSV. They remain in the raw JSON.

## Notes

- Data are unverified claims posted by criminal groups. Posting dates are not breach dates.
- Sector and country depend on the aggregator's enrichment and may be missing. See the field-coverage table in each report.
- Only `api.ransomware.live` is contacted. Any other host is refused.
