# SubRecon – Comprehensive Subdomain Enumeration Automation

> 22+ sources | CLI Tools + APIs + Curl Endpoints | All-in-one pipeline

SubRecon automates subdomain enumeration by running **22+ enumeration sources** in parallel — CLI tools, public APIs, and certificate transparency logs — then merges, deduplicates, resolves DNS, probes for live hosts, and generates professional reports.

## Features

- **12 CLI Tool Wrappers** – subfinder, amass, assetfinder, chaos, findomain, haktrails, gau, github-subdomains, gitlab-subdomains, cero, shosubgo, puredns
- **10 API/Curl Sources** – crt.sh, JLDC/Anubis, AlienVault OTX, Subdomain Center, CertSpotter, VirusTotal, BufferOver, HackerTarget, RapidDNS, URLScan.io
- **Concurrent DNS Resolution** – Resolves all subdomains with wildcard detection & filtering
- **HTTP Probing** – Checks which subdomains are alive (ports 80/443) with status codes & page titles
- **Trickest Resolvers** – Auto-downloads fresh DNS resolvers for puredns
- **Multiple Output Formats** – TXT, JSON, CSV, and a self-contained dark-themed HTML report
- **Rich Terminal UI** – Beautiful banners, progress, and summary tables via Rich
- **Graceful Degradation** – Missing CLI tools are skipped with a warning; API-only mode available

## Installation

```bash
# Clone or copy the project
cd recon

# Install Python dependencies
pip install -r requirements.txt

# (Optional) Install CLI tools for maximum coverage
# See "CLI Tools Setup" below
```

## Usage

```bash
# Basic scan (API sources + any installed CLI tools)
python subenum.py example.com

# API-only mode (no CLI tools needed)
python subenum.py example.com --no-tools

# Skip HTTP probing (faster, just enumerate)
python subenum.py example.com --no-probe

# Silent mode — just print subdomains (pipe-friendly)
python subenum.py example.com --silent --no-resolve --no-probe

# Full scan with all API keys and brute-force
python subenum.py example.com \
  --vt-key YOUR_VT_KEY \
  --github-token YOUR_GITHUB_TOKEN \
  --shodan-key YOUR_SHODAN_KEY \
  --wordlist /path/to/wordlist.txt \
  --threads 100

# Custom output directory
python subenum.py example.com -o ./my_results
```

## CLI Flags

| Flag | Description | Default |
|------|-------------|---------|
| `domain` | Target domain (positional) | required |
| `-o, --output` | Output directory | `results/<domain>` |
| `--threads` | Concurrency level | 50 |
| `--timeout` | HTTP/API timeout (seconds) | 15 |
| `--tool-timeout` | CLI tool timeout (seconds) | 300 |
| `--no-resolve` | Skip DNS resolution | off |
| `--no-probe` | Skip HTTP probing | off |
| `--no-tools` | Skip CLI tools (API-only) | off |
| `--silent` | Print subdomains only | off |
| `--vt-key` | VirusTotal API key | `$VT_API_KEY` |
| `--github-token` | GitHub token | `$GITHUB_TOKEN` |
| `--gitlab-token` | GitLab token | `$GITLAB_TOKEN` |
| `--shodan-key` | Shodan API key | `$SHODAN_KEY` |
| `--wordlist` | Wordlist for puredns | none |
| `--resolvers` | Custom DNS resolvers file | auto-downloads |
| `--subfinder-config` | subfinder provider-config.yaml path | none |
| `-v, --verbose` | Debug logging | off |

## Output Files

After a scan, the `results/<domain>/` directory will contain:

| File | Description |
|------|-------------|
| `subdomains.txt` | One subdomain per line |
| `subdomains.json` | Full results with per-source breakdown, DNS, and probing data |
| `subdomains.csv` | Spreadsheet-friendly table with IP, status, title, server |
| `report.html` | Self-contained dark-themed HTML report (open in browser) |

## CLI Tools Setup

Install these Go-based tools for maximum coverage. SubRecon works without them (using API-only mode) but having them installed significantly increases results.

```bash
# Core tools
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/owasp-amass/amass/v4/...@master
go install github.com/tomnomnom/assetfinder@latest
go install github.com/projectdiscovery/chaos-client/cmd/chaos@latest
# findomain — download binary from https://github.com/Findomain/Findomain

# URL & cert tools
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/glebarez/cero@latest

# Git-based
go install github.com/gwen001/github-subdomains@latest
go install github.com/gwen001/gitlab-subdomains@latest

# Shodan-based
go install github.com/incogbyte/shosubgo@latest

# SecurityTrails
go install github.com/hakluke/haktrails@latest

# DNS brute-force
go install github.com/d3mondev/puredns/v2@latest

# Chaos (requires PDCP_API_KEY)
go install github.com/projectdiscovery/chaos-client/cmd/chaos@latest
```

## Environment Variables

Set these for tools that need authentication:

```bash
export GITHUB_TOKEN="ghp_..."
export GITLAB_TOKEN="glpat-..."
export SHODAN_KEY="..."
export VT_API_KEY="..."
export PDCP_API_KEY="..."   # For chaos
```

## Architecture

```
┌──────────────────────────────────────────────────┐
│                   SubRecon                       │
├──────────────────────────────────────────────────┤
│                                                  │
│  ┌─────────────┐  ┌────────────────────────────┐ │
│  │  CLI Tools  │  │     API Sources            │ │
│  │  (12 tools) │  │     (10 endpoints)         │ │
│  │  subprocess │  │     aiohttp async          │ │
│  └──────┬──────┘  └────────────┬───────────────┘ │
│         │                      │                 │
│         └──────────┬───────────┘                 │
│                    ▼                             │
│         ┌──────────────────┐                     │
│         │  Merge & Dedup   │                     │
│         └────────┬─────────┘                     │
│                  ▼                               │
│         ┌──────────────────┐                     │
│         │  DNS Resolution  │ (wildcard detection)│
│         └────────┬─────────┘                     │
│                  ▼                               │
│         ┌──────────────────┐                     │
│         │  HTTP Probing    │ (status + title)    │
│         └────────┬─────────┘                     │
│                  ▼                               │
│    ┌─────┬──────┬──────┬───────┐                 │
│    │ TXT │ JSON │ CSV  │ HTML  │                 │
│    └─────┴──────┴──────┴───────┘                 │
└──────────────────────────────────────────────────┘
```

## License

MIT — use freely for bug bounty & security research.
