#!/usr/bin/env python3
"""
SubRecon – Comprehensive Subdomain Enumeration Automation
==========================================================
Wraps 22+ subdomain enumeration sources (CLI tools + APIs) into a single
automated pipeline. Runs everything in parallel, merges & deduplicates,
resolves DNS, probes live hosts, and generates professional reports.

Author : @dhananjay
Usage  : python subenum.py <domain> [options]
"""

import argparse
import asyncio
import csv
import json
import sqlite3
import logging
import os
import platform
import re
import shutil
import socket
import ssl
import subprocess
import sys
import time
import random
import string
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from concurrent.futures import ThreadPoolExecutor

try:
    import aiohttp
except ImportError:
    print("[!] aiohttp not installed. Run: pip install aiohttp")
    sys.exit(1)

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, BarColumn, TimeRemainingColumn, TextColumn, SpinnerColumn
    from rich.live import Live
    from rich.text import Text
    from rich import box
except ImportError:
    print("[!] rich not installed. Run: pip install rich")
    sys.exit(1)

try:
    from bs4 import BeautifulSoup
except ImportError:
    BeautifulSoup = None

try:
    import aiodns
except ImportError:
    aiodns = None

# ─────────────────────────────────────────────────────────────────────────────
# .ENV LOADER
# ─────────────────────────────────────────────────────────────────────────────

def load_dotenv(filepath: str = ".env"):
    """Load environment variables from a .env file (no external dependency)."""
    env_path = Path(filepath)
    if not env_path.exists():
        # Also check relative to script location
        env_path = Path(__file__).parent / filepath
    if not env_path.exists():
        return
    with open(env_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key and value and key not in os.environ:
                os.environ[key] = value


# ─────────────────────────────────────────────────────────────────────────────
# GLOBALS
# ─────────────────────────────────────────────────────────────────────────────

console = Console()
log = logging.getLogger("subrecon")

BANNER = r"""[bold cyan]
  ███████ ██    ██ ██████  ██████  ███████  ██████  ██████  ███    ██
  ██      ██    ██ ██   ██ ██   ██ ██      ██      ██    ██ ████   ██
  ███████ ██    ██ ██████  ██████  █████   ██      ██    ██ ██ ██  ██
       ██ ██    ██ ██   ██ ██   ██ ██      ██      ██    ██ ██  ██ ██
  ███████  ██████  ██████  ██   ██ ███████  ██████  ██████  ██   ████
[/bold cyan]
[dim]  ──────────────────────────────────────────────────────────────────
  Comprehensive Subdomain Enumeration Automation  │  v3.0
  25+ Sources  │  CLI Tools + APIs + Curl Endpoints
  ──────────────────────────────────────────────────────────────────[/dim]
"""

SUBDOMAIN_REGEX = re.compile(
    r"^(?!-)[a-zA-Z0-9_-]{1,63}(?:\.[a-zA-Z0-9_-]{1,63})*\.[a-zA-Z]{2,}$"
)

USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"


# ─────────────────────────────────────────────────────────────────────────────
# RETRY REQUEST HELPER
# ─────────────────────────────────────────────────────────────────────────────

async def retry_request(
    session: aiohttp.ClientSession,
    url: str,
    retries: int = 3,
    backoff: float = 1.0,
    **kwargs,
) -> aiohttp.ClientResponse | None:
    """GET request with exponential backoff on 429/5xx errors."""
    for attempt in range(retries + 1):
        try:
            resp = await session.get(url, **kwargs)
            if resp.status == 429 or resp.status >= 500:
                if attempt < retries:
                    wait = backoff * (2 ** attempt)
                    log.debug(f"Retry {attempt+1}/{retries} for {url} (HTTP {resp.status}), waiting {wait}s")
                    await asyncio.sleep(wait)
                    continue
            return resp
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            if attempt < retries:
                wait = backoff * (2 ** attempt)
                log.debug(f"Retry {attempt+1}/{retries} for {url} ({e}), waiting {wait}s")
                await asyncio.sleep(wait)
            else:
                raise
    return None


# ─────────────────────────────────────────────────────────────────────────────
# SQLITE DATABASE STORAGE
# ─────────────────────────────────────────────────────────────────────────────

class SubReconDB:
    """SQLite storage for scan history and diff tracking."""

    def __init__(self, db_path: str = "results/subrecon.db"):
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(db_path)
        self._init_tables()

    def _init_tables(self):
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                total_subdomains INTEGER DEFAULT 0,
                resolved_count INTEGER DEFAULT 0,
                live_count INTEGER DEFAULT 0,
                elapsed REAL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS subdomains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                subdomain TEXT NOT NULL,
                source TEXT DEFAULT '',
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            );
            CREATE INDEX IF NOT EXISTS idx_domain ON scans(domain);
            CREATE INDEX IF NOT EXISTS idx_sub ON subdomains(subdomain);
        """)
        self.conn.commit()

    def save_scan(
        self,
        domain: str,
        subdomains: set[str],
        source_results: dict[str, set[str]],
        resolved_count: int,
        live_count: int,
        elapsed: float,
    ) -> int:
        """Save a scan and return the scan ID."""
        cur = self.conn.execute(
            "INSERT INTO scans (domain, timestamp, total_subdomains, resolved_count, live_count, elapsed) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (domain, datetime.now(timezone.utc).isoformat(), len(subdomains), resolved_count, live_count, elapsed),
        )
        scan_id = cur.lastrowid

        # Build subdomain → sources mapping
        sub_sources: dict[str, list[str]] = {}
        for source, subs in source_results.items():
            for s in subs:
                sub_sources.setdefault(s, []).append(source)

        rows = []
        for sub in sorted(subdomains):
            sources_str = ",".join(sub_sources.get(sub, ["unknown"]))
            rows.append((scan_id, sub, sources_str))

        self.conn.executemany(
            "INSERT INTO subdomains (scan_id, subdomain, source) VALUES (?, ?, ?)",
            rows,
        )
        self.conn.commit()
        return scan_id

    def get_previous_subdomains(self, domain: str) -> set[str]:
        """Get all subdomains from the previous scan of this domain."""
        row = self.conn.execute(
            "SELECT id FROM scans WHERE domain = ? ORDER BY id DESC LIMIT 1 OFFSET 1",
            (domain,),
        ).fetchone()
        if not row:
            return set()
        rows = self.conn.execute(
            "SELECT subdomain FROM subdomains WHERE scan_id = ?",
            (row[0],),
        ).fetchall()
        return {r[0] for r in rows}

    def get_new_subdomains(self, domain: str, current: set[str]) -> set[str]:
        """Return subdomains that are new compared to the previous scan."""
        previous = self.get_previous_subdomains(domain)
        if not previous:
            return current  # First scan = all are new
        return current - previous

    def close(self):
        self.conn.close()


# ─────────────────────────────────────────────────────────────────────────────
# NOTIFICATION SUPPORT
# ─────────────────────────────────────────────────────────────────────────────

class Notifier:
    """Send scan notifications to Discord, Slack, or Telegram."""

    def __init__(
        self,
        discord_webhook: str = "",
        slack_webhook: str = "",
        telegram_token: str = "",
        telegram_chat_id: str = "",
    ):
        self.discord_webhook = discord_webhook
        self.slack_webhook = slack_webhook
        self.telegram_token = telegram_token
        self.telegram_chat_id = telegram_chat_id

    @property
    def enabled(self) -> bool:
        return bool(self.discord_webhook or self.slack_webhook or (self.telegram_token and self.telegram_chat_id))

    async def send(
        self,
        domain: str,
        total: int,
        resolved: int,
        live: int,
        new_count: int | None = None,
        elapsed: float = 0,
    ):
        """Send scan summary to all configured channels."""
        new_str = f"\n🆕 New subdomains: {new_count}" if new_count is not None else ""
        summary = (
            f"🔍 SubRecon Scan Complete\n"
            f"🎯 Domain: {domain}\n"
            f"📊 Subdomains: {total}\n"
            f"🌐 DNS Resolved: {resolved}\n"
            f"✅ Live Hosts: {live}{new_str}\n"
            f"⏱️ Time: {elapsed:.1f}s"
        )

        tasks = []
        if self.discord_webhook:
            tasks.append(self._send_discord(summary))
        if self.slack_webhook:
            tasks.append(self._send_slack(summary))
        if self.telegram_token and self.telegram_chat_id:
            tasks.append(self._send_telegram(summary))

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _send_discord(self, message: str):
        try:
            async with aiohttp.ClientSession() as session:
                payload = {"content": message}
                async with session.post(self.discord_webhook, json=payload) as resp:
                    if resp.status not in (200, 204):
                        log.debug(f"Discord notification failed: HTTP {resp.status}")
        except Exception as e:
            log.debug(f"Discord notification error: {e}")

    async def _send_slack(self, message: str):
        try:
            async with aiohttp.ClientSession() as session:
                payload = {"text": message}
                async with session.post(self.slack_webhook, json=payload) as resp:
                    if resp.status != 200:
                        log.debug(f"Slack notification failed: HTTP {resp.status}")
        except Exception as e:
            log.debug(f"Slack notification error: {e}")

    async def _send_telegram(self, message: str):
        try:
            url = f"https://api.telegram.org/bot{self.telegram_token}/sendMessage"
            async with aiohttp.ClientSession() as session:
                payload = {"chat_id": self.telegram_chat_id, "text": message}
                async with session.post(url, json=payload) as resp:
                    if resp.status != 200:
                        log.debug(f"Telegram notification failed: HTTP {resp.status}")
        except Exception as e:
            log.debug(f"Telegram notification error: {e}")


# ─────────────────────────────────────────────────────────────────────────────
# UTILITY FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────

def is_valid_subdomain(sub: str, domain: str) -> bool:
    """Validate that a string is a proper subdomain of the target domain."""
    sub = sub.strip().lower().lstrip("*.")
    if not sub:
        return False
    if not sub.endswith("." + domain) and sub != domain:
        return False
    if not SUBDOMAIN_REGEX.match(sub):
        return False
    return True


def clean_subdomain(raw: str) -> str:
    """Clean and normalize a raw subdomain string."""
    s = raw.strip().lower()
    s = re.sub(r"^https?://", "", s)
    s = re.sub(r"[/:].*$", "", s)
    s = s.lstrip("*.")
    s = s.strip(".")
    return s


def tool_exists(name: str) -> bool:
    """Check if a CLI tool is available on PATH."""
    return shutil.which(name) is not None


def get_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


# ─────────────────────────────────────────────────────────────────────────────
# CLI TOOL RUNNERS
# ─────────────────────────────────────────────────────────────────────────────

class CLIToolRunner:
    """Runs external CLI tools and collects subdomain results."""

    def __init__(self, domain: str, output_dir: Path, timeout: int = 300,
                 github_token: str = "", gitlab_token: str = "",
                 shodan_key: str = "", wordlist: str = "",
                 resolvers_file: str = "", subfinder_config: str = ""):
        self.domain = domain
        self.output_dir = output_dir
        self.timeout = timeout
        self.github_token = github_token
        self.gitlab_token = gitlab_token
        self.shodan_key = shodan_key
        self.wordlist = wordlist
        self.resolvers_file = resolvers_file
        self.subfinder_config = subfinder_config
        self.results: dict[str, set[str]] = {}
        self.errors: dict[str, str] = {}  # source → error reason

    async def _run(self, name: str, cmd: list[str], parse_file: Optional[str] = None) -> set[str]:
        """Run a CLI tool and return discovered subdomains."""
        if not tool_exists(cmd[0]):
            self.errors[name] = "not found on PATH"
            log.warning(f"[skip] {name} not found on PATH")
            return set()

        subs = set()
        outfile = parse_file or str(self.output_dir / f"{name}-raw.txt")

        try:
            log.info(f"[run] {name}: {' '.join(cmd)}")
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=self.timeout
            )

            # Parse stdout
            if stdout:
                for line in stdout.decode(errors="ignore").splitlines():
                    cleaned = clean_subdomain(line)
                    if is_valid_subdomain(cleaned, self.domain):
                        subs.add(cleaned)

            # Also parse output file if it exists
            if parse_file and os.path.isfile(parse_file):
                with open(parse_file, "r", errors="ignore") as f:
                    for line in f:
                        cleaned = clean_subdomain(line)
                        if is_valid_subdomain(cleaned, self.domain):
                            subs.add(cleaned)

        except asyncio.TimeoutError:
            self.errors[name] = f"timeout ({self.timeout}s)"
            log.warning(f"[timeout] {name} exceeded {self.timeout}s")
        except Exception as e:
            self.errors[name] = str(e)[:60]
            log.warning(f"[error] {name}: {e}")

        self.results[name] = subs
        return subs

    async def run_subfinder(self) -> set[str]:
        outfile = str(self.output_dir / "subfinder-raw.txt")
        cmd = ["subfinder", "-d", self.domain, "-all", "-o", outfile]
        if self.subfinder_config and os.path.isfile(self.subfinder_config):
            cmd.extend(["-pc", self.subfinder_config])
        return await self._run("subfinder", cmd, parse_file=outfile)

    async def run_amass(self) -> set[str]:
        outfile = str(self.output_dir / "amass-raw.txt")
        cmd = ["amass", "enum", "-passive", "-norecursive", "-noalts",
               "-d", self.domain, "-o", outfile]
        return await self._run("amass", cmd, parse_file=outfile)

    async def run_assetfinder(self) -> set[str]:
        cmd = ["assetfinder", "-subs-only", self.domain]
        return await self._run("assetfinder", cmd)

    async def run_chaos(self) -> set[str]:
        outfile = str(self.output_dir / "chaos-raw.txt")
        cmd = ["chaos", "-d", self.domain, "-o", outfile]
        return await self._run("chaos", cmd, parse_file=outfile)

    async def run_findomain(self) -> set[str]:
        outfile = str(self.output_dir / "findomain-raw.txt")
        cmd = ["findomain", "-t", self.domain, "-u", outfile]
        return await self._run("findomain", cmd, parse_file=outfile)

    async def run_haktrails(self) -> set[str]:
        """echo domain | haktrails subdomains"""
        if not tool_exists("haktrails"):
            self.errors["haktrails"] = "not found on PATH"
            log.warning("[skip] haktrails not found on PATH")
            return set()

        subs = set()
        try:
            proc = await asyncio.create_subprocess_shell(
                f'echo {self.domain} | haktrails subdomains',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=self.timeout)
            if stdout:
                for line in stdout.decode(errors="ignore").splitlines():
                    cleaned = clean_subdomain(line)
                    if is_valid_subdomain(cleaned, self.domain):
                        subs.add(cleaned)
        except Exception as e:
            self.errors["haktrails"] = str(e)[:60]
            log.warning(f"[error] haktrails: {e}")

        self.results["haktrails"] = subs
        return subs

    async def run_gau(self) -> set[str]:
        """echo domain | gau → extract subdomains via regex"""
        if not tool_exists("gau"):
            self.errors["gau"] = "not found on PATH"
            log.warning("[skip] gau not found on PATH")
            return set()

        subs = set()
        pattern = re.compile(
            rf"[a-zA-Z0-9._-]+\.{re.escape(self.domain)}", re.I
        )
        try:
            proc = await asyncio.create_subprocess_shell(
                f'echo {self.domain} | gau',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=self.timeout)
            if stdout:
                for match in pattern.findall(stdout.decode(errors="ignore")):
                    cleaned = clean_subdomain(match)
                    if is_valid_subdomain(cleaned, self.domain):
                        subs.add(cleaned)
        except Exception as e:
            self.errors["gau"] = str(e)[:60]
            log.warning(f"[error] gau: {e}")

        self.results["gau"] = subs
        return subs

    async def run_github_subdomains(self) -> set[str]:
        if not self.github_token:
            self.errors["github-subdomains"] = "no GITHUB_TOKEN set"
            log.warning("[skip] github-subdomains: no GITHUB_TOKEN set")
            return set()
        cmd = ["github-subdomains", "-d", self.domain, "-t", self.github_token]
        return await self._run("github-subdomains", cmd)

    async def run_gitlab_subdomains(self) -> set[str]:
        if not self.gitlab_token:
            self.errors["gitlab-subdomains"] = "no GITLAB_TOKEN set"
            log.warning("[skip] gitlab-subdomains: no GITLAB_TOKEN set")
            return set()
        cmd = ["gitlab-subdomains", "-d", self.domain, "-t", self.gitlab_token]
        return await self._run("gitlab-subdomains", cmd)

    async def run_cero(self) -> set[str]:
        cmd = ["cero", self.domain]
        return await self._run("cero", cmd)

    async def run_shosubgo(self) -> set[str]:
        if not self.shodan_key:
            self.errors["shosubgo"] = "no SHODAN_KEY set"
            log.warning("[skip] shosubgo: no SHODAN_KEY set")
            return set()
        cmd = ["shosubgo", "-d", self.domain, "-s", self.shodan_key]
        return await self._run("shosubgo", cmd)

    async def run_puredns(self) -> set[str]:
        if not self.wordlist or not os.path.isfile(self.wordlist):
            self.errors["puredns"] = "no wordlist file provided"
            log.warning("[skip] puredns: no wordlist file provided")
            return set()
        cmd = ["puredns", "bruteforce", self.wordlist, self.domain, "-q"]
        if self.resolvers_file and os.path.isfile(self.resolvers_file):
            cmd.extend(["--resolvers", self.resolvers_file])
        return await self._run("puredns", cmd)

    async def run_all(self) -> dict[str, set[str]]:
        """Run all CLI tools concurrently."""
        tasks = [
            self.run_subfinder(),
            self.run_amass(),
            self.run_assetfinder(),
            self.run_chaos(),
            self.run_findomain(),
            self.run_haktrails(),
            self.run_gau(),
            self.run_github_subdomains(),
            self.run_gitlab_subdomains(),
            self.run_cero(),
            self.run_shosubgo(),
            self.run_puredns(),
        ]
        await asyncio.gather(*tasks, return_exceptions=True)
        return self.results


# ─────────────────────────────────────────────────────────────────────────────
# API / CURL SOURCE FETCHERS
# ─────────────────────────────────────────────────────────────────────────────

class APIFetcher:
    """Fetches subdomains from all API / curl-based sources."""

    def __init__(self, domain: str, timeout: int = 30,
                 vt_api_key: str = "", securitytrails_key: str = ""):
        self.domain = domain
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.vt_api_key = vt_api_key
        self.securitytrails_key = securitytrails_key
        self.results: dict[str, set[str]] = {}
        self.errors: dict[str, str] = {}  # source → error reason
        self.headers = {"User-Agent": USER_AGENT}

    def _extract(self, raw_list: list[str]) -> set[str]:
        subs = set()
        for item in raw_list:
            cleaned = clean_subdomain(item)
            if is_valid_subdomain(cleaned, self.domain):
                subs.add(cleaned)
        return subs

    async def fetch_crtsh(self, session: aiohttp.ClientSession) -> set[str]:
        """Certificate Transparency via crt.sh (dedicated 30s timeout)"""
        url = f"https://crt.sh/?q=%25.{self.domain}&output=json"
        subs = set()
        # crt.sh is slow but very valuable — use a dedicated 30s timeout
        crtsh_timeout = aiohttp.ClientTimeout(total=30)
        try:
            async with aiohttp.ClientSession(
                headers=self.headers, timeout=crtsh_timeout,
                connector=aiohttp.TCPConnector(ssl=False)
            ) as crt_session:
                resp = await retry_request(crt_session, url, ssl=False)
                if resp and resp.status == 200:
                    data = await resp.json(content_type=None)
                    for entry in data:
                        name_value = entry.get("name_value", "")
                        for name in name_value.split("\n"):
                            cleaned = clean_subdomain(name)
                            if is_valid_subdomain(cleaned, self.domain):
                                subs.add(cleaned)
                elif resp:
                    self.errors["crt.sh"] = f"HTTP {resp.status}"
        except asyncio.TimeoutError:
            self.errors["crt.sh"] = "timeout (30s)"
            log.warning("[error] crt.sh: timeout after 30s")
        except Exception as e:
            self.errors["crt.sh"] = str(e)[:60]
            log.warning(f"[error] crt.sh: {e}")
        self.results["crt.sh"] = subs
        return subs

    async def fetch_jldc(self, session: aiohttp.ClientSession) -> set[str]:
        """JLDC / Anubis API"""
        url = f"https://jldc.me/anubis/subdomains/{self.domain}"
        subs = set()
        try:
            resp = await retry_request(session, url, ssl=False)
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                if isinstance(data, list):
                    subs = self._extract(data)
        except Exception as e:
            self.errors["jldc"] = str(e)[:60]
            log.warning(f"[error] jldc: {e}")
        self.results["jldc"] = subs
        return subs

    async def fetch_alienvault(self, session: aiohttp.ClientSession) -> set[str]:
        """AlienVault OTX"""
        subs = set()
        for page in range(1, 20):
            url = (f"https://otx.alienvault.com/api/v1/indicators/domain/"
                   f"{self.domain}/url_list?limit=500&page={page}")
            try:
                resp = await retry_request(session, url, ssl=False)
                if resp and resp.status == 200:
                    data = await resp.json(content_type=None)
                    url_list = data.get("url_list", [])
                    if not url_list:
                        break
                    for entry in url_list:
                        hostname = entry.get("hostname") or ""
                        if not hostname:
                            continue
                        cleaned = clean_subdomain(hostname)
                        if is_valid_subdomain(cleaned, self.domain):
                            subs.add(cleaned)
                else:
                    break
            except Exception as e:
                self.errors["alienvault"] = str(e)[:60]
                log.warning(f"[error] alienvault page {page}: {e}")
                break
        self.results["alienvault"] = subs
        return subs

    async def fetch_subdomain_center(self, session: aiohttp.ClientSession) -> set[str]:
        """Subdomain Center API"""
        url = f"https://api.subdomain.center/?domain={self.domain}"
        subs = set()
        try:
            resp = await retry_request(session, url, ssl=False)
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                if isinstance(data, list):
                    subs = self._extract(data)
        except Exception as e:
            self.errors["subdomain-center"] = str(e)[:60]
            log.warning(f"[error] subdomain-center: {e}")
        self.results["subdomain-center"] = subs
        return subs

    async def fetch_certspotter(self, session: aiohttp.ClientSession) -> set[str]:
        """CertSpotter API"""
        url = (f"https://api.certspotter.com/v1/issuances?"
               f"domain={self.domain}&include_subdomains=true&expand=dns_names")
        subs = set()
        try:
            resp = await retry_request(session, url, ssl=False)
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                if isinstance(data, list):
                    for entry in data:
                        for name in entry.get("dns_names", []):
                            cleaned = clean_subdomain(name)
                            if is_valid_subdomain(cleaned, self.domain):
                                subs.add(cleaned)
        except Exception as e:
            self.errors["certspotter"] = str(e)[:60]
            log.warning(f"[error] certspotter: {e}")
        self.results["certspotter"] = subs
        return subs

    async def fetch_virustotal(self, session: aiohttp.ClientSession) -> set[str]:
        """VirusTotal API (requires API key)"""
        if not self.vt_api_key:
            self.errors["virustotal"] = "no VT_API_KEY set"
            log.warning("[skip] virustotal: no VT_API_KEY set")
            self.results["virustotal"] = set()
            return set()

        url = (f"https://www.virustotal.com/vtapi/v2/domain/report?"
               f"apikey={self.vt_api_key}&domain={self.domain}")
        subs = set()
        try:
            resp = await retry_request(session, url, ssl=False)
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                for entry in data.get("subdomains", []):
                    full = f"{entry}.{self.domain}" if "." not in entry else entry
                    cleaned = clean_subdomain(full)
                    if is_valid_subdomain(cleaned, self.domain):
                        subs.add(cleaned)
        except Exception as e:
            self.errors["virustotal"] = str(e)[:60]
            log.warning(f"[error] virustotal: {e}")
        self.results["virustotal"] = subs
        return subs

    async def fetch_wayback(self, session: aiohttp.ClientSession) -> set[str]:
        """Wayback Machine CDX API — massive historical dataset, no key needed"""
        url = (f"https://web.archive.org/cdx/search/cdx?"
               f"url=*.{self.domain}&output=json&fl=original&collapse=urlkey&limit=10000")
        subs = set()
        try:
            resp = await retry_request(session, url, ssl=False)
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                # First row is the header ["original"], skip it
                for row in data[1:] if len(data) > 1 else []:
                    if row:
                        raw_url = row[0] if isinstance(row, list) else row
                        # Extract hostname from URL
                        hostname = re.sub(r"^https?://", "", str(raw_url)).split("/")[0].split(":")[0]
                        cleaned = clean_subdomain(hostname)
                        if is_valid_subdomain(cleaned, self.domain):
                            subs.add(cleaned)
            elif resp:
                self.errors["wayback"] = f"HTTP {resp.status}"
        except Exception as e:
            self.errors["wayback"] = str(e)[:60]
            log.warning(f"[error] wayback: {e}")
        self.results["wayback"] = subs
        return subs

    async def fetch_hackertarget(self, session: aiohttp.ClientSession) -> set[str]:
        """HackerTarget API"""
        url = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
        subs = set()
        try:
            resp = await retry_request(session, url, ssl=False)
            if resp and resp.status == 200:
                text = await resp.text()
                if "error" not in text.lower():
                    for line in text.splitlines():
                        hostname = line.split(",")[0]
                        cleaned = clean_subdomain(hostname)
                        if is_valid_subdomain(cleaned, self.domain):
                            subs.add(cleaned)
        except Exception as e:
            self.errors["hackertarget"] = str(e)[:60]
            log.warning(f"[error] hackertarget: {e}")
        self.results["hackertarget"] = subs
        return subs

    async def fetch_rapiddns(self, session: aiohttp.ClientSession) -> set[str]:
        """RapidDNS (HTML scraping)"""
        url = f"https://rapiddns.io/subdomain/{self.domain}?full=1"
        subs = set()
        try:
            resp = await retry_request(session, url, ssl=False)
            if resp and resp.status == 200:
                html = await resp.text()
                if BeautifulSoup:
                    soup = BeautifulSoup(html, "html.parser")
                    for td in soup.find_all("td"):
                        text = td.get_text(strip=True)
                        cleaned = clean_subdomain(text)
                        if is_valid_subdomain(cleaned, self.domain):
                            subs.add(cleaned)
                else:
                    pattern = re.compile(
                        rf"[a-zA-Z0-9._-]+\.{re.escape(self.domain)}"
                    )
                    for match in pattern.findall(html):
                        cleaned = clean_subdomain(match)
                        if is_valid_subdomain(cleaned, self.domain):
                            subs.add(cleaned)
        except Exception as e:
            self.errors["rapiddns"] = str(e)[:60]
            log.warning(f"[error] rapiddns: {e}")
        self.results["rapiddns"] = subs
        return subs

    async def fetch_urlscan(self, session: aiohttp.ClientSession) -> set[str]:
        """URLScan.io API"""
        url = f"https://urlscan.io/api/v1/search/?q=domain:{self.domain}&size=1000"
        subs = set()
        try:
            resp = await retry_request(session, url, ssl=False)
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                for result in data.get("results", []):
                    page = result.get("page", {})
                    domain_val = page.get("domain", "")
                    cleaned = clean_subdomain(domain_val)
                    if is_valid_subdomain(cleaned, self.domain):
                        subs.add(cleaned)
            elif resp:
                self.errors["urlscan"] = f"HTTP {resp.status}"
        except Exception as e:
            self.errors["urlscan"] = str(e)[:60]
            log.warning(f"[error] urlscan: {e}")
        self.results["urlscan"] = subs
        return subs

    async def fetch_commoncrawl(self, session: aiohttp.ClientSession) -> set[str]:
        """CommonCrawl Index API — complements Wayback with different crawl data"""
        subs = set()
        # Try the latest index
        index_url = "https://index.commoncrawl.org/collinfo.json"
        try:
            resp = await retry_request(session, index_url, ssl=False)
            if not resp or resp.status != 200:
                self.errors["commoncrawl"] = "could not fetch index list"
                self.results["commoncrawl"] = subs
                return subs

            indexes = await resp.json(content_type=None)
            if not indexes:
                self.errors["commoncrawl"] = "empty index list"
                self.results["commoncrawl"] = subs
                return subs

            # Use the latest index
            latest_api = indexes[0].get("cdx-api", "")
            if not latest_api:
                self.errors["commoncrawl"] = "no CDX API in latest index"
                self.results["commoncrawl"] = subs
                return subs

            search_url = f"{latest_api}?url=*.{self.domain}&output=json&limit=5000"
            resp2 = await retry_request(session, search_url, ssl=False)
            if resp2 and resp2.status == 200:
                text = await resp2.text()
                for line in text.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        raw_url = entry.get("url", "")
                        hostname = re.sub(r"^https?://", "", raw_url).split("/")[0].split(":")[0]
                        cleaned = clean_subdomain(hostname)
                        if is_valid_subdomain(cleaned, self.domain):
                            subs.add(cleaned)
                    except json.JSONDecodeError:
                        continue
            elif resp2:
                self.errors["commoncrawl"] = f"HTTP {resp2.status}"
        except Exception as e:
            self.errors["commoncrawl"] = str(e)[:60]
            log.warning(f"[error] commoncrawl: {e}")
        self.results["commoncrawl"] = subs
        return subs

    async def fetch_securitytrails(self, session: aiohttp.ClientSession) -> set[str]:
        """SecurityTrails API — direct API call, no CLI needed"""
        if not self.securitytrails_key:
            self.errors["securitytrails"] = "no SECURITYTRAILS_KEY set"
            log.warning("[skip] securitytrails: no SECURITYTRAILS_KEY set")
            self.results["securitytrails"] = set()
            return set()

        url = f"https://api.securitytrails.com/v1/domain/{self.domain}/subdomains"
        subs = set()
        try:
            headers = {"APIKEY": self.securitytrails_key}
            resp = await retry_request(session, url, ssl=False, headers=headers)
            if resp and resp.status == 200:
                data = await resp.json(content_type=None)
                for sub_name in data.get("subdomains", []):
                    full = f"{sub_name}.{self.domain}"
                    cleaned = clean_subdomain(full)
                    if is_valid_subdomain(cleaned, self.domain):
                        subs.add(cleaned)
            elif resp:
                self.errors["securitytrails"] = f"HTTP {resp.status}"
        except Exception as e:
            self.errors["securitytrails"] = str(e)[:60]
            log.warning(f"[error] securitytrails: {e}")
        self.results["securitytrails"] = subs
        return subs

    async def fetch_all(self) -> dict[str, set[str]]:
        """Run all API fetchers concurrently."""
        connector = aiohttp.TCPConnector(limit=20, ssl=False)
        async with aiohttp.ClientSession(
            headers=self.headers, timeout=self.timeout, connector=connector
        ) as session:
            tasks = [
                self.fetch_crtsh(session),
                self.fetch_jldc(session),
                self.fetch_alienvault(session),
                self.fetch_subdomain_center(session),
                self.fetch_certspotter(session),
                self.fetch_virustotal(session),
                self.fetch_wayback(session),
                self.fetch_hackertarget(session),
                self.fetch_rapiddns(session),
                self.fetch_urlscan(session),
                self.fetch_commoncrawl(session),
                self.fetch_securitytrails(session),
            ]
            await asyncio.gather(*tasks, return_exceptions=True)
        return self.results


# ─────────────────────────────────────────────────────────────────────────────
# DNS RESOLVER
# ─────────────────────────────────────────────────────────────────────────────

class DNSResolver:
    """Concurrent DNS resolution with wildcard detection."""

    def __init__(self, domain: str, concurrency: int = 100, timeout: float = 5.0):
        self.domain = domain
        self.concurrency = concurrency
        self.timeout = timeout
        self.wildcard_ips: set[str] = set()
        self.is_wildcard = False

    async def detect_wildcard(self):
        """Check if domain has wildcard DNS by resolving random subdomains."""
        random_subs = [
            f"{''.join(random.choices(string.ascii_lowercase, k=12))}.{self.domain}"
            for _ in range(3)
        ]
        resolved_ips = set()
        for sub in random_subs:
            ips = await self._resolve_one(sub)
            resolved_ips.update(ips)

        if len(resolved_ips) > 0:
            self.is_wildcard = True
            self.wildcard_ips = resolved_ips
            log.warning(f"[!] Wildcard DNS detected! IPs: {resolved_ips}")

    async def _resolve_one(self, subdomain: str) -> list[str]:
        """Resolve a single subdomain to IP addresses."""
        loop = asyncio.get_event_loop()
        try:
            result = await asyncio.wait_for(
                loop.getaddrinfo(subdomain, None, family=socket.AF_INET),
                timeout=self.timeout,
            )
            return list({addr[4][0] for addr in result})
        except Exception:
            return []

    async def resolve_all(self, subdomains: set[str]) -> dict[str, list[str]]:
        """Resolve all subdomains concurrently. Returns {sub: [ips]}."""
        await self.detect_wildcard()

        sem = asyncio.Semaphore(self.concurrency)
        resolved = {}

        async def _resolve(sub: str):
            async with sem:
                ips = await self._resolve_one(sub)
                if ips:
                    # Filter wildcard IPs
                    if self.is_wildcard:
                        non_wildcard = [ip for ip in ips if ip not in self.wildcard_ips]
                        if non_wildcard:
                            resolved[sub] = non_wildcard
                    else:
                        resolved[sub] = ips

        tasks = [_resolve(sub) for sub in subdomains]
        await asyncio.gather(*tasks, return_exceptions=True)
        return resolved


# ─────────────────────────────────────────────────────────────────────────────
# HTTP PROBER
# ─────────────────────────────────────────────────────────────────────────────

class HTTPProber:
    """Probe subdomains for live HTTP(S) responses using projectdiscovery/httpx."""

    def __init__(self, concurrency: int = 50, timeout: int = 10):
        self.concurrency = concurrency
        self.timeout = timeout

    async def probe_all(self, subdomains: set[str]) -> list[dict]:
        """Probe all subdomains using the httpx CLI tool."""
        if not subdomains:
            return []

        if not tool_exists("httpx"):
            log.warning("[!] httpx not found on PATH – falling back to aiohttp prober")
            return await self._fallback_probe(subdomains)

        # Write targets to a temp file for httpx to consume
        import tempfile
        tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False, encoding="utf-8"
        )
        try:
            for sub in sorted(subdomains):
                tmp.write(sub + "\n")
            tmp.close()

            cmd = [
                "httpx",
                "-l", tmp.name,
                "-json",
                "-title",
                "-server",
                "-status-code",
                "-content-length",
                "-follow-redirects",
                "-threads", str(self.concurrency),
                "-timeout", str(self.timeout),
                "-silent",
            ]

            log.info(f"[*] Running httpx on {len(subdomains)} targets ...")
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()

            if stderr:
                err_text = stderr.decode(errors="ignore").strip()
                if err_text:
                    log.debug(f"[httpx stderr] {err_text[:500]}")

            results: list[dict] = []
            for line in stdout.decode(errors="ignore").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue

                url = entry.get("url", "")
                scheme = "https" if url.startswith("https") else "http"

                results.append({
                    "subdomain": entry.get("input", entry.get("host", "")),
                    "url": url,
                    "status": entry.get("status_code", entry.get("status-code", 0)),
                    "title": (entry.get("title", "") or "")[:100],
                    "server": entry.get("webserver", entry.get("server", "")),
                    "content_length": str(entry.get("content_length", entry.get("content-length", ""))),
                    "scheme": scheme,
                })

            results.sort(key=lambda x: (x["status"], x["subdomain"]))
            log.info(f"[+] httpx found {len(results)} live hosts")
            return results

        finally:
            try:
                os.unlink(tmp.name)
            except OSError:
                pass

    # ── Fallback: aiohttp-based prober (used when httpx is not installed) ──

    async def _fallback_probe_one(
        self, session: aiohttp.ClientSession, subdomain: str
    ) -> Optional[dict]:
        """Probe a single subdomain on HTTP and HTTPS (fallback)."""
        for scheme in ("https", "http"):
            url = f"{scheme}://{subdomain}"
            try:
                async with session.get(url, ssl=False, allow_redirects=True) as resp:
                    body = await resp.text(errors="ignore")
                    title_match = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
                    title = title_match.group(1).strip()[:100] if title_match else ""
                    return {
                        "subdomain": subdomain,
                        "url": str(resp.url),
                        "status": resp.status,
                        "title": title,
                        "server": resp.headers.get("Server", ""),
                        "content_length": resp.headers.get("Content-Length", ""),
                        "scheme": scheme,
                    }
            except Exception:
                continue
        return None

    async def _fallback_probe(self, subdomains: set[str]) -> list[dict]:
        """Probe all subdomains using aiohttp (fallback when httpx is absent)."""
        sem = asyncio.Semaphore(self.concurrency)
        results: list[dict] = []
        timeout = aiohttp.ClientTimeout(total=self.timeout)

        connector = aiohttp.TCPConnector(limit=self.concurrency, ssl=False)
        async with aiohttp.ClientSession(
            timeout=timeout, connector=connector,
            headers={"User-Agent": USER_AGENT}
        ) as session:
            async def _probe(sub):
                async with sem:
                    result = await self._fallback_probe_one(session, sub)
                    if result:
                        results.append(result)

            tasks = [_probe(sub) for sub in subdomains]
            await asyncio.gather(*tasks, return_exceptions=True)

        results.sort(key=lambda x: (x["status"], x["subdomain"]))
        return results


# ─────────────────────────────────────────────────────────────────────────────
# RESOLVERS DOWNLOADER
# ─────────────────────────────────────────────────────────────────────────────

async def download_trickest_resolvers(output_dir: Path) -> str:
    """Download fresh resolvers from Trickest GitHub repo."""
    url = "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt"
    filepath = output_dir / "resolvers.txt"
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, ssl=False) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    filepath.write_text(text)
                    log.info(f"[+] Downloaded {len(text.splitlines())} resolvers")
                    return str(filepath)
    except Exception as e:
        log.warning(f"[error] downloading resolvers: {e}")
    return ""


# ─────────────────────────────────────────────────────────────────────────────
# OUTPUT WRITERS
# ─────────────────────────────────────────────────────────────────────────────

def write_txt(subdomains: set[str], filepath: Path):
    """Write subdomains to a plain text file, one per line."""
    with open(filepath, "w") as f:
        for sub in sorted(subdomains):
            f.write(sub + "\n")


def write_json(data: dict, filepath: Path):
    """Write full results as JSON."""
    # Convert sets to lists for JSON serialization
    serializable = {}
    for key, value in data.items():
        if isinstance(value, set):
            serializable[key] = sorted(list(value))
        elif isinstance(value, dict):
            serializable[key] = {
                k: sorted(list(v)) if isinstance(v, set) else v
                for k, v in value.items()
            }
        else:
            serializable[key] = value
    with open(filepath, "w") as f:
        json.dump(serializable, f, indent=2, default=str)


def write_csv(subdomains: set[str], resolved: dict[str, list[str]],
              probed: list[dict], filepath: Path):
    """Write results as CSV."""
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Subdomain", "IP Addresses", "Status", "Title", "Server", "URL"])
        probed_map = {p["subdomain"]: p for p in probed}
        for sub in sorted(subdomains):
            ips = ", ".join(resolved.get(sub, []))
            p = probed_map.get(sub, {})
            writer.writerow([
                sub,
                ips,
                p.get("status", ""),
                p.get("title", ""),
                p.get("server", ""),
                p.get("url", ""),
            ])


# ─────────────────────────────────────────────────────────────────────────────
# HTML REPORT GENERATOR
# ─────────────────────────────────────────────────────────────────────────────

def generate_html_report(
    domain: str,
    all_subdomains: set[str],
    source_results: dict[str, set[str]],
    resolved: dict[str, list[str]],
    probed: list[dict],
    elapsed: float,
    filepath: Path,
):
    """Generate a self-contained dark-themed HTML report."""

    # Source stats table rows
    source_rows = ""
    for src, subs in sorted(source_results.items(), key=lambda x: -len(x[1])):
        count = len(subs)
        bar_width = int((count / max(len(all_subdomains), 1)) * 100)
        source_rows += f"""
        <tr>
          <td class="src-name">{src}</td>
          <td class="src-count">{count}</td>
          <td><div class="bar-bg"><div class="bar-fill" style="width:{bar_width}%"></div></div></td>
        </tr>"""

    # Probed results table rows
    probed_rows = ""
    for p in probed:
        status = p["status"]
        if 200 <= status < 300:
            status_class = "status-2xx"
        elif 300 <= status < 400:
            status_class = "status-3xx"
        elif 400 <= status < 500:
            status_class = "status-4xx"
        else:
            status_class = "status-5xx"
        probed_rows += f"""
        <tr>
          <td><a href="{p['url']}" target="_blank">{p['subdomain']}</a></td>
          <td class="{status_class}">{status}</td>
          <td>{p['title']}</td>
          <td>{p['server']}</td>
        </tr>"""

    # All subdomains list
    all_subs_list = "\n".join(f"<li>{s}</li>" for s in sorted(all_subdomains))

    # Stats
    total = len(all_subdomains)
    resolved_count = len(resolved)
    live_count = len(probed)
    sources_count = len(source_results)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SubRecon Report – {domain}</title>
<style>
  :root {{
    --bg: #0a0e17;
    --surface: #111827;
    --surface2: #1a2332;
    --border: rgba(56, 189, 248, 0.08);
    --text: #e2e8f0;
    --text-dim: #64748b;
    --accent: #38bdf8;
    --accent2: #818cf8;
    --green: #34d399;
    --yellow: #fbbf24;
    --red: #f87171;
    --orange: #fb923c;
  }}
  * {{ margin:0; padding:0; box-sizing:border-box; }}
  body {{
    font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
    background: var(--bg);
    color: var(--text);
    line-height: 1.6;
  }}
  .container {{ max-width: 1200px; margin: 0 auto; padding: 24px; }}

  /* Header */
  .header {{
    text-align: center;
    padding: 48px 24px 32px;
    background: linear-gradient(135deg, rgba(56,189,248,0.05) 0%, rgba(129,140,248,0.05) 100%);
    border-bottom: 1px solid var(--border);
    margin-bottom: 32px;
  }}
  .header h1 {{
    font-size: 2.5rem;
    background: linear-gradient(135deg, var(--accent), var(--accent2));
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    margin-bottom: 8px;
  }}
  .header .domain {{ font-size: 1.2rem; color: var(--accent); font-family: monospace; }}
  .header .meta {{ color: var(--text-dim); font-size: 0.85rem; margin-top: 12px; }}

  /* Stats Cards */
  .stats {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 16px;
    margin-bottom: 32px;
  }}
  .stat-card {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 24px;
    text-align: center;
  }}
  .stat-card .value {{
    font-size: 2.2rem;
    font-weight: 700;
    background: linear-gradient(135deg, var(--accent), var(--accent2));
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
  }}
  .stat-card .label {{ color: var(--text-dim); font-size: 0.85rem; text-transform: uppercase; letter-spacing: 1px; margin-top: 4px; }}

  /* Sections */
  .section {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 24px;
    margin-bottom: 24px;
  }}
  .section h2 {{
    font-size: 1.3rem;
    color: var(--accent);
    margin-bottom: 16px;
    padding-bottom: 8px;
    border-bottom: 1px solid var(--border);
  }}

  /* Tables */
  table {{ width: 100%; border-collapse: collapse; }}
  th {{
    text-align: left;
    padding: 10px 12px;
    color: var(--text-dim);
    font-size: 0.8rem;
    text-transform: uppercase;
    letter-spacing: 1px;
    border-bottom: 1px solid var(--border);
  }}
  td {{
    padding: 8px 12px;
    border-bottom: 1px solid rgba(255,255,255,0.03);
    font-size: 0.9rem;
  }}
  tr:hover {{ background: rgba(56,189,248,0.03); }}
  a {{ color: var(--accent); text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}

  /* Status badges */
  .status-2xx {{ color: var(--green); font-weight: 700; }}
  .status-3xx {{ color: var(--accent); font-weight: 700; }}
  .status-4xx {{ color: var(--orange); font-weight: 700; }}
  .status-5xx {{ color: var(--red); font-weight: 700; }}

  /* Source bars */
  .src-name {{ font-weight: 600; color: var(--accent); }}
  .src-count {{ font-weight: 700; font-family: monospace; }}
  .bar-bg {{ background: var(--surface2); border-radius: 4px; height: 8px; width: 100%; }}
  .bar-fill {{ background: linear-gradient(90deg, var(--accent), var(--accent2)); height: 100%; border-radius: 4px; transition: width 0.3s; }}

  /* Subdomain list */
  .subs-list {{
    columns: 3;
    column-gap: 24px;
    list-style: none;
    max-height: 500px;
    overflow-y: auto;
    font-family: monospace;
    font-size: 0.85rem;
  }}
  .subs-list li {{
    padding: 3px 0;
    color: var(--text-dim);
    break-inside: avoid;
  }}

  /* Search */
  .search-box {{
    width: 100%;
    padding: 10px 16px;
    background: var(--surface2);
    border: 1px solid var(--border);
    border-radius: 8px;
    color: var(--text);
    font-size: 0.9rem;
    margin-bottom: 16px;
    outline: none;
  }}
  .search-box:focus {{ border-color: var(--accent); }}

  /* Responsive */
  @media (max-width: 768px) {{
    .subs-list {{ columns: 1; }}
    .header h1 {{ font-size: 1.8rem; }}
  }}
</style>
</head>
<body>
<div class="header">
  <h1>SubRecon Report</h1>
  <div class="domain">{domain}</div>
  <div class="meta">Generated on {get_timestamp()} │ Scan duration: {elapsed:.1f}s</div>
</div>

<div class="container">
  <!-- Stats -->
  <div class="stats">
    <div class="stat-card"><div class="value">{total}</div><div class="label">Total Subdomains</div></div>
    <div class="stat-card"><div class="value">{resolved_count}</div><div class="label">DNS Resolved</div></div>
    <div class="stat-card"><div class="value">{live_count}</div><div class="label">Live Hosts</div></div>
    <div class="stat-card"><div class="value">{sources_count}</div><div class="label">Sources Used</div></div>
  </div>

  <!-- Source Breakdown -->
  <div class="section">
    <h2>Source Breakdown</h2>
    <table>
      <thead><tr><th>Source</th><th>Found</th><th>Coverage</th></tr></thead>
      <tbody>{source_rows}</tbody>
    </table>
  </div>

  <!-- Live Hosts -->
  <div class="section">
    <h2>Live Hosts ({live_count})</h2>
    <input type="text" class="search-box" id="probeSearch"
           placeholder="Filter live hosts..." onkeyup="filterProbed()">
    <table id="probeTable">
      <thead><tr><th>Subdomain</th><th>Status</th><th>Title</th><th>Server</th></tr></thead>
      <tbody>{probed_rows}</tbody>
    </table>
  </div>

  <!-- All Subdomains -->
  <div class="section">
    <h2>All Subdomains ({total})</h2>
    <input type="text" class="search-box" id="subSearch"
           placeholder="Search subdomains..." onkeyup="filterSubs()">
    <ul class="subs-list" id="subsList">{all_subs_list}</ul>
  </div>
</div>

<script>
function filterProbed() {{
  const q = document.getElementById('probeSearch').value.toLowerCase();
  document.querySelectorAll('#probeTable tbody tr').forEach(r => {{
    r.style.display = r.textContent.toLowerCase().includes(q) ? '' : 'none';
  }});
}}
function filterSubs() {{
  const q = document.getElementById('subSearch').value.toLowerCase();
  document.querySelectorAll('#subsList li').forEach(li => {{
    li.style.display = li.textContent.toLowerCase().includes(q) ? '' : 'none';
  }});
}}
</script>
</body>
</html>"""

    filepath.write_text(html, encoding="utf-8")


# ─────────────────────────────────────────────────────────────────────────────
# TERMINAL UI
# ─────────────────────────────────────────────────────────────────────────────

def print_source_table(source_results: dict[str, set[str]], total: int,
                       errors: dict[str, str] | None = None):
    """Print a rich table showing results per source."""
    errors = errors or {}
    table = Table(
        title="[bold cyan]Source Results[/bold cyan]",
        box=box.ROUNDED,
        border_style="dim",
        show_lines=False,
        pad_edge=True,
    )
    table.add_column("Source", style="cyan", min_width=20)
    table.add_column("Found", justify="right", style="bold white", min_width=8)
    table.add_column("Status", min_width=10)
    table.add_column("Reason", style="dim", min_width=20)

    for name, subs in sorted(source_results.items(), key=lambda x: -len(x[1])):
        count = len(subs)
        if count > 0:
            status = f"[green]✓ {count}[/green]"
            reason = ""
        else:
            err = errors.get(name, "")
            if err:
                status = "[yellow]⚠ 0[/yellow]"
                reason = f"[dim yellow]{err}[/dim yellow]"
            else:
                status = "[dim red]✗ 0[/dim red]"
                reason = ""
        table.add_row(name, str(count), status, reason)

    table.add_section()
    table.add_row("[bold]TOTAL (deduplicated)[/bold]", f"[bold green]{total}[/bold green]", "", "")
    console.print(table)


def print_probe_table(probed: list[dict]):
    """Print a rich table showing live hosts."""
    if not probed:
        console.print("[dim]No live hosts found.[/dim]")
        return

    table = Table(
        title=f"[bold cyan]Live Hosts ({len(probed)})[/bold cyan]",
        box=box.ROUNDED,
        border_style="dim",
    )
    table.add_column("Subdomain", style="cyan", max_width=50)
    table.add_column("Status", justify="center", min_width=8)
    table.add_column("Title", max_width=40)
    table.add_column("Server", style="dim", max_width=20)

    for p in probed[:50]:  # Show top 50 in terminal
        status = p["status"]
        if 200 <= status < 300:
            s_str = f"[green]{status}[/green]"
        elif 300 <= status < 400:
            s_str = f"[blue]{status}[/blue]"
        elif 400 <= status < 500:
            s_str = f"[yellow]{status}[/yellow]"
        else:
            s_str = f"[red]{status}[/red]"
        table.add_row(p["subdomain"], s_str, p["title"][:40], p["server"][:20])

    if len(probed) > 50:
        table.add_row(f"[dim]... and {len(probed) - 50} more (see report)[/dim]", "", "", "")

    console.print(table)


# ─────────────────────────────────────────────────────────────────────────────
# MAIN ORCHESTRATOR
# ─────────────────────────────────────────────────────────────────────────────

async def run(args):
    """Main orchestration pipeline."""
    domain = args.domain.strip().lower()
    start_time = time.time()

    # Setup output directory
    output_dir = Path(args.output) if args.output else Path("results") / domain
    output_dir.mkdir(parents=True, exist_ok=True)

    if not args.silent:
        console.print(BANNER)
        console.print(Panel(
            f"[bold]Target:[/bold] [cyan]{domain}[/cyan]\n"
            f"[bold]Output:[/bold] [dim]{output_dir.resolve()}[/dim]\n"
            f"[bold]Time:[/bold]   [dim]{get_timestamp()}[/dim]",
            title="[bold cyan]Scan Configuration[/bold cyan]",
            border_style="cyan",
        ))

    all_subdomains: set[str] = set()
    all_source_results: dict[str, set[str]] = {}
    resolved: dict[str, list[str]] = {}
    probed: list[dict] = []

    # Count total phases
    total_phases = 2  # API + Output always run
    if not args.no_tools:
        total_phases += 1
    if not args.no_resolve:
        total_phases += 1
    if not args.no_probe:
        total_phases += 1

    if args.silent:
        # ── Silent mode: no UI, just run everything ──
        resolvers_file = args.resolvers
        if not resolvers_file and (args.wordlist or os.environ.get("WORDLIST", "")):
            resolvers_file = await download_trickest_resolvers(output_dir)

        api_fetcher = APIFetcher(domain=domain, timeout=args.timeout,
                                  vt_api_key=args.vt_key or os.environ.get("VT_API_KEY", ""),
                                  securitytrails_key=args.securitytrails_key or os.environ.get("SECURITYTRAILS_KEY", ""))
        api_results = await api_fetcher.fetch_all()
        all_source_results.update(api_results)
        all_errors = dict(api_fetcher.errors)
        for subs in api_results.values():
            all_subdomains.update(subs)

        if not args.no_tools:
            cli_runner = CLIToolRunner(
                domain=domain, output_dir=output_dir, timeout=args.tool_timeout,
                github_token=args.github_token or os.environ.get("GITHUB_TOKEN", ""),
                gitlab_token=args.gitlab_token or os.environ.get("GITLAB_TOKEN", ""),
                shodan_key=args.shodan_key or os.environ.get("SHODAN_KEY", ""),
                wordlist=args.wordlist or os.environ.get("WORDLIST", ""),
                resolvers_file=resolvers_file or "",
                subfinder_config=args.subfinder_config or "",
            )
            cli_results = await cli_runner.run_all()
            all_source_results.update(cli_results)
            all_errors.update(cli_runner.errors)
            for subs in cli_results.values():
                all_subdomains.update(subs)

        if not args.no_resolve and all_subdomains:
            resolver = DNSResolver(domain=domain, concurrency=args.threads, timeout=5.0)
            resolved = await resolver.resolve_all(all_subdomains)

        if not args.no_probe and all_subdomains:
            probe_targets = set(resolved.keys()) if resolved else all_subdomains
            prober = HTTPProber(concurrency=args.threads, timeout=args.timeout)
            probed = await prober.probe_all(probe_targets)

        txt_path = output_dir / "subdomains.txt"
        write_txt(all_subdomains, txt_path)
        for sub in sorted(all_subdomains):
            print(sub)

    else:
        # ── Interactive mode: progress bar ──
        resolvers_file = args.resolvers

        with Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(bar_width=30),
            TextColumn("[bold]{task.completed}/{task.total}[/bold]"),
            TextColumn("[dim]{task.fields[status]}[/dim]"),
            console=console,
            transient=False,
        ) as progress:

            scan_task = progress.add_task("Scanning", total=total_phases, status="Starting...")
            phase = 0

            # Phase: Download resolvers if needed
            if not resolvers_file and (args.wordlist or os.environ.get("WORDLIST", "")):
                progress.update(scan_task, status="Downloading resolvers...")
                resolvers_file = await download_trickest_resolvers(output_dir)

            # Phase: API Sources
            progress.update(scan_task, completed=phase, status="Querying 12 API sources...")
            api_fetcher = APIFetcher(domain=domain, timeout=args.timeout,
                                      vt_api_key=args.vt_key or os.environ.get("VT_API_KEY", ""),
                                      securitytrails_key=args.securitytrails_key or os.environ.get("SECURITYTRAILS_KEY", ""))
            api_results = await api_fetcher.fetch_all()
            all_errors = dict(api_fetcher.errors)
            all_source_results.update(api_results)
            for subs in api_results.values():
                all_subdomains.update(subs)
            phase += 1
            progress.update(scan_task, completed=phase,
                            status=f"APIs done — {sum(len(s) for s in api_results.values())} found")

            # Phase: CLI Tools
            if not args.no_tools:
                progress.update(scan_task, status="Running 12 CLI tools...")
                cli_runner = CLIToolRunner(
                    domain=domain, output_dir=output_dir, timeout=args.tool_timeout,
                    github_token=args.github_token or os.environ.get("GITHUB_TOKEN", ""),
                    gitlab_token=args.gitlab_token or os.environ.get("GITLAB_TOKEN", ""),
                    shodan_key=args.shodan_key or os.environ.get("SHODAN_KEY", ""),
                    wordlist=args.wordlist or os.environ.get("WORDLIST", ""),
                    resolvers_file=resolvers_file or "",
                    subfinder_config=args.subfinder_config or "",
                )
                cli_results = await cli_runner.run_all()
                all_source_results.update(cli_results)
                all_errors.update(cli_runner.errors)
                for subs in cli_results.values():
                    all_subdomains.update(subs)
                phase += 1
                progress.update(scan_task, completed=phase,
                                status=f"CLI done — {len(all_subdomains)} unique total")

            # Phase: DNS Resolution
            if not args.no_resolve and all_subdomains:
                progress.update(scan_task, status=f"Resolving DNS for {len(all_subdomains)} subdomains...")
                resolver = DNSResolver(domain=domain, concurrency=args.threads, timeout=5.0)
                resolved = await resolver.resolve_all(all_subdomains)
                phase += 1
                progress.update(scan_task, completed=phase,
                                status=f"DNS done — {len(resolved)}/{len(all_subdomains)} resolved")

            # Phase: HTTP Probing
            if not args.no_probe and all_subdomains:
                probe_targets = set(resolved.keys()) if resolved else all_subdomains
                progress.update(scan_task, status=f"Probing {len(probe_targets)} hosts...")
                prober = HTTPProber(concurrency=args.threads, timeout=args.timeout)
                probed = await prober.probe_all(probe_targets)
                phase += 1
                progress.update(scan_task, completed=phase,
                                status=f"Probing done — {len(probed)} live hosts")

            # Phase: Save output
            progress.update(scan_task, status="Saving results...")
            txt_path = output_dir / "subdomains.txt"
            write_txt(all_subdomains, txt_path)
            phase += 1
            progress.update(scan_task, completed=phase, status="Complete ✓")

        # ── Final Summary ──
        elapsed = time.time() - start_time
        console.print()
        print_source_table(all_source_results, len(all_subdomains), all_errors)

        # ── Database Storage ──
        new_count = None
        if hasattr(args, '_db') and args._db:
            db: SubReconDB = args._db
            if args.diff:
                new_count = len(db.get_new_subdomains(domain, all_subdomains))
            db.save_scan(domain, all_subdomains, all_source_results,
                         len(resolved), len(probed), elapsed)

        diff_line = ""
        if new_count is not None:
            diff_line = f"\n[bold]New Subdomains    :[/bold]  [yellow]{new_count}[/yellow]"

        console.print(Panel(
            f"[bold]Unique Subdomains :[/bold]  [cyan]{len(all_subdomains)}[/cyan]\n"
            f"[bold]DNS Resolved      :[/bold]  [cyan]{len(resolved)}[/cyan]\n"
            f"[bold]Live Hosts        :[/bold]  [cyan]{len(probed)}[/cyan]\n"
            f"[bold]Scan Time         :[/bold]  [cyan]{elapsed:.1f}s[/cyan]"
            f"{diff_line}",
            title="[bold green]Scan Complete[/bold green]",
            border_style="green",
        ))

        # ── Notifications ──
        if hasattr(args, '_notifier') and args._notifier and args._notifier.enabled:
            await args._notifier.send(
                domain=domain,
                total=len(all_subdomains),
                resolved=len(resolved),
                live=len(probed),
                new_count=new_count,
                elapsed=elapsed,
            )


# ─────────────────────────────────────────────────────────────────────────────
# CLI ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

def main():
    # Load API keys from .env file
    load_dotenv()

    parser = argparse.ArgumentParser(
        description="SubRecon – Comprehensive Subdomain Enumeration Automation",
        usage=argparse.SUPPRESS,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python subenum.py example.com
  python subenum.py --list domains.txt                # Multi-domain scan
  python subenum.py example.com --diff                # Show only new subdomains
  python subenum.py example.com --no-tools            # API sources only
  python subenum.py example.com --silent              # Just print subdomains
  python subenum.py example.com -o ./output --threads 100
  python subenum.py example.com --discord-webhook URL # Send Discord alert
        """
    )

    parser.add_argument("domain", nargs="?", default=None, help="Target domain to enumerate")
    parser.add_argument("--list", dest="domain_list", help="File with one domain per line for multi-domain scan")
    parser.add_argument("-o", "--output", help="Output directory (default: results/<domain>)")
    parser.add_argument("--threads", type=int, default=50, help="Concurrency level (default: 50)")
    parser.add_argument("--timeout", type=int, default=30, help="HTTP/API timeout in seconds (default: 30)")
    parser.add_argument("--tool-timeout", type=int, default=300, help="CLI tool timeout in seconds (default: 300)")

    # Feature flags
    parser.add_argument("--no-resolve", action="store_true", help="Skip DNS resolution")
    parser.add_argument("--no-probe", action="store_true", help="Skip HTTP probing")
    parser.add_argument("--no-tools", action="store_true", help="Skip CLI tools, use API sources only")
    parser.add_argument("--silent", action="store_true", help="Minimal output, just print subdomains")
    parser.add_argument("--diff", action="store_true", help="Show only NEW subdomains since last scan")

    # API Keys
    parser.add_argument("--vt-key", help="VirusTotal API key (or set VT_API_KEY env)")
    parser.add_argument("--github-token", help="GitHub token for github-subdomains (or set GITHUB_TOKEN env)")
    parser.add_argument("--gitlab-token", help="GitLab token for gitlab-subdomains (or set GITLAB_TOKEN env)")
    parser.add_argument("--shodan-key", help="Shodan API key for shosubgo (or set SHODAN_KEY env)")
    parser.add_argument("--securitytrails-key", help="SecurityTrails API key (or set SECURITYTRAILS_KEY env)")

    # Tool configs
    parser.add_argument("--wordlist", help="Wordlist path for puredns bruteforce")
    parser.add_argument("--resolvers", help="Custom resolvers file path (auto-downloads Trickest if not set)")
    parser.add_argument("--subfinder-config", help="Path to subfinder provider-config.yaml")

    # Notifications
    parser.add_argument("--discord-webhook", help="Discord webhook URL for notifications")
    parser.add_argument("--slack-webhook", help="Slack webhook URL for notifications")
    parser.add_argument("--telegram-bot-token", help="Telegram bot token for notifications")
    parser.add_argument("--telegram-chat-id", help="Telegram chat ID for notifications")

    # Verbosity
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose/debug logging")

    args = parser.parse_args()

    # Validate: need either domain or --list
    if not args.domain and not args.domain_list:
        parser.error("Please provide a domain or use --list <file>")

    # Setup logging
    level = logging.DEBUG if args.verbose else logging.CRITICAL
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )

    # Run – avoid deprecation warning on Python 3.14+
    if platform.system() == "Windows" and sys.version_info < (3, 14):
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    # Initialize DB
    db = SubReconDB()
    args._db = db

    # Initialize Notifier
    notifier = Notifier(
        discord_webhook=args.discord_webhook or os.environ.get("DISCORD_WEBHOOK", ""),
        slack_webhook=args.slack_webhook or os.environ.get("SLACK_WEBHOOK", ""),
        telegram_token=args.telegram_bot_token or os.environ.get("TELEGRAM_BOT_TOKEN", ""),
        telegram_chat_id=args.telegram_chat_id or os.environ.get("TELEGRAM_CHAT_ID", ""),
    )
    args._notifier = notifier

    # Build domain list
    domains = []
    if args.domain_list:
        list_path = Path(args.domain_list)
        if not list_path.exists():
            console.print(f"[red][!] Domain list file not found: {args.domain_list}[/red]")
            sys.exit(1)
        with open(list_path, "r") as f:
            for line in f:
                d = line.strip().lower()
                if d and not d.startswith("#"):
                    domains.append(d)
        if not domains:
            console.print("[red][!] No domains found in the list file[/red]")
            sys.exit(1)
    else:
        domains = [args.domain.strip().lower()]

    # Run scans
    if len(domains) == 1:
        args.domain = domains[0]
        asyncio.run(run(args))
    else:
        async def run_multi():
            for i, domain in enumerate(domains, 1):
                if not args.silent:
                    console.print(f"\n[bold magenta]━━━ Scanning {i}/{len(domains)}: {domain} ━━━[/bold magenta]\n")
                args.domain = domain
                args.output = None  # Let each domain use its own default output dir
                await run(args)
        asyncio.run(run_multi())

    # Cleanup
    db.close()


if __name__ == "__main__":
    main()
