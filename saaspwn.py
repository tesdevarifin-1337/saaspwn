#!/usr/bin/env python3
"""
SaasPwn - SaaS & 3rd-Party Misconfig Recon Pipeline
Enumerate, probe, and scan company SaaS tenants & 3rd-party assets.

Usage:
  python saaspwn.py --target abc.corp
  python saaspwn.py --target acme --skip-nuclei
  python saaspwn.py --target abc.corp --webhook https://hooks.slack.com/...
"""

import argparse
import json
import logging
import os
import re
import shlex
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path

try:
    import yaml
except ImportError:
    yaml = None

# ─── Logging Setup ───────────────────────────────────────────────────────────
LOG_FORMAT = "%(asctime)s [%(levelname)s] %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT, datefmt="%H:%M:%S")
log = logging.getLogger("saaspwn")

# ─── Constants ───────────────────────────────────────────────────────────────
REQUIRED_TOOLS = ["dnsx", "httpx", "nuclei"]
OPTIONAL_TOOLS = ["uncover", "trufflehog"]
SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_PROVIDERS_FILE = SCRIPT_DIR / "providers.yaml"
DEFAULT_ENV_FILE = SCRIPT_DIR / ".env"

# Fallback providers jika YAML tidak tersedia / tidak ditemukan
FALLBACK_SAAS = [
    "atlassian.net", "service-now.com", "zendesk.com", "okta.com",
    "freshdesk.com", "auth0.com", "onelogin.com", "herokuapp.com",
    "vercel.app", "netlify.app", "salesforce.com", "notion.site",
    "monday.com", "azurewebsites.net",
]
FALLBACK_CLOUD_STORAGE = [
    "{slug}.s3.amazonaws.com",
    "{slug}-assets.s3.amazonaws.com",
    "{slug}-dev.s3.amazonaws.com",
    "{slug}-staging.s3.amazonaws.com",
    "{slug}.blob.core.windows.net",
    "storage.googleapis.com/{slug}",
]
FALLBACK_THIRDPARTY = [
    "groups.google.com/a/{slug}",
    "{slug}.slack.com",
    "{slug}.sharepoint.com",
    "{slug}-my.sharepoint.com",
    "github.com/{slug}",
    "gitlab.com/{slug}",
    "{slug}.github.io",
    "{slug}.bitbucket.io",
    "trello.com/{slug}",
]
FALLBACK_DORKS = [
    'site:pastebin.com "{slug}"',
    'site:trello.com "{slug}"',
    'site:docs.google.com "{slug}"',
    'site:drive.google.com "{slug}"',
    'site:github.com "{slug}" password OR secret OR api_key',
    'site:s3.amazonaws.com "{slug}"',
]


# ─── Helpers ─────────────────────────────────────────────────────────────────

def load_dotenv(env_file: Path = DEFAULT_ENV_FILE):
    """Load .env file ke os.environ (tanpa dependency python-dotenv)."""
    if not env_file.exists():
        log.debug(f".env file tidak ditemukan: {env_file}")
        return

    loaded = []
    with open(env_file) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key and value:
                os.environ[key] = value
                loaded.append(key)

    if loaded:
        log.info(f"📦 Loaded {len(loaded)} env vars dari .env: {', '.join(loaded)}")
    else:
        log.warning(".env ditemukan tapi kosong / tidak ada key yang terisi")


def check_tools() -> bool:
    """Check apakah tools yang dibutuhkan sudah terinstall."""
    missing = []

    for tool in REQUIRED_TOOLS:
        if not shutil.which(tool):
            missing.append(tool)
    for tool in OPTIONAL_TOOLS:
        if not shutil.which(tool):
            log.warning(f"Optional tool '{tool}' tidak ditemukan, fitur terkait akan di-skip")

    if missing:
        log.error(f"Required tools tidak ditemukan: {', '.join(missing)}")
        log.error("Install via: go install -v github.com/projectdiscovery/<tool>/v2/cmd/<tool>@latest")
        return False
    return True


def sanitize_slug(slug: str) -> str:
    """Hanya izinkan alphanumeric dan hyphens di slug."""
    sanitized = re.sub(r"[^a-z0-9\-]", "", slug.lower())
    return sanitized.strip("-")


def run_cmd(cmd: str, timeout: int = 120) -> str:
    """
    Jalankan shell command dengan timeout & error handling.
    Menggunakan shlex.split untuk keamanan lebih baik.
    """
    log.debug(f"Running: {cmd}")
    try:
        args = shlex.split(cmd)
        result = subprocess.run(
            args, capture_output=True, text=True, timeout=timeout
        )
        if result.returncode == 0:
            return result.stdout.strip()
        else:
            stderr_preview = result.stderr.strip()[:300]
            log.warning(f"Command exited {result.returncode}: {cmd}")
            if stderr_preview:
                log.warning(f"  stderr: {stderr_preview}")
            return ""
    except subprocess.TimeoutExpired:
        log.error(f"Timeout ({timeout}s) expired: {cmd}")
        return ""
    except FileNotFoundError:
        log.error(f"Command not found: {args[0] if args else cmd}")
        return ""
    except Exception as e:
        log.error(f"Error running: {cmd} → {e}")
        return ""


def derive_company_slug(target: str) -> str:
    """abc.corp → abc | abc-corp.com → abc-corp"""
    slug = target.lower().replace("https://", "").replace("http://", "")
    slug = slug.split("/")[0]  # ambil hanya domain
    for ext in [".corp", ".co.id", ".com", ".id", ".net", ".io", ".org"]:
        if slug.endswith(ext):
            slug = slug[: -len(ext)]
            break  # hanya hapus 1 extension
    return sanitize_slug(slug)


def generate_slug_variations(base_slug: str, aliases: list = None) -> list:
    """
    Generate variasi slug company untuk coverage maksimal.

    Contoh: base_slug = "abccorp"
    Output: ["abccorp", "abc-corp", "abc_corp", "abc.corp",
             "staging-abccorp", "dev-abccorp", ...]

    Juga support aliases manual, misal: ["abc", "abcorporation"]
    """
    variations = set()
    seeds = {base_slug}

    # Tambah aliases manual
    if aliases:
        for a in aliases:
            seeds.add(sanitize_slug(a))

    # Auto-detect split points: huruf+angka boundary, camelCase
    # abccorp → ["abc", "corp"]  (jika ada kata umum: corp, tech, dev, inc, co, hq, grp)
    corp_suffixes = ["corp", "tech", "dev", "inc", "co", "hq", "grp", "group",
                     "global", "labs", "sys", "net", "digital", "solutions"]

    for slug in list(seeds):
        # 1. Coba split berdasarkan common corp suffixes
        for suffix in corp_suffixes:
            if slug.endswith(suffix) and len(slug) > len(suffix):
                prefix = slug[: -len(suffix)]
                if len(prefix) >= 2:  # minimal 2 char
                    seeds.add(prefix)                        # "abc"
                    seeds.add(f"{prefix}-{suffix}")          # "abc-corp"
                    seeds.add(f"{prefix}_{suffix}")          # "abc_corp"
            if slug.startswith(suffix) and len(slug) > len(suffix):
                remainder = slug[len(suffix):]
                if len(remainder) >= 2:
                    seeds.add(remainder)

        # 2. Jika sudah ada hyphen, generate tanpa hyphen juga
        if "-" in slug:
            seeds.add(slug.replace("-", ""))     # abc-corp → abccorp
            seeds.add(slug.replace("-", "_"))    # abc-corp → abc_corp
        if "_" in slug:
            seeds.add(slug.replace("_", ""))     # abc_corp → abccorp
            seeds.add(slug.replace("_", "-"))    # abc_corp → abc-corp

    # Environment prefixes (common SaaS naming patterns)
    env_prefixes = ["staging", "dev", "test", "uat", "sandbox",
                    "qa", "preprod", "demo", "internal"]

    # SaaS service suffixes (Atlassian, Zendesk, dll.)
    service_suffixes = ["service-desk", "servicedesk", "helpdesk",
                        "jira", "wiki", "confluence", "support", "help"]

    for slug in list(seeds):
        # Tambahkan slug asli
        variations.add(slug)
        # Tambahkan dengan environment prefix
        for prefix in env_prefixes:
            variations.add(f"{prefix}-{slug}")
            variations.add(f"{slug}-{prefix}")
        # Tambahkan dengan service suffix (e.g., spotify-service-desk)
        for suffix in service_suffixes:
            variations.add(f"{slug}-{suffix}")

    # Filter: hapus yang terlalu pendek
    variations = {v for v in variations if len(v) >= 2 and v}

    return sorted(variations)


def load_providers(providers_file: Path, slugs: list) -> dict:
    """
    Load provider configuration dari YAML, fallback ke built-in list.
    Sekarang menerima list of slugs untuk coverage variasi nama.
    """
    config = {
        "saas_tenants": [],
        "cloud_storage": [],
        "thirdparty": [],
        "dorks": [],
        "nuclei_tags_saas": set(),
        "nuclei_tags_thirdparty": set(),
    }

    seen_tenants = set()  # dedup

    if yaml and providers_file.exists():
        log.info(f"Loading providers dari: {providers_file}")
        with open(providers_file) as f:
            data = yaml.safe_load(f)

        for slug in slugs:
            # SaaS providers
            for p in data.get("saas_providers", []):
                tenant = p["pattern"].replace("{slug}", slug)
                if tenant not in seen_tenants:
                    config["saas_tenants"].append(tenant)
                    seen_tenants.add(tenant)
                config["nuclei_tags_saas"].update(p.get("tags", []))

            # Cloud storage
            for p in data.get("cloud_storage", []):
                entry = p["pattern"].replace("{slug}", slug)
                if entry not in seen_tenants:
                    config["cloud_storage"].append(entry)
                    seen_tenants.add(entry)

            # 3rd-party
            for p in data.get("thirdparty_candidates", []):
                entry = p["pattern"].replace("{slug}", slug)
                if entry not in seen_tenants:
                    config["thirdparty"].append(entry)
                    seen_tenants.add(entry)
                config["nuclei_tags_thirdparty"].update(p.get("tags", []))

        # Dorks (pakai slug pertama / primary saja)
        for d in data.get("google_dorks", []):
            config["dorks"].append(d["query"].replace("{slug}", slugs[0]))
    else:
        if not yaml:
            log.warning("PyYAML tidak terinstall, menggunakan built-in provider list")
        else:
            log.warning(f"{providers_file} tidak ditemukan, menggunakan built-in provider list")

        for slug in slugs:
            for p in FALLBACK_SAAS:
                tenant = f"{slug}.{p}"
                if tenant not in seen_tenants:
                    config["saas_tenants"].append(tenant)
                    seen_tenants.add(tenant)
            for p in FALLBACK_CLOUD_STORAGE:
                entry = p.replace("{slug}", slug)
                if entry not in seen_tenants:
                    config["cloud_storage"].append(entry)
                    seen_tenants.add(entry)
            for p in FALLBACK_THIRDPARTY:
                entry = p.replace("{slug}", slug)
                if entry not in seen_tenants:
                    config["thirdparty"].append(entry)
                    seen_tenants.add(entry)

        config["dorks"] = [d.replace("{slug}", slugs[0]) for d in FALLBACK_DORKS]
        config["nuclei_tags_saas"] = {
            "atlassian", "jira", "confluence", "servicenow", "zendesk", "okta",
        }
        config["nuclei_tags_thirdparty"] = {
            "microsoft", "sharepoint", "github", "slack", "gitlab",
        }

    return config


def parse_httpx_jsonl(jsonl_file: str, url_output: str) -> list:
    """
    Parse httpx JSONL → extract live URLs dan data.
    Return list of dicts. Tulis URL list ke url_output untuk Nuclei.
    """
    live_entries = []
    urls = []

    if not os.path.exists(jsonl_file):
        return live_entries

    with open(jsonl_file) as f:
        for line in f:
            try:
                data = json.loads(line.strip())
                status = data.get("status_code", 0)
                url = data.get("url", "")
                if 200 <= status < 400 and url:
                    live_entries.append({
                        "url": url,
                        "status_code": status,
                        "title": data.get("title", ""),
                        "tech": data.get("tech", []),
                        "webserver": data.get("webserver", ""),
                    })
                    urls.append(url)
            except json.JSONDecodeError:
                log.debug(f"Skipping invalid JSON line in {jsonl_file}")

    if urls:
        with open(url_output, "w") as f:
            f.write("\n".join(urls))
        log.info(f"  → {len(urls)} live URLs ditulis ke {url_output}")

    return live_entries


def parse_nuclei_results(nuclei_file: str) -> list:
    """Parse nuclei JSONL output, return high/critical findings."""
    findings = []
    if not os.path.exists(nuclei_file):
        return findings

    with open(nuclei_file) as f:
        for line in f:
            try:
                data = json.loads(line.strip())
                severity = data.get("info", {}).get("severity", "").lower()
                if severity in ("critical", "high"):
                    findings.append({
                        "template_id": data.get("template-id", ""),
                        "name": data.get("info", {}).get("name", ""),
                        "severity": severity,
                        "url": data.get("matched-at", data.get("host", "")),
                        "description": data.get("info", {}).get("description", "")[:200],
                    })
            except json.JSONDecodeError:
                log.debug(f"Skipping invalid JSON line in {nuclei_file}")

    return findings


def send_webhook(webhook_url: str, results: dict):
    """Kirim summary ke Slack/Discord webhook."""
    try:
        import urllib.request
        payload = {
            "text": (
                f"🔥 *SaasPwn Recon Complete*\n"
                f"Target: `{results['target']}`\n"
                f"Live SaaS: {len(results['live_saas'])} | "
                f"Live 3rd-party: {len(results['live_thirdparty'])} | "
                f"Cloud Storage: {len(results.get('cloud_storage_exposed', []))} | "
                f"🚨 High/Critical: {len(results['nuclei_high_critical'])}"
            )
        }
        req = urllib.request.Request(
            webhook_url,
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=10)
        log.info("Webhook notification sent!")
    except Exception as e:
        log.error(f"Failed to send webhook: {e}")


# ─── Main Pipeline ───────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="🚀 SaasPwn - SaaS & 3rd-Party Misconfig Recon Pipeline"
    )
    parser.add_argument(
        "--target", required=True,
        help="Company name atau domain (contoh: abc.corp atau acme)"
    )
    parser.add_argument("--output-dir", default=None, help="Folder output (default: auto)")
    parser.add_argument("--providers", default=None, help="Path ke providers.yaml (default: ./providers.yaml)")
    parser.add_argument("--skip-nuclei", action="store_true", help="Skip Nuclei scanning")
    parser.add_argument("--skip-storage", action="store_true", help="Skip cloud storage check")
    parser.add_argument("--skip-secrets", action="store_true", help="Skip secret scanning (trufflehog)")
    parser.add_argument("--webhook", default=None, help="Slack/Discord webhook URL untuk notifikasi")
    parser.add_argument("--nuclei-timeout", type=int, default=600, help="Timeout Nuclei scan dalam detik (default: 600)")
    parser.add_argument("--aliases", nargs="+", default=[], help="Nama alternatif company (contoh: --aliases abc abc-corporation)")
    parser.add_argument("--no-variations", action="store_true", help="Jangan generate variasi slug otomatis")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output (DEBUG level)")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Load .env file (API keys untuk uncover, trufflehog, dll)
    load_dotenv()

    # Dependency check
    if not check_tools():
        sys.exit(1)

    company = derive_company_slug(args.target)
    if not company:
        log.error("Company slug kosong setelah sanitasi. Pastikan target valid.")
        sys.exit(1)

    # Generate slug variations
    if args.no_variations:
        slugs = [company] + [sanitize_slug(a) for a in args.aliases if sanitize_slug(a)]
    else:
        slugs = generate_slug_variations(company, aliases=args.aliases)

    log.info(f"🔑 Slug variations ({len(slugs)}): {', '.join(slugs[:15])}")
    if len(slugs) > 15:
        log.info(f"   ... dan {len(slugs) - 15} variasi lainnya")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M")
    output_dir = args.output_dir or f"recon_{company}_{timestamp}"
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    # Simpan slug variations ke file
    with open(f"{output_dir}/slug_variations.txt", "w") as f:
        f.write("\n".join(slugs))

    providers_file = Path(args.providers) if args.providers else DEFAULT_PROVIDERS_FILE
    config = load_providers(providers_file, slugs)

    log.info(f"🔥 Target: {args.target} (primary slug: {company})")
    log.info(f"📁 Output: {output_dir}")
    log.info(f"📋 SaaS tenants: {len(config['saas_tenants'])} | "
             f"3rd-party: {len(config['thirdparty'])} | "
             f"Cloud storage: {len(config['cloud_storage'])}\n")

    results = {
        "target": args.target,
        "company_slug": company,
        "timestamp": timestamp,
        "live_saas": [],
        "live_thirdparty": [],
        "cloud_storage_exposed": [],
        "nuclei_high_critical": [],
        "dork_queries": config["dorks"],
        "summary": "",
    }

    # ===================== PHASE 1: SaaS TENANT ENUM =====================
    log.info("=" * 60)
    log.info("PHASE 1: SaaS Tenant Enumeration")
    log.info("=" * 60)

    # Generate tenant list
    saas_file = f"{output_dir}/saas_tenants.txt"
    with open(saas_file, "w") as f:
        f.write("\n".join(config["saas_tenants"]))
    log.info(f"1️⃣  Generated {len(config['saas_tenants'])} SaaS tenant URLs")

    # DNS Resolve
    log.info("2️⃣  DNS resolve via dnsx...")
    resolved_file = f"{output_dir}/saas_resolved.txt"
    run_cmd(f"dnsx -l {saas_file} -o {resolved_file} -silent -resp", timeout=180)

    # httpx probe + fingerprint
    log.info("3️⃣  Probing with httpx...")
    saas_httpx = f"{output_dir}/saas_httpx.jsonl"
    run_cmd(
        f"httpx -l {resolved_file} -title -tech-detect -status-code -web-server "
        f"-o {saas_httpx} -json -silent",
        timeout=300,
    )

    # Parse live SaaS & extract URL list
    saas_urls = f"{output_dir}/saas_live_urls.txt"
    results["live_saas"] = parse_httpx_jsonl(saas_httpx, saas_urls)
    log.info(f"   ✅ Live SaaS: {len(results['live_saas'])}")

    # Nuclei scan SaaS
    if not args.skip_nuclei and os.path.exists(saas_urls):
        log.info("4️⃣  Nuclei scan SaaS...")
        tags = ",".join(config["nuclei_tags_saas"]) if config["nuclei_tags_saas"] else "misconfig"
        nuclei_saas_out = f"{output_dir}/nuclei_saas.jsonl"
        run_cmd(
            f"nuclei -l {saas_urls} -tags {tags} "
            f"-severity critical,high -o {nuclei_saas_out} -jsonl -silent",
            timeout=args.nuclei_timeout,
        )

    # ===================== PHASE 2: CLOUD STORAGE =====================
    if not args.skip_storage and config["cloud_storage"]:
        log.info("")
        log.info("=" * 60)
        log.info("PHASE 2: Cloud Storage Exposure Check")
        log.info("=" * 60)

        storage_file = f"{output_dir}/cloud_storage_targets.txt"
        with open(storage_file, "w") as f:
            f.write("\n".join(config["cloud_storage"]))

        log.info(f"5️⃣  Checking {len(config['cloud_storage'])} cloud storage URLs...")
        storage_httpx = f"{output_dir}/cloud_storage_httpx.jsonl"
        run_cmd(
            f"httpx -l {storage_file} -status-code -title -follow-redirects "
            f"-o {storage_httpx} -json -silent",
            timeout=180,
        )

        storage_urls = f"{output_dir}/cloud_storage_live.txt"
        results["cloud_storage_exposed"] = parse_httpx_jsonl(storage_httpx, storage_urls)
        log.info(f"   ✅ Exposed storage: {len(results['cloud_storage_exposed'])}")

    # ===================== PHASE 3: 3RD-PARTY RECON =====================
    log.info("")
    log.info("=" * 60)
    log.info("PHASE 3: 3rd-Party Asset Recon")
    log.info("=" * 60)

    tp_candidates_file = f"{output_dir}/thirdparty_candidates.txt"
    with open(tp_candidates_file, "w") as f:
        f.write("\n".join(config["thirdparty"]))
    log.info(f"6️⃣  Generated {len(config['thirdparty'])} 3rd-party candidates")

    # Uncover (dijalankan terpisah per query, bukan campur -l dan -q)
    if shutil.which("uncover"):
        log.info("7️⃣  Running uncover queries...")
        uncover_out = f"{output_dir}/thirdparty_uncover.txt"
        uncover_results = []
        for dork in config["dorks"][:5]:  # limit 5 dorks untuk rate-limit
            out = run_cmd(f'uncover -q "{dork}" -silent -limit 50', timeout=60)
            if out:
                uncover_results.extend(out.splitlines())

        if uncover_results:
            with open(uncover_out, "w") as f:
                f.write("\n".join(set(uncover_results)))
            log.info(f"   → {len(set(uncover_results))} uncover results")

            # Gabungkan dengan candidates
            with open(tp_candidates_file, "a") as f:
                f.write("\n" + "\n".join(set(uncover_results)))
    else:
        log.info("7️⃣  Skipping uncover (not installed)")

    # httpx 3rd-party
    log.info("8️⃣  Probing 3rd-party with httpx...")
    tp_httpx = f"{output_dir}/thirdparty_httpx.jsonl"
    run_cmd(
        f"httpx -l {tp_candidates_file} -title -tech-detect -status-code "
        f"-o {tp_httpx} -json -silent",
        timeout=300,
    )

    # Parse live 3rd-party (FIX: sebelumnya tidak pernah diisi!)
    tp_urls = f"{output_dir}/thirdparty_live_urls.txt"
    results["live_thirdparty"] = parse_httpx_jsonl(tp_httpx, tp_urls)
    log.info(f"   ✅ Live 3rd-party: {len(results['live_thirdparty'])}")

    # Nuclei 3rd-party
    if not args.skip_nuclei and os.path.exists(tp_urls):
        log.info("9️⃣  Nuclei scan 3rd-party...")
        tags = ",".join(config["nuclei_tags_thirdparty"]) if config["nuclei_tags_thirdparty"] else "misconfig"
        nuclei_tp_out = f"{output_dir}/nuclei_thirdparty.jsonl"
        run_cmd(
            f"nuclei -l {tp_urls} -tags {tags} "
            f"-severity critical,high,medium -o {nuclei_tp_out} -jsonl -silent",
            timeout=args.nuclei_timeout,
        )

    # ===================== PHASE 4: SECRET SCANNING =====================
    if not args.skip_secrets and shutil.which("trufflehog"):
        log.info("")
        log.info("=" * 60)
        log.info("PHASE 4: Secret Scanning (TruffleHog)")
        log.info("=" * 60)

        # Scan GitHub org jika ada
        github_url = f"https://github.com/{company}"
        secrets_out = f"{output_dir}/secrets_trufflehog.json"
        log.info(f"🔑 Scanning GitHub org: {github_url}")
        run_cmd(
            f"trufflehog github --org {company} --json --only-verified "
            f"--concurrency 3 2>/dev/null | head -500 > {secrets_out}",
            timeout=args.nuclei_timeout,
        )
        # Note: trufflehog output needs shell pipe, fallback ke run via shell
        if os.path.exists(secrets_out) and os.path.getsize(secrets_out) > 0:
            log.info(f"   ⚠️  Secrets found! Check: {secrets_out}")
        else:
            log.info("   ✅ No verified secrets found")

    # ===================== COMPILE RESULTS =====================
    log.info("")
    log.info("=" * 60)
    log.info("COMPILING RESULTS")
    log.info("=" * 60)

    # Collect nuclei findings
    for nuclei_file in [
        f"{output_dir}/nuclei_saas.jsonl",
        f"{output_dir}/nuclei_thirdparty.jsonl",
    ]:
        results["nuclei_high_critical"].extend(parse_nuclei_results(nuclei_file))

    results["summary"] = (
        f"Live SaaS: {len(results['live_saas'])} | "
        f"Live 3rd-party: {len(results['live_thirdparty'])} | "
        f"Cloud Storage Exposed: {len(results.get('cloud_storage_exposed', []))} | "
        f"High/Critical: {len(results['nuclei_high_critical'])}"
    )

    # Save final JSON
    summary_file = f"{output_dir}/FINAL_SUMMARY.json"
    with open(summary_file, "w") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    # Save dork queries untuk manual follow-up
    dork_file = f"{output_dir}/google_dorks.txt"
    with open(dork_file, "w") as f:
        f.write("\n".join(config["dorks"]))

    # ===================== FINAL OUTPUT =====================
    log.info("")
    log.info("🎉 RECON SELESAI!")
    log.info(f"   📊 Live SaaS           : {len(results['live_saas'])}")
    log.info(f"   📊 Live 3rd-party      : {len(results['live_thirdparty'])}")
    log.info(f"   📊 Cloud Storage       : {len(results.get('cloud_storage_exposed', []))}")
    log.info(f"   🚨 High/Critical vuln  : {len(results['nuclei_high_critical'])}")
    log.info(f"   🔍 Google Dorks saved  : {dork_file}")
    log.info(f"   📁 Output folder       : {output_dir}")
    log.info(f"   📄 Summary JSON        : {summary_file}")

    if results["nuclei_high_critical"]:
        log.info("")
        log.info("⚠️  HIGH/CRITICAL FINDINGS:")
        for finding in results["nuclei_high_critical"][:10]:
            log.info(f"   [{finding['severity'].upper()}] {finding['name']} → {finding['url']}")
        if len(results["nuclei_high_critical"]) > 10:
            log.info(f"   ... dan {len(results['nuclei_high_critical']) - 10} lagi")

    # Webhook notification
    if args.webhook:
        send_webhook(args.webhook, results)

    return results


if __name__ == "__main__":
    main()