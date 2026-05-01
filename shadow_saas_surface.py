"""
ShadowSaaS Surface Scanner v1.0
Author: Jordan Bonagura
Secure Ideas - Professionally Evil


Enumerates subdomains and detects dangling or abandoned SaaS integrations
by correlating DNS records, HTTP responses, and provider-specific fingerprints.
Intended for authorized security testing and research only.
"""
import json
import re
import sys
import time

import dns.resolver
import requests
import tldextract
import urllib3


BRUTEFORCE_NAMES = [
    "api", "admin", "login", "auth", "portal",
    "app", "dev", "staging", "test", "old",
    "beta", "internal", "vpn", "mail",
    "dashboard", "service", "services"
]

# Critical subdomains
CRITICAL_NAMES = [
    "login", "auth", "api", "app", "portal",
    "dev", "staging", "old", "test", "preview",
]

GITHUB_PAGES_IPS = {
    "185.199.108.153",
    "185.199.109.153",
    "185.199.110.153",
    "185.199.111.153"
}

# Azure provider 404 page signatures — confirms the app slot is deleted/unprovisioned.
# A generic 404 from a live app will NOT contain these strings.
AZURE_404_SIGNATURES = [
    "the web app you have attempted to reach is not available",
    "error 404 - web app not found",
    "no web app was found for the hostname",
    "this web app has been stopped",
    "this azure website has been removed",
]

# Azure Blob Storage 404/error signatures — confirms the storage account is deleted.
# A 404 on a missing container/blob within an existing account will NOT contain these.
AZURE_BLOB_404_SIGNATURES = [
    "the specified resource does not exist",
    "blobnotfound",
    "storageaccountnotfound",
    "no such host",
    "the storage account being accessed does not exist",
]

# Azure service hostnames that can appear as asverify CNAME targets.
# Used to generalise asverify detection beyond App Service only.
AZURE_TAKEOVER_TARGETS = [
    "azurewebsites.net",
    "blob.core.windows.net",
    "azurestaticapps.net",
    "trafficmanager.net",
    "azureedge.net",
    "cloudapp.azure.com",
]

# CloudFront distribution deleted signatures.
# A 404 from an active distribution serving missing content will NOT contain these.
# The AWS identifier (e.g. d3kalschzfy4m2) is unique and never reused,
# so takeover is only possible if the distribution itself was deleted.
CLOUDFRONT_DELETED_SIGNATURES = [
    "the request could not be satisfied",
    "error: the request could not be satisfied",
    "no such distribution",
    "distribution is disabled",
]

# SaaS types with dedicated risk blocks — excluded from the generic SaaS block.
# Each type here has provider-specific body signatures to avoid false positives.
MANAGED_SAAS_TYPES = (
    "azure_app_service",
    "azure_traffic_manager",
    "azure_asverify",
    "azure_blob_storage",
    "aws_cloudfront",
)

# ---------------------------------------------------------------------------
# Subdomain validation
# ---------------------------------------------------------------------------

def is_valid_subdomain(subdomain, root):
    """Return True if subdomain is a valid label under root domain."""
    if not subdomain.endswith(root):
        return False
    if subdomain == root:
        return True  # root domain is valid (optional)
    if subdomain.startswith("*."):
        return False
    if "@" in subdomain or " " in subdomain:
        return False
    dns_regex = r"^[a-z0-9.-]+$"
    if not re.match(dns_regex, subdomain):
        return False
    return True


# ---------------------------------------------------------------------------
# Enumeration
# ---------------------------------------------------------------------------

def enumerate_by_wordlist(_rd):
    """Return a dict of speculative subdomains from the built-in wordlist."""
    return {f"{name}.{_rd}": "wordlist" for name in CRITICAL_NAMES}


def _ct_request(url, _rd, source_label, parse_fn, retries=3, delay=5):
    """
    Generic CT log fetcher with retry logic.
    parse_fn receives the response and _rd, returns {subdomain: source_label}
    or raises on bad responses.
    """
    subs = {}
    headers = {"User-Agent": "Mozilla/5.0 (compatible; ShadowSaaSSurface/1.0)"}

    for attempt in range(1, retries + 1):
        try:
            r = requests.get(url, headers=headers, timeout=30)

            if r.status_code == 403:
                raise ValueError(f"HTTP 403 - IP may be blocked by {source_label}")
            if r.status_code == 429:
                raise ValueError(f"HTTP 429 - Rate limited by {source_label}")
            if not r.ok:
                raise ValueError(f"HTTP {r.status_code} from {source_label}")

            found = parse_fn(r, _rd)
            subs.update(found)
            return subs

        except (
            requests.exceptions.RequestException,
            ValueError, KeyError, json.JSONDecodeError,
        ) as _err:
            print(f"[!] {source_label} lookup failed (attempt {attempt}/{retries}): {_err}")
            if attempt < retries:
                time.sleep(delay * attempt)

    return subs


def _parse_crtsh(r, _rd):
    """Parse crt.sh JSON response into {subdomain: ct_log} dict."""
    content_type = r.headers.get("Content-Type", "")
    if "application/json" not in content_type:
        raise ValueError("Non-JSON response (possible rate-limit or HTML error)")
    data = r.json()
    if not data:
        raise ValueError("Empty JSON dataset from crt.sh")
    subs = {}
    for entry in data:
        names = entry.get("name_value", "")
        for _sub in names.split("\n"):
            _sub = _sub.strip().lower()
            if is_valid_subdomain(_sub, _rd):
                subs[_sub] = "ct_log"
    return subs


def _parse_certspotter(r, _rd):
    """Parse certspotter JSON response into {subdomain: ct_log} dict."""
    data = r.json()
    if not data:
        raise ValueError("Empty JSON dataset from certspotter")
    subs = {}
    for entry in data:
        for name in entry.get("dns_names", []):
            name = name.strip().lower().lstrip("*.")
            if is_valid_subdomain(name, _rd):
                subs[name] = "ct_log"
    return subs


def _parse_hackertarget(r, _rd):
    """Parse HackerTarget plain-text response into {subdomain: ct_log} dict."""
    text = r.text.strip()
    if not text or "error" in text.lower() or "api count" in text.lower():
        raise ValueError(f"HackerTarget returned no usable data: {text[:80]}")
    subs = {}
    for _line in text.splitlines():
        parts = _line.split(",")
        name = parts[0].strip().lower()
        if is_valid_subdomain(name, _rd):
            subs[name] = "ct_log"
    return subs


def enumerate_ct_logs(_rd, retries=3, delay=5):
    """
    Enumerates subdomains via CT logs using multiple sources in cascade.
    Falls back to the next source if the previous one fails or is blocked.

    Sources (in order):
      1. crt.sh       — most comprehensive, blocks some datacenter IPs
      2. certspotter  — Sectigo CT aggregator, free tier, no key required
      3. hackertarget — free tier (limited req/day), no key required
    """
    certspotter_url = (
        f"https://api.certspotter.com/v1/issuances"
        f"?domain={_rd}&include_subdomains=true&expand=dns_names"
    )
    sources = [
        (f"https://crt.sh/?q=%25.{_rd}&output=json", "crt.sh", _parse_crtsh),
        (certspotter_url, "certspotter", _parse_certspotter),
        (f"https://api.hackertarget.com/hostsearch/?q={_rd}", "hackertarget", _parse_hackertarget),
    ]

    for url, label, parse_fn in sources:
        print(f"[*] Querying {label} (CT logs)...")
        subs = _ct_request(url, _rd, label, parse_fn, retries=retries, delay=delay)
        if subs:
            print(f"[+] {label} returned {len(subs)} subdomains")
            return subs
        print(f"[!] {label} returned no results — trying next source...")

    print("[!] All CT log sources failed or returned no data.")
    return {}


def enumerate_asverify_candidates(analyzed_results, _rd):
    """
    Derives asverify.<subdomain> candidates ONLY from subdomains that:
      - Have DNS active
      - Point to a known Azure resource (azurewebsites, blob, trafficmanager, etc.)
      - Are not already an asverify record
      - Are not www.* (never have direct Azure custom domain binds)

    asverify records are Azure domain-ownership verification CNAMEs.
    They never appear in CT logs (no TLS cert is issued), so we derive
    them post-analysis from confirmed Azure subdomains only.

    Running pre-analysis against all subdomains would generate hundreds of
    useless candidates for non-Azure, inactive, or www.* entries.
    """
    candidates = {}

    for _entry in analyzed_results:
        _sub = _entry.get("subdomain", "")
        label = _sub.split(".")[0]

        # Skip already-asverify records
        if label == "asverify":
            continue

        # Skip www.* — never have direct Azure custom domain binds
        if label == "www":
            continue

        # Skip inactive DNS — asverify would not resolve either
        if not _entry.get("dns_active"):
            continue

        # Only generate for confirmed Azure targets
        dns_target = (_entry.get("dns_target") or "").lower()
        if not any(az in dns_target for az in AZURE_TAKEOVER_TARGETS):
            continue

        asverify = f"asverify.{_sub}"
        if is_valid_subdomain(asverify, _rd):
            candidates[asverify] = "asverify_derived"

    return candidates


def enumerate_subdomains(_rd, speculative=False, bruteforce=False):
    """Enumerate subdomains via CT logs, optional wordlist, and optional brute-force."""
    subs = {}

    # Primary source — CT logs
    subs.update(enumerate_ct_logs(_rd))

    # Speculative wordlist (optional)
    if speculative:
        for _sub, src in enumerate_by_wordlist(_rd).items():
            if _sub not in subs:
                subs[_sub] = src

    # DNS brute-force (optional)
    if bruteforce:
        brute = enumerate_dns_bruteforce(_rd, BRUTEFORCE_NAMES)
        for _sub, src in brute.items():
            subs.setdefault(_sub, src)

    return subs


def enumerate_dns_bruteforce(_rd, names, delay=0.05):
    """Brute-force DNS resolution for each name in the provided list."""
    subs = {}

    print("[*] Performing DNS brute-force enumeration...")

    for name in names:
        _sub = f"{name}.{_rd}"
        try:
            dns.resolver.resolve(_sub, "A")
            subs[_sub] = "dns_bruteforce"
            time.sleep(delay)
        except dns.exception.DNSException:
            try:
                dns.resolver.resolve(_sub, "CNAME")
                subs[_sub] = "dns_bruteforce"
                time.sleep(delay)
            except dns.exception.DNSException:
                continue

    return subs


# ---------------------------------------------------------------------------
# DNS
# ---------------------------------------------------------------------------

def resolve_dns(subdomain):
    """
    Tries CNAME first, then A record.
    Returns (dns_active: bool, target: str)
    """
    try:
        answers = dns.resolver.resolve(subdomain, 'CNAME')
        return True, f"CNAME -> {answers[0].target}"
    except dns.exception.DNSException:
        try:
            answers = dns.resolver.resolve(subdomain, 'A')
            return True, f"A -> {answers[0].address}"
        except dns.exception.DNSException:
            return False, None


def clean_dns_target(dns_target):
    """Strip CNAME/A prefixes and trailing dots from a raw DNS target string."""
    if not dns_target:
        return None
    return dns_target.replace("CNAME ->", "").replace("A ->", "").strip().strip(".")


# ---------------------------------------------------------------------------
# HTTP probe
# ---------------------------------------------------------------------------

def http_probe(subdomain):
    """Probe subdomain over HTTPS then HTTP; return (status, headers, body)."""
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    for scheme in ["https", "http"]:
        try:
            r = requests.get(
                f"{scheme}://{subdomain}",
                timeout=5,
                headers={"User-Agent": "ShadowSaaSSurface/1.0"},
                verify=False  # allow dangling/expired certs
            )
            return r.status_code, r.headers, r.text.lower()
        except requests.exceptions.SSLError:
            continue
        except requests.exceptions.Timeout:
            continue
        except requests.exceptions.ConnectionError:
            continue
        except OSError:
            continue
    return None, {}, ""


# ---------------------------------------------------------------------------
# SaaS detection
# ---------------------------------------------------------------------------

def is_saas_dns_plausible(saas, dns_target):
    """Return True if the DNS target is consistent with the detected SaaS type."""
    if not saas or not dns_target:
        return False

    dns_target = dns_target.lower()

    # GitHub Pages is takeover-capable via A-record
    if saas == "github_pages":
        return True

    # Azure asverify, Traffic Manager, and Blob Storage use CNAME
    if saas in ("azure_asverify", "azure_traffic_manager", "azure_blob_storage"):
        return True

    # All other SaaS require CNAME — reject A-records
    if dns_target.startswith("a ->"):
        return False

    # Firebase requires googlehosted.com in the CNAME target
    if saas == "firebase" and "googlehosted.com" not in dns_target:
        return False

    return True


def detect_saas_by_domain(subdomain, dns_target, _rd):
    """Detect SaaS provider from subdomain label and CNAME/A target."""
    subdomain = subdomain.lower()
    _tgt = dns_target.split("->")[-1].strip().strip(".").lower() if dns_target else ""

    # ----------------------------
    # GitHub Pages via A-record
    # ----------------------------
    if dns_target and dns_target.lower().startswith("a ->"):
        ip = _tgt.strip()
        if ip in GITHUB_PAGES_IPS:
            return "github_pages"

    # ----------------------------
    # First-party / internal DNS
    # ----------------------------
    if _rd and _rd in _tgt:
        return None

    # ----------------------------
    # Azure edge infra (not takeover-capable)
    # ----------------------------
    if _tgt.endswith(".azurefd.net"):
        return None

    # ----------------------------
    # Azure asverify — domain ownership verification record
    # Never generates a TLS cert, so never appears in CT logs.
    # Derived and checked separately via enumerate_asverify_candidates.
    # Generalised to cover all Azure resource types, not just App Service.
    # ----------------------------
    if subdomain.split(".")[0] == "asverify":
        if any(az in _tgt for az in AZURE_TAKEOVER_TARGETS):
            return "azure_asverify"

    # ----------------------------
    # Provider-based detection
    # ----------------------------
    if subdomain.endswith(".firebaseapp.com"):
        return "firebase"

    if "azurewebsites.net" in _tgt:
        return "azure_app_service"

    # Azure Static Apps — only match the actual static apps domain
    if subdomain.endswith(".azurestaticapps.net"):
        return "azure_static_apps"

    # Azure Traffic Manager — DNS-level load balancer/failover
    # Separate from Static Apps: TM can front any Azure resource type
    if "trafficmanager.net" in _tgt:
        return "azure_traffic_manager"

    # Azure Blob Storage — storage account custom domain binding
    if "blob.core.windows.net" in _tgt:
        return "azure_blob_storage"

    if "github.io" in _tgt:
        return "github_pages"

    if "cloudfront.net" in _tgt:
        return "aws_cloudfront"

    return None


def fingerprint_saas(headers, body):
    """
    Conservative SaaS fingerprinting via HTTP response headers and body.
    Requires provider-specific indicators — avoids false positives.
    """
    headers_l = {k.lower(): str(v).lower() for k, v in headers.items()}
    body_l = body.lower() if body else ""

    # GitHub Pages
    if (
        "github" in headers_l.get("server", "")
        or "there isn't a github pages site here" in body_l
    ):
        return "github_pages"

    # Heroku
    if (
        "heroku" in headers_l.get("server", "")
        or "no such app" in body_l
    ):
        return "heroku"

    # Vercel
    if (
        "vercel" in headers_l.get("server", "")
        or headers_l.get("x-vercel-id") is not None
        or "deployment could not be found" in body_l
    ):
        return "vercel"

    # Netlify
    if (
        "netlify" in headers_l.get("server", "")
        or "x-nf-request-id" in headers_l
        or "not found - request id" in body_l
    ):
        return "netlify"

    # Azure Static Web Apps
    if (
        headers_l.get("x-ms-request-id")
        and "web app not found" in body_l
    ):
        return "azure_static_apps"

    # Cloudflare Pages
    if (
        "cloudflare" in headers_l.get("server", "")
        and "project not found" in body_l
    ):
        return "cloudflare_pages"

    # Shopify
    if (
        "x-shopify-stage" in headers_l
        or "x-shopify-shop-api-call-limit" in headers_l
    ):
        return "shopify"

    # Firebase — EXTREMELY STRICT
    if (
        "x-firebase" in headers_l
        or ("firebase hosting" in body_l and "error 404" in body_l)
    ):
        return "firebase"

    return None


# ---------------------------------------------------------------------------
# Risk scoring
# ---------------------------------------------------------------------------

def is_critical_subdomain(subdomain):
    """Returns True if the first label of the subdomain is in CRITICAL_NAMES."""
    label = subdomain.split(".")[0]
    return label in CRITICAL_NAMES


def takeover_reason(saas, dns_target, status, body):
    """Build a list of human-readable takeover indicators from provider signals."""
    reasons = []

    if dns_target and dns_target.lower().startswith("cname ->"):
        reasons.append("Dangling CNAME detected")

    if saas:
        reasons.append(f"Points to claimable SaaS provider: {saas}")

    if status == 404:
        reasons.append("HTTP 404 from provider endpoint")

    if body and "cloudfront" in body and "not found" in body:
        reasons.append("Possible dangling CloudFront distribution")

    if body:
        for keyword in [
            "no such app",
            "project not found",
            "deployment could not be found",
            "there isn't a github pages site here"
        ]:
            if keyword in body:
                reasons.append(f"Provider error message: '{keyword}'")
                break

    return reasons


def risk_score(
    subdomain, dns_active, saas, status, body, _source,
    dns_target=None, _rd=None, headers=None
):
    """
    Calculates risk score, analysis reasons, and takeover_possible flag.

    Each provider block uses specific signals to avoid false positives:
    - azurewebsites.net: requires provider 404 body signature OR unreachable probe
    - trafficmanager.net: same signals, slightly lower score due to indirection
    - blob.core.windows.net: requires storage-specific 404 signature OR unreachable probe
    - cloudfront.net: requires body signature AND absence of active CloudFront headers
    - asverify: informational only, raises score, identifies backing Azure service
    - Generic 404 from a live app does NOT trigger takeover
    - HTTP 403 is treated as "app exists, access denied" — not a takeover
    """
    score = 20
    reasons = []
    takeover_possible = False
    headers = headers or {}

    if _source == "dns_bruteforce":
        reasons.append("Subdomain confirmed via DNS brute-force")

    # -----------------------------------------------------------------------
    # Azure App Service — azurewebsites.net
    # -----------------------------------------------------------------------
    if dns_target and "azurewebsites.net" in dns_target.lower():
        reasons.append("Azure App Service CNAME detected")

        azure_404_confirmed = bool(body) and any(
            sig in body for sig in AZURE_404_SIGNATURES
        )

        if azure_404_confirmed:
            takeover_possible = True
            score += 40
            reasons.append("Azure provider 404 confirmed - app slot deleted or unprovisioned")
        elif status is None:
            takeover_possible = True
            score += 40
            reasons.append("Azure app unreachable (probe failed) - possible orphaned app")
        elif status == 403:
            reasons.append("Azure app returned 403 - app exists but access denied (not a takeover)")
        elif status == 404:
            reasons.append("HTTP 404 from app - content missing but app likely still provisioned")

    # -----------------------------------------------------------------------
    # Azure Traffic Manager — trafficmanager.net
    # -----------------------------------------------------------------------
    if dns_target and "trafficmanager.net" in dns_target.lower():
        reasons.append("Azure Traffic Manager endpoint detected")

        azure_404_confirmed = bool(body) and any(
            sig in body for sig in AZURE_404_SIGNATURES
        )

        if azure_404_confirmed:
            takeover_possible = True
            score += 35
            reasons.append(
                "Traffic Manager backend: Azure provider 404 confirmed"
                " - possible orphaned endpoint"
            )
        elif status is None:
            takeover_possible = True
            score += 35
            reasons.append(
                "Traffic Manager backend unreachable (probe failed)"
                " - possible orphaned endpoint"
            )
        elif status == 403:
            reasons.append(
                "Traffic Manager returned 403"
                " - backend exists but access denied (not a takeover)"
            )
        elif status == 404:
            reasons.append(
                "HTTP 404 from Traffic Manager backend"
                " - endpoint may exist but has no content"
            )

    # -----------------------------------------------------------------------
    # Azure Blob Storage — blob.core.windows.net
    # Takeover is possible if the storage account name has been released.
    # A 404 on a missing container/blob within a live account is NOT a takeover.
    # -----------------------------------------------------------------------
    if dns_target and "blob.core.windows.net" in dns_target.lower():
        reasons.append("Azure Blob Storage endpoint detected")

        blob_404_confirmed = bool(body) and any(
            sig in body for sig in AZURE_BLOB_404_SIGNATURES
        )

        if blob_404_confirmed:
            takeover_possible = True
            score += 40
            reasons.append(
                "Azure Blob Storage account deleted"
                " - storage account name available for registration"
            )
        elif status is None:
            takeover_possible = True
            score += 35
            reasons.append(
                "Azure Blob Storage unreachable (probe failed)"
                " - possible deleted storage account"
            )
        elif status == 403:
            reasons.append(
                "Azure Blob Storage returned 403"
                " - account exists but access denied (not a takeover)"
            )
        elif status == 404:
            reasons.append(
                "HTTP 404 from blob endpoint"
                " - container may be missing but account still exists"
            )

    # -----------------------------------------------------------------------
    # Azure asverify — dangling domain ownership verification record
    # Identifies which backing Azure service the bind pointed to for context.
    # -----------------------------------------------------------------------
    if saas == "azure_asverify" and dns_target:
        score += 20
        reasons.append("Dangling Azure asverify record - custom domain bind was removed")
        t = dns_target.lower()
        if "blob.core.windows.net" in t:
            reasons.append(
                "Investigate whether storage account has been deleted: "
                + dns_target
            )
        elif "azurewebsites.net" in t:
            reasons.append("Investigate parent subdomain for orphaned Azure App Service binding")
        elif "trafficmanager.net" in t:
            reasons.append(
                "Investigate parent subdomain for orphaned Azure Traffic Manager endpoint"
            )
        elif "azurestaticapps.net" in t:
            reasons.append("Investigate parent subdomain for orphaned Azure Static Web App binding")
        else:
            reasons.append("Investigate parent subdomain for orphaned Azure resource binding")

    # -----------------------------------------------------------------------
    # Speculative subdomains — cap score if DNS inactive
    # -----------------------------------------------------------------------
    if _source == "wordlist" and not dns_active:
        reasons.append("Speculative subdomain (not present in DNS)")
        score = min(score, 25)

    # -----------------------------------------------------------------------
    # Provider-specific early exits
    # -----------------------------------------------------------------------
    if saas == "firebase":
        return score, ["Firebase hosting is not takeover-capable"], False

    if saas == "cloudflare_pages":
        reasons.append("Cloudflare Pages projects are not publicly claimable")
        return score, reasons, False

    # -----------------------------------------------------------------------
    # Generic SaaS block — providers not handled by dedicated blocks above
    # -----------------------------------------------------------------------
    if dns_active and saas and saas not in MANAGED_SAAS_TYPES:
        # Skip if CNAME points back to own domain
        if dns_target and _rd and _rd in dns_target.lower():
            reasons.append("CNAME points to first-party domain")
            return score, reasons, False

        score += 30
        reasons.append("DNS active pointing to SaaS")

        if status == 200:
            takeover_possible = False
            reasons.append("HTTP 200 - SaaS endpoint active, takeover not possible")
        elif status == 404:
            score += 30
            takeover_possible = True
            reasons.append("SaaS project appears deleted or orphaned")
            reasons.extend(takeover_reason(saas, dns_target, status, body))
        else:
            if not takeover_possible:
                takeover_possible = False

    # -----------------------------------------------------------------------
    # Azure SaaS blocks — add "DNS active" label and handle 200 explicitly
    # -----------------------------------------------------------------------
    non_label_types = ("azure_asverify", "azure_blob_storage", "aws_cloudfront")
    if dns_active and saas in MANAGED_SAAS_TYPES and saas not in non_label_types:
        if dns_target and _rd and _rd in dns_target.lower():
            reasons.append("CNAME points to first-party domain")
            return score, reasons, False

        if "DNS active pointing to SaaS" not in reasons:
            score += 30
            reasons.append("DNS active pointing to SaaS")

        if status == 200:
            takeover_possible = False
            if "HTTP 200 - SaaS endpoint active, takeover not possible" not in reasons:
                reasons.append("HTTP 200 - SaaS endpoint active, takeover not possible")

    # -----------------------------------------------------------------------
    # Critical subdomain label — increases score only
    # -----------------------------------------------------------------------
    if is_critical_subdomain(subdomain):
        score += 10
        reasons.append("Critical subdomain name")

    # -----------------------------------------------------------------------
    # AWS CloudFront — cloudfront.net
    # CloudFront distribution IDs are unique and never reused by AWS.
    # Takeover is only possible if the distribution was deleted AND the body
    # contains AWS's specific error for a missing distribution AND the response
    # lacks active CloudFront headers (x-cache, x-amz-cf-id).
    #
    # An active distribution blocking access (WAF, geo-restriction, signed URLs)
    # returns the same body signatures BUT always injects x-cache and x-amz-cf-id.
    # Checking for the absence of these headers distinguishes a deleted distribution
    # from a live one that is simply restricting access — eliminating false positives
    # on 403 responses from active distributions.
    # -----------------------------------------------------------------------
    if dns_target and "cloudfront.net" in dns_target.lower():
        reasons.append("AWS CloudFront distribution detected")

        # Active distributions always inject these headers, even on error responses.
        # A deleted distribution has no infrastructure to add them.
        cf_has_active_headers = bool(
            headers.get("x-cache") or headers.get("x-amz-cf-id")
        )

        cf_deleted = (
            bool(body)
            and any(sig in body for sig in CLOUDFRONT_DELETED_SIGNATURES)
            and not cf_has_active_headers
        )

        if cf_deleted:
            takeover_possible = True
            score += 35
            reasons.append("CloudFront distribution deleted - dangling CNAME confirmed")
        elif status == 404:
            reasons.append(
                "HTTP 404 from CloudFront - origin missing content,"
                " distribution likely active (not a takeover)"
            )
        elif status is None:
            reasons.append(
                "CloudFront unreachable via HTTP"
                " - check if distribution is disabled or restricted"
            )
        elif status == 403:
            if cf_has_active_headers:
                reasons.append(
                    "CloudFront returned 403 with active headers"
                    " - distribution exists, access restricted (not a takeover)"
                )
            else:
                reasons.append(
                    "CloudFront returned 403 without active headers"
                    " - distribution may be deleted, manual verification recommended"
                )

    # A-record to non-GitHub infra — not takeover-capable
    if dns_target and dns_target.lower().startswith("a ->"):
        if saas != "github_pages":
            reasons.append("A record points to first-party infrastructure")
            takeover_possible = False

    score = min(score, 100)

    return score, reasons, takeover_possible


# ---------------------------------------------------------------------------
# Main analysis
# ---------------------------------------------------------------------------

def calculate_confidence(_source, dns_active, saas, takeover_possible):
    """Return a confidence string based on source and detection signals."""
    if _source == "wordlist":
        return "speculative"
    if _source == "dns_bruteforce":
        return "low"
    if _source == "asverify_derived":
        return "medium" if dns_active else "low"
    if dns_active and saas and takeover_possible:
        return "high"
    if dns_active and saas:
        return "medium"
    return "low"


def analyze_subdomain(subdomain, _source, _rd):
    """Run full DNS, HTTP, SaaS detection and risk scoring for one subdomain."""

    # Resolve DNS
    dns_active, raw_dns_target = resolve_dns(subdomain)
    dns_target = clean_dns_target(raw_dns_target)

    # HTTP probe (only if DNS resolves)
    if dns_active:
        status, headers, body = http_probe(subdomain)
    else:
        status, headers, body = None, {}, ""

    # Detect SaaS provider
    saas = detect_saas_by_domain(subdomain, dns_target, _rd)
    if not saas:
        saas = fingerprint_saas(headers, body)

    # DNS sanity check — discard SaaS classification if DNS doesn't support it
    if saas and not is_saas_dns_plausible(saas, dns_target):
        saas = None

    # Calculate risk — pass headers so CloudFront block can inspect them
    score, reasons, takeover_possible = risk_score(
        subdomain,
        dns_active,
        saas,
        status,
        body,
        _source,
        dns_target=dns_target,
        _rd=_rd,
        headers=headers,
    )

    # Confidence
    confidence = calculate_confidence(_source, dns_active, saas, takeover_possible)

    return {
        "subdomain": subdomain,
        "_source": _source,
        "dns_active": dns_active,
        "dns_target": dns_target,
        "saas": saas,
        "http_status": status,
        "risk_score": score,
        "takeover_possible": takeover_possible,
        "confidence": confidence,
        "analysis": reasons
    }


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def _normalize_target(_raw):
    """Strip scheme prefix and whitespace from a domain/subdomain string."""
    t = _raw.strip().lower()
    if t.startswith("http://"):
        t = t[len("http://"):]
    elif t.startswith("https://"):
        t = t[len("https://"):]
    return t.rstrip("/")


def _run_domain_scan(_scan_target, speculative, bruteforce):
    """
    Run a full scan for a single root domain or direct subdomain.
    Returns (scan_results, scan_takeovers).
    """
    _sr = []
    _tc = 0

    # ================================
    # DIRECT SUBDOMAIN MODE
    # ================================
    if _scan_target.count(".") >= 2:
        ext = tldextract.extract(_scan_target)
        _root = ext.top_domain_under_public_suffix

        if not _root:
            print(f"[!] Could not determine root domain for {_scan_target}")
            _root = ".".join(_scan_target.split(".")[-2:])
            print(f"[+] Fallback root domain: {_root}")

        print(f"[+] Direct subdomain analysis: {_scan_target}")
        _res = analyze_subdomain(_scan_target, "direct_input", _root)
        _sr.append(_res)

        if _res["takeover_possible"]:
            _tc = 1

    # ================================
    # ROOT DOMAIN ENUMERATION MODE
    # ================================
    else:
        ext = tldextract.extract(_scan_target)
        _domain = ext.top_domain_under_public_suffix or _scan_target
        print(f"[+] Enumerating subdomains for {_domain}...")

        subdomains = enumerate_subdomains(
            _domain,
            speculative=speculative,
            bruteforce=bruteforce,
        )

        if not subdomains:
            print("[!] No subdomains found via CT logs.")
            if speculative:
                print("[*] Using speculative wordlist fallback.")
                subdomains = enumerate_by_wordlist(_domain)
            else:
                print("[!] Tip: try --speculative")

        print(f"[+] Found {len(subdomains)} subdomains\n")

        # ---- First pass: analyse all discovered subdomains ----
        first_pass_results = []
        total = len(subdomains)
        for i, (_sub, _source) in enumerate(subdomains.items(), start=1):
            print(f"[+] [{i}/{total}] Analyzing {_sub}")
            _res = analyze_subdomain(_sub, _source, _domain)

            if _res["dns_target"] and _domain in _res["dns_target"].lower():
                _res["takeover_possible"] = False
                _res["confidence"] = "low"
                if "CNAME points to first-party domain" not in _res["analysis"]:
                    _res["analysis"].append("CNAME points to first-party domain")

            first_pass_results.append(_res)
            _sr.append(_res)
            if _res["takeover_possible"]:
                _tc += 1

        # ---- Second pass: asverify candidates from confirmed Azure subdomains only ----
        asverify_candidates = enumerate_asverify_candidates(first_pass_results, _domain)
        if asverify_candidates:
            count = len(asverify_candidates)
            print(f"[+] Derived {count} asverify candidates from Azure subdomains")
            av_total = len(asverify_candidates)
            for i, (_sub, _source) in enumerate(asverify_candidates.items(), start=1):
                print(f"[+] [asverify {i}/{av_total}] Analyzing {_sub}")
                _res = analyze_subdomain(_sub, _source, _domain)

                if _res["dns_target"] and _domain in _res["dns_target"].lower():
                    _res["takeover_possible"] = False
                    _res["confidence"] = "low"
                    if "CNAME points to first-party domain" not in _res["analysis"]:
                        _res["analysis"].append("CNAME points to first-party domain")

                _sr.append(_res)
                if _res["takeover_possible"]:
                    _tc += 1

    return _sr, _tc


if __name__ == "__main__":
    import argparse

    # ------------------------------------------------------------------
    # Argument parser
    # ------------------------------------------------------------------
    parser = argparse.ArgumentParser(
        prog="shadow_saas_surface.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="""
┌─────────────────────────────────────────────────────────────────┐
│               ShadowSaaS Surface Scanner  v1.0                  │
│        Subdomain Takeover & Dangling CNAME Detector             │
│                      Jordan Bonagura                            │
│               Secure Ideas - Professionally Evil                │
└─────────────────────────────────────────────────────────────────┘

Enumerates subdomains and detects dangling or abandoned SaaS
integrations by correlating DNS records, HTTP responses, and
provider-specific fingerprints.

Providers covered:
  Azure   — App Service, Traffic Manager, Blob Storage,
            Static Apps, asverify verification records
  AWS     — CloudFront distributions
  GitHub  — GitHub Pages (A-record and CNAME)
  Heroku, Vercel, Netlify, Shopify, Firebase

Detection modes:
  CT logs      — Certificate Transparency log enumeration
                 (crt.sh → certspotter → hackertarget cascade)
  Direct       — Single subdomain analysis
  File         — Read targets from a file (one per line)
  Speculative  — Wordlist-based guessing for common subdomains
  Brute-force  — DNS brute-force against a built-in wordlist

Intended for authorized security testing only.
        """,
        epilog="""
Examples:
  # Enumerate a root domain via CT logs
  python shadow_saas_surface.py example.com

  # Analyse a single subdomain directly
  python shadow_saas_surface.py staging.example.com

  # Read multiple targets from a file (one domain/subdomain per line)
  python shadow_saas_surface.py --file targets.txt

  # Full scan with speculative wordlist and brute-force
  python shadow_saas_surface.py example.com --speculative --bruteforce

  # Save results as pretty-printed JSON
  python shadow_saas_surface.py example.com -o results.json --pretty

  # Scan a file of targets and save output
  python shadow_saas_surface.py --file targets.txt -o results.json --pretty

File format (targets.txt):
  example.com
  staging.example.com
  # Lines starting with # are treated as comments and skipped
  another.com
        """
    )

    # Mutually exclusive: either a positional domain OR --file
    input_group = parser.add_mutually_exclusive_group(required=False)
    input_group.add_argument(
        "domain",
        nargs="?",
        help="Target domain or subdomain (e.g. example.com or sub.example.com)"
    )
    input_group.add_argument(
        "--file", "-f",
        metavar="FILE",
        help="Path to a file containing one domain or subdomain per line. "
             "Blank lines and lines starting with # are skipped."
    )

    parser.add_argument(
        "--speculative",
        action="store_true",
        help="Include speculative subdomains from a built-in wordlist "
             "(login, auth, api, app, portal, dev, staging, etc.). "
             "Useful when CT logs return no results."
    )
    parser.add_argument(
        "--bruteforce",
        action="store_true",
        help="Enable DNS brute-force enumeration against a built-in wordlist. "
             "Slower but finds subdomains not present in CT logs."
    )
    parser.add_argument(
        "-o", "--output",
        metavar="FILE",
        help="Write JSON results to FILE instead of stdout."
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON output (indent=2). Has no effect without -o or stdout."
    )
    parser.add_argument(
        "--takeovers-only",
        action="store_true",
        help="Only include results where takeover_possible is true in the output."
    )

    args = parser.parse_args()

    if not args.domain and not args.file:
        parser.print_help()
        sys.exit(0)

    # ------------------------------------------------------------------
    # Build target list
    # ------------------------------------------------------------------
    raw_targets = []

    if args.file:
        try:
            with open(args.file, encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    raw_targets.append(line)
        except OSError as e:
            print(f"[!] Cannot read file: {e}")
            sys.exit(1)

        if not raw_targets:
            print(f"[!] No valid targets found in {args.file}")
            sys.exit(1)

        print(f"[+] Loaded {len(raw_targets)} target(s) from {args.file}")
    else:
        raw_targets = [args.domain]

    # ------------------------------------------------------------------
    # Validate and normalise targets
    # ------------------------------------------------------------------
    targets = []
    for raw in raw_targets:
        norm = _normalize_target(raw)
        if "." not in norm:
            print(f"[!] Skipping '{norm}' — does not look like a valid domain (missing TLD)")
            continue
        targets.append(norm)

    if not targets:
        print("[!] No valid targets to scan.")
        sys.exit(1)

    # ------------------------------------------------------------------
    # Scan
    # ------------------------------------------------------------------
    all_results = []
    total_takeovers = 0

    for idx, _scan_target in enumerate(targets, start=1):
        if len(targets) > 1:
            print(f"\n{'='*60}")
            print(f"[{idx}/{len(targets)}] Target: {_scan_target}")
            print(f"{'='*60}")

        scan_results, scan_takeovers = _run_domain_scan(
            _scan_target,
            speculative=args.speculative,
            bruteforce=args.bruteforce,
        )
        all_results.extend(scan_results)
        total_takeovers += scan_takeovers

    # ------------------------------------------------------------------
    # Apply output filter
    # ------------------------------------------------------------------
    if args.takeovers_only:
        all_results = [r for r in all_results if r.get("takeover_possible")]

    # ------------------------------------------------------------------
    # Output
    # ------------------------------------------------------------------
    output_data = {
        "summary": {
            "total_subdomains": len(all_results),
            "potential_takeovers": total_takeovers,
            "targets_scanned": len(targets),
        },
        "results": all_results,
    }

    json_output = json.dumps(
        output_data,
        indent=2 if args.pretty else None
    )

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(json_output)

        print("\n========== Scan Summary ==========")
        print(f"Targets scanned          : {len(targets)}")
        print(f"Total subdomains analyzed: {len(all_results)}")
        print(f"Potential takeovers found: {total_takeovers}")
        print("=================================\n")
        print(f"[+] Results saved to {args.output}")
    else:
        print(json_output)