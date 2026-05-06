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
    "192.30.252.153",
    "192.30.252.154",
    "185.199.108.153",
    "185.199.109.153",
    "185.199.110.153",
    "185.199.111.153",
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

# Non-HTTP protocol indicators — subdomains/targets containing these labels
# will never respond to HTTP probes even when fully active (LDAP, VPN, etc.).
# Used to avoid false positives when http_status is null for non-HTTP services.
NON_HTTP_INDICATORS = [
    "ldap", "ldaps", "smtp", "ftp", "sftp",
    "rdp", "ssh", "sql", "db", "database",
    "vpn", "radius", "sip", "voip",
]

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

def _is_non_http_endpoint(_sub_name, _dns_tgt):
    """Return True if subdomain/target name suggests a non-HTTP protocol service.

    Endpoints fronting LDAP, VPN, SMTP, etc. will never respond to HTTP probes
    even when fully active. A null HTTP status for these is expected behaviour
    and should not be treated as an orphan signal.
    """
    label = (_sub_name or "").lower()
    tgt   = (_dns_tgt or "").lower()
    return any(ind in label or ind in tgt for ind in NON_HTTP_INDICATORS)

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
            if _is_non_http_endpoint(subdomain, dns_target):
                reasons.append(
                    "Azure app unreachable via HTTP"
                    " - likely non-HTTP protocol endpoint (not a takeover)"
                )
            else:
                takeover_possible = True
                score += 40
                reasons.append(
                    "Azure app unreachable (probe failed) - possible orphaned app"
                )
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
            if _is_non_http_endpoint(subdomain, dns_target):
                reasons.append(
                    "Traffic Manager backend unreachable via HTTP"
                    " - likely non-HTTP protocol endpoint (not a takeover)"
                )
            else:
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



def _render_html_report(_report_data):
    """Render scan results as a self-contained HTML report string."""
    summary = _report_data.get("summary", {})
    results = _report_data.get("results", [])

    total     = summary.get("total_subdomains", 0)
    takeovers = summary.get("potential_takeovers", 0)
    scanned   = summary.get("targets_scanned", 0)

    confidence_order = {"high": 0, "medium": 1, "low": 2, "speculative": 3}
    results_sorted = sorted(
        results,
        key=lambda r: (
            0 if r.get("takeover_possible") else 1,
            confidence_order.get(r.get("confidence", "low"), 9),
            -(r.get("risk_score") or 0),
        ),
    )

    def badge(confidence):
        """Return HTML badge for confidence level."""
        colours = {
            "high":        ("cf-badge cf-badge-high",        "HIGH"),
            "medium":      ("cf-badge cf-badge-medium",      "MEDIUM"),
            "low":         ("cf-badge cf-badge-low",         "LOW"),
            "speculative": ("cf-badge cf-badge-speculative", "SPECULATIVE"),
        }
        cls, label = colours.get(confidence, ("cf-badge cf-badge-low", confidence.upper()))
        return f'<span class="{cls}">{label}</span>'

    def score_bar(score):
        """Return a risk-score progress bar."""
        pct = min(max(score or 0, 0), 100)
        clr = "#D32027" if pct >= 70 else ("#e07b00" if pct >= 45 else "#00a878")
        return (
            f'<div class="score-wrap">'
            f'<div class="score-bar" style="width:{pct}%;background:{clr}"></div>'
            f'<span class="score-num">{pct}</span>'
            f'</div>'
        )

    def row(r):
        """Return HTML table row for one result."""
        sub         = r.get("subdomain", "")
        takeover    = r.get("takeover_possible", False)
        dns_target  = r.get("dns_target") or "—"
        saas        = r.get("saas") or "—"
        http_status = r.get("http_status")
        status_str  = str(http_status) if http_status is not None else "—"
        risk        = r.get("risk_score", 20)
        conf        = r.get("confidence", "low")
        analysis    = r.get("analysis") or []
        row_cls     = "row-takeover" if takeover else ""
        takeover_cell = (
            '<span class="pill pill-yes">&#9888; YES</span>' if takeover
            else '<span class="pill pill-no">NO</span>'
        )
        analysis_html = (
            "".join(f"<li>{a}</li>" for a in analysis) if analysis else "<li>—</li>"
        )
        inspect_url = f"https://web-check.xyz/check/{sub}"
        inspect_btn = (
            f'<a class="inspect-btn" href="{inspect_url}" target="_blank" '
            f'rel="noopener noreferrer">&#128269; Inspect</a>'
        )
        return f"""
        <tr class="{row_cls}">
          <td class="td-sub"><span class="subdomain">{sub}</span></td>
          <td>{takeover_cell}</td>
          <td>{score_bar(risk)}</td>
          <td>{badge(conf)}</td>
          <td class="td-mono">{dns_target}</td>
          <td class="td-saas">{saas}</td>
          <td class="td-status">{status_str}</td>
          <td><ul class="analysis-list">{analysis_html}</ul></td>
          <td>{inspect_btn}</td>
        </tr>"""

    rows_html = "\n".join(row(r) for r in results_sorted)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>ShadowSaaS Report</title>
<link rel="preconnect" href="https://fonts.googleapis.com"/>
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin/>
<link href="https://fonts.googleapis.com/css2?family=Lato:wght@300;400;700;900&family=Share+Tech+Mono&display=swap" rel="stylesheet"/>
<style>
  :root {{
    --bg:        #031B26;
    --surface:   #01161E;
    --surface2:  #063348;
    --border:    #0a4a63;
    --teal:      #004E63;
    --teal-lt:   #006b87;
    --red:       #D32027;
    --red-dk:    #a81820;
    --text:      #cdd9e0;
    --text-dim:  #7a9aaa;
    --muted:     #3d6070;
    --takeover:  rgba(211,32,39,.08);
    --radius:    5px;
  }}

  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}

  body {{
    background: var(--bg);
    color: var(--text);
    font-family: 'Lato', sans-serif;
    font-size: 13px;
    line-height: 1.6;
    min-height: 100vh;
  }}

  a {{ color: var(--teal-lt); text-decoration: none; transition: color .15s; }}
  a:hover {{ color: #fff; }}

  /* ── header ── */
  .header {{
    background: linear-gradient(160deg, #020f18 0%, var(--teal) 100%);
    border-bottom: 3px solid var(--red);
    padding: 36px 48px 28px;
    position: relative;
    overflow: hidden;
  }}
  .header::before {{
    content: "";
    position: absolute; inset: 0;
    background:
      repeating-linear-gradient(0deg,transparent,transparent 39px,rgba(0,78,99,.15) 40px),
      repeating-linear-gradient(90deg,transparent,transparent 39px,rgba(0,78,99,.15) 40px);
    pointer-events: none;
  }}
  .header::after {{
    content: "";
    position: absolute;
    right: -60px; top: -60px;
    width: 320px; height: 320px;
    border-radius: 50%;
    background: radial-gradient(circle, rgba(211,32,39,.18) 0%, transparent 70%);
    pointer-events: none;
  }}
  .header-inner {{ position: relative; z-index: 1; }}
  .logo {{
    font-size: 11px;
    letter-spacing: .22em;
    text-transform: uppercase;
    color: rgba(255,255,255,.55);
    margin-bottom: 8px;
    font-family: 'Share Tech Mono', monospace;
  }}
  h1 {{
    font-family: 'Lato', sans-serif;
    font-size: 42px;
    font-weight: 900;
    color: #fff;
    letter-spacing: -1px;
    line-height: 1;
    text-transform: uppercase;
  }}
  h1 .red {{ color: var(--red); }}
  .subtitle {{
    font-size: 12px;
    color: rgba(255,255,255,.45);
    margin-top: 8px;
    font-family: 'Share Tech Mono', monospace;
    letter-spacing: .04em;
  }}
  .subtitle a {{
    color: rgba(255,255,255,.65);
    border-bottom: 1px solid rgba(255,255,255,.2);
    padding-bottom: 1px;
  }}
  .subtitle a:hover {{ color: #fff; border-color: #fff; }}

  /* ── stat cards ── */
  .stats {{
    display: flex;
    gap: 16px;
    padding: 28px 48px;
    flex-wrap: wrap;
  }}
  .stat-card {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 22px 28px;
    min-width: 160px;
    flex: 1;
    position: relative;
    overflow: hidden;
  }}
  .stat-card::before {{
    content: "";
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 3px;
    background: var(--border);
  }}
  .stat-card.teal::before  {{ background: var(--teal-lt); }}
  .stat-card.danger::before {{ background: var(--red); }}
  .stat-card.neutral::before {{ background: var(--muted); }}
  .stat-label {{
    font-size: 10px;
    text-transform: uppercase;
    letter-spacing: .18em;
    color: var(--text-dim);
    font-weight: 700;
  }}
  .stat-value {{
    font-family: 'Lato', sans-serif;
    font-size: 54px;
    font-weight: 900;
    color: #fff;
    line-height: 1;
    margin-top: 6px;
    letter-spacing: -2px;
  }}
  .stat-card.teal   .stat-value {{ color: var(--teal-lt); }}
  .stat-card.danger .stat-value {{ color: var(--red); }}

  /* ── toolbar ── */
  .toolbar {{
    padding: 0 48px 18px;
    display: flex;
    gap: 10px;
    flex-wrap: wrap;
    align-items: center;
    border-bottom: 1px solid var(--border);
    margin-bottom: 4px;
  }}
  .filter-btn {{
    background: var(--surface);
    border: 1px solid var(--border);
    color: var(--text-dim);
    padding: 6px 16px;
    border-radius: 20px;
    cursor: pointer;
    font-size: 11px;
    font-family: 'Lato', sans-serif;
    font-weight: 700;
    letter-spacing: .06em;
    text-transform: uppercase;
    transition: all .15s;
  }}
  .filter-btn:hover {{
    border-color: var(--teal-lt);
    color: #fff;
  }}
  .filter-btn.active {{
    background: var(--teal);
    border-color: var(--teal-lt);
    color: #fff;
  }}
  .filter-btn.active-danger {{
    background: var(--red-dk);
    border-color: var(--red);
    color: #fff;
  }}
  #search {{
    margin-left: auto;
    background: var(--surface);
    border: 1px solid var(--border);
    color: var(--text);
    padding: 7px 14px;
    border-radius: var(--radius);
    font-size: 12px;
    font-family: 'Lato', sans-serif;
    width: 240px;
    outline: none;
    transition: border .15s;
  }}
  #search:focus {{ border-color: var(--teal-lt); }}
  #search::placeholder {{ color: var(--muted); }}

  /* ── table ── */
  .table-wrap {{
    padding: 16px 48px 48px;
    overflow-x: auto;
  }}
  table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 12px;
  }}
  thead tr {{
    background: var(--surface2);
    border-bottom: 2px solid var(--teal);
  }}
  th {{
    padding: 11px 12px;
    text-align: left;
    font-size: 10px;
    text-transform: uppercase;
    letter-spacing: .14em;
    color: var(--teal-lt);
    font-weight: 700;
    white-space: nowrap;
    font-family: 'Lato', sans-serif;
  }}
  td {{
    padding: 10px 12px;
    border-bottom: 1px solid rgba(10,74,99,.5);
    vertical-align: top;
  }}
  tr:hover td {{ background: rgba(0,78,99,.12); }}
  .row-takeover td {{ background: var(--takeover); }}
  .row-takeover:hover td {{ background: rgba(211,32,39,.14); }}

  /* ── cells ── */
  .subdomain {{
    font-family: 'Share Tech Mono', monospace;
    color: #fff;
    font-size: 12px;
    word-break: break-all;
  }}
  .td-mono {{
    font-family: 'Share Tech Mono', monospace;
    color: var(--text-dim);
    font-size: 11px;
    word-break: break-all;
    max-width: 200px;
  }}
  .td-saas {{
    font-family: 'Share Tech Mono', monospace;
    font-size: 11px;
    color: var(--teal-lt);
  }}
  .td-status {{
    font-family: 'Share Tech Mono', monospace;
    font-size: 12px;
    font-weight: 700;
    color: var(--text);
  }}

  /* ── pills ── */
  .pill {{
    display: inline-block;
    padding: 3px 10px;
    border-radius: 20px;
    font-size: 10px;
    font-weight: 700;
    letter-spacing: .08em;
    font-family: 'Lato', sans-serif;
  }}
  .pill-yes {{ background: rgba(211,32,39,.2); color: #f07070; border: 1px solid rgba(211,32,39,.45); }}
  .pill-no  {{ background: rgba(0,168,120,.12); color: #00a878; border: 1px solid rgba(0,168,120,.3); }}

  /* ── confidence badges ── */
  .cf-badge {{
    display: inline-block;
    padding: 2px 8px;
    border-radius: 3px;
    font-size: 9px;
    font-weight: 700;
    letter-spacing: .12em;
    font-family: 'Lato', sans-serif;
    text-transform: uppercase;
  }}
  .cf-badge-high        {{ background: rgba(211,32,39,.22);  color: #f07070; }}
  .cf-badge-medium      {{ background: rgba(224,123,0,.18);  color: #e07b00; }}
  .cf-badge-low         {{ background: rgba(61,96,112,.35);  color: #7a9aaa; }}
  .cf-badge-speculative {{ background: rgba(100,80,200,.2);  color: #9b8de8; }}

  /* ── score bar ── */
  .score-wrap {{
    display: flex;
    align-items: center;
    gap: 8px;
    min-width: 110px;
  }}
  .score-bar {{
    height: 5px;
    border-radius: 3px;
    flex: 1;
    max-width: 70px;
  }}
  .score-num {{
    font-family: 'Share Tech Mono', monospace;
    font-size: 11px;
    color: var(--text-dim);
    min-width: 22px;
  }}

  /* ── analysis list ── */
  .analysis-list {{
    list-style: none;
    padding: 0;
    max-width: 340px;
  }}
  .analysis-list li {{
    font-size: 11px;
    color: var(--text-dim);
    padding: 1px 0 1px 12px;
    position: relative;
    line-height: 1.5;
  }}
  .analysis-list li::before {{
    content: "›";
    position: absolute;
    left: 0;
    color: var(--teal-lt);
  }}

  /* ── inspect button ── */
  .inspect-btn {{
    display: inline-block;
    padding: 4px 12px;
    border-radius: var(--radius);
    font-size: 10px;
    font-family: 'Lato', sans-serif;
    font-weight: 700;
    letter-spacing: .06em;
    text-transform: uppercase;
    color: var(--teal-lt);
    border: 1px solid var(--teal);
    text-decoration: none;
    white-space: nowrap;
    transition: all .15s;
  }}
  .inspect-btn:hover {{
    background: var(--teal);
    color: #fff;
    border-color: var(--teal-lt);
  }}

  tr.hidden {{ display: none; }}

  /* ── footer ── */
  .footer {{
    text-align: center;
    padding: 24px 48px;
    font-size: 11px;
    color: var(--muted);
    font-family: 'Lato', sans-serif;
    letter-spacing: .04em;
    border-top: 1px solid var(--border);
  }}
  .footer a {{
    color: var(--text-dim);
    border-bottom: 1px solid var(--muted);
    padding-bottom: 1px;
  }}
  .footer a:hover {{ color: #fff; border-color: #fff; }}
</style>
</head>
<body>

<div class="header">
  <div class="header-inner">
    <div class="logo">&#9632; Secure Ideas · Professionally Evil</div>
    <h1>Shadow<span class="red">SaaS</span> Surface Scanner</h1>
    <div class="subtitle">
      Subdomain Takeover &amp; Dangling CNAME Report &nbsp;·&nbsp; v1.0
      &nbsp;·&nbsp;
      <a href="https://www.linkedin.com/in/jordan-bonagura" target="_blank" rel="noopener noreferrer">Jordan Bonagura</a>
      &nbsp;·&nbsp;
      <a href="https://www.secureideas.com" target="_blank" rel="noopener noreferrer">Secure Ideas - Professionally Evil</a>
    </div>
  </div>
</div>

<div class="stats">
  <div class="stat-card teal">
    <div class="stat-label">Targets Scanned</div>
    <div class="stat-value">{scanned}</div>
  </div>
  <div class="stat-card neutral">
    <div class="stat-label">Subdomains Analysed</div>
    <div class="stat-value">{total}</div>
  </div>
  <div class="stat-card danger">
    <div class="stat-label">Potential Takeovers</div>
    <div class="stat-value">{takeovers}</div>
  </div>
</div>

<div class="toolbar">
  <button class="filter-btn active" onclick="filterRows('all',this)">All</button>
  <button class="filter-btn" onclick="filterRows('takeover',this)">&#9888; Takeovers only</button>
  <button class="filter-btn" onclick="filterRows('high',this)">High confidence</button>
  <button class="filter-btn" onclick="filterRows('active',this)">DNS active</button>
  <input id="search" type="text" placeholder="Search subdomain / target…" oninput="searchRows(this.value)"/>
</div>

<div class="table-wrap">
  <table id="results-table">
    <thead>
      <tr>
        <th>Subdomain</th>
        <th>Takeover</th>
        <th>Risk Score</th>
        <th>Confidence</th>
        <th>DNS Target</th>
        <th>SaaS</th>
        <th>HTTP</th>
        <th>Analysis</th>
        <th>Inspect</th>
      </tr>
    </thead>
    <tbody id="results-body">
{rows_html}
    </tbody>
  </table>
</div>

<div class="footer">
  Generated by ShadowSaaS Surface Scanner v1.0 &nbsp;&middot;&nbsp;
  <a href="https://www.linkedin.com/in/jordan-bonagura" target="_blank" rel="noopener noreferrer">Jordan Bonagura</a>
  &nbsp;&middot;&nbsp;
  <a href="https://www.secureideas.com" target="_blank" rel="noopener noreferrer">Secure Ideas - Professionally Evil</a>
</div>

<script>
  const rows = Array.from(document.querySelectorAll('#results-body tr'));
  let currentFilter = 'all';
  let currentSearch = '';

  function applyFilters() {{
    rows.forEach(r => {{
      const takeover = r.classList.contains('row-takeover');
      const conf     = r.querySelector('.cf-badge');
      const confText = conf ? conf.textContent.trim().toLowerCase() : '';
      const dnsCell  = r.querySelector('.td-mono');
      const dnsActive = dnsCell ? dnsCell.textContent.trim() !== '—' : false;
      const text     = r.textContent.toLowerCase();

      let show = true;
      if (currentFilter === 'takeover' && !takeover)           show = false;
      if (currentFilter === 'high'     && confText !== 'high') show = false;
      if (currentFilter === 'active'   && !dnsActive)          show = false;
      if (currentSearch  && !text.includes(currentSearch))     show = false;

      r.classList.toggle('hidden', !show);
    }});
  }}

  function filterRows(type, btn) {{
    currentFilter = type;
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active','active-danger'));
    btn.classList.add(type === 'takeover' ? 'active-danger' : 'active');
    applyFilters();
  }}

  function searchRows(val) {{
    currentSearch = val.toLowerCase();
    applyFilters();
  }}
</script>
</body>
</html>"""


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

Output options:
  -o / --output    — Save results as JSON file
  --pretty         — Pretty-print JSON output
  --html FILE      — Generate a self-contained HTML report
  --quiet          — Suppress JSON stdout (use with --html or -o)
  --takeovers-only — Only include takeover findings in output

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

  # Save results as JSON
  python shadow_saas_surface.py example.com -o results.json --pretty

  # Generate HTML report only (no JSON printed to terminal)
  python shadow_saas_surface.py example.com --html report.html --quiet

  # JSON + HTML simultaneously, suppress terminal output
  python shadow_saas_surface.py example.com -o results.json --html report.html --quiet

  # Only show takeover findings in output
  python shadow_saas_surface.py example.com --takeovers-only --html report.html --quiet

  # Scan a file of targets and save both formats
  python shadow_saas_surface.py --file targets.txt -o results.json --html report.html --quiet

File format (targets.txt):
  example.com
  staging.example.com
  # Lines starting with # are treated as comments and skipped
  another.com
        """    )

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
        "--html",
        metavar="FILE",
        help="Write a self-contained HTML report to FILE (e.g. report.html)."
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help=(
            "Suppress JSON stdout output. "
            "Useful when using --html or --output to avoid printing to terminal."
        )
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
    elif not args.quiet:
        print(json_output)

    if args.html:
        html = _render_html_report(output_data)
        with open(args.html, "w", encoding="utf-8") as fh:
            fh.write(html)
        print(f"[+] HTML report saved to {args.html}")