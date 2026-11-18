## TrustLeak integration (optional, separate project)

ShadowSaaS can optionally hand its results off to **TrustLeak**, a
companion tool that correlates active applications against the
dangling subdomains found here, surfacing trust relationships that
extend takeover risk beyond the subdomain itself (shared cookies, CSP
references, confirmed CORS misconfigurations, and more).

TrustLeak is a separate, standalone project — not bundled with
ShadowSaaS. To use it:

```powershell
git clone https://github.com/jbonagura/trustleak.git
```

Place the cloned `trustleak/` folder as a sibling of this one (or
inside it — both layouts are detected automatically), then run:

```powershell
python shadow_saas_surface.py example.com --trustleak
```

For active-probe analyzers (JS, OAuth/OIDC discovery, CORS reflection)
and a saved findings file you can reuse later without re-running them,
add `--allow-active-probes` and `--trustleak-output`:

```powershell
python shadow_saas_surface.py example.com --trustleak --allow-active-probes --trustleak-output findings.json --trustleak-html report.html
```
Or use `--all` as a shorthand for the same two decisions
(`--trustleak --allow-active-probes`), with every output file
auto-named from the domain and timestamp for anything you didn't
specify yourself:

```powershell
python shadow_saas_surface.py example.com --all
```

`--all` still respects each active analyzer's own per-analyzer
confirmation prompt past its request-volume threshold — it only skips
the two higher-level decisions (continue into TrustLeak, allow active
probes), not those volume safeguards.

See [trustleak](https://github.com/jbonagura/trustleak) for details,
including `--render-from` for regenerating TrustLeak's HTML report from
a saved findings file without touching the network again.

## Proxy support (v1.1+)

ShadowSaaS can route its HTTP traffic through a proxy — useful for
inspecting its requests in Burp/mitmproxy during development, or for
routing through a client-provided jump host (PuTTY/SSH dynamic
forwarding) during an engagement.

```bash
# Through Burp (or any HTTP/HTTPS proxy)
python shadow_saas_surface.py example.com --proxy http://127.0.0.1:8080

# Through an SSH/PuTTY dynamic tunnel (ssh -D 1080 / PuTTY Dynamic forwarding)
python shadow_saas_surface.py example.com --proxy socks5h://127.0.0.1:1080
```

Accepted schemes: `http://`, `https://`, `socks5://`, `socks5h://`.
`socks5h://` resolves the target hostname through the proxy as well;
`socks5://` resolves it locally first. For SOCKS proxies, install the
optional dependency:

```bash
pip install requests[socks]
```

**What is and isn't proxied:** HTTP probes against subdomains and the
three CT log lookups (`crt.sh`, `certspotter`, `hackertarget`) go
through the proxy. The initial CNAME/A DNS resolution does **not** —
it's a raw DNS query, not HTTP, so a `requests` proxy can't intercept
it. If full-traffic routing matters for an engagement, route that at
the OS/network level (e.g. `proxychains`) rather than relying on
`--proxy` alone.

### Inspecting CT log traffic through an intercepting proxy

By default, CT log lookups verify TLS certificates (`verify=True`).
An intercepting proxy like Burp presents its own CA, which `requests`
won't trust out of the box — you'll see a `CERTIFICATE_VERIFY_FAILED`
error. To inspect that traffic too, export the proxy's CA and pass it:

```bash
# Burp: Proxy > Options > Import / Export CA Certificate > Certificate in DER format
openssl x509 -inform DER -in burp_cacert.der -out burp_cacert.pem

python shadow_saas_surface.py example.com --proxy http://127.0.0.1:8080 --proxy-ca burp_cacert.pem
```

`--proxy-ca` only affects the CT log requests. Subdomain probes
(`http_probe`) already run with `verify=False`, since dangling or
expired certificates on abandoned subdomains are an expected, common
case there — not a signal to flag.

### If a certificate error happens without `--proxy-ca`

A certificate verification failure while `--proxy` is active and no
`--proxy-ca` is given is treated as systemic — the same untrusted CA
will fail identically against every CT log provider, so the tool fails
fast instead of retrying. The **entire target** is skipped (including
`--speculative`/`--bruteforce` fallbacks), and a note is added to
`summary.warnings` in the JSON/HTML output so this doesn't read as a
genuine zero-subdomain result:

```json
{
  "summary": {
    "total_subdomains": 0,
    "potential_takeovers": 0,
    "targets_scanned": 1,
    "warnings": [
      "Scan of example.com was aborted entirely due to a proxy certificate error. ..."
    ]
  },
  "results": []
}
```

Fix with `--proxy-ca` (above) or drop `--proxy` for that run, then
re-run before trusting a "0 found" result.

