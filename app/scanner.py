"""Security checks. Passive checks run for everyone; active checks (ports, exposed
paths) run only for domains whose ownership has been verified."""
import ipaddress, json, re, socket, ssl, time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from urllib.parse import urlencode, urljoin, urlparse

import dns.query
import dns.resolver
import dns.zone
import requests

UA = {"User-Agent": "SiteScanBot/0.1 (security self-check; abuse@yourdomain.example)"}
TIMEOUT = 8
POINTS = {"critical": 30, "high": 20, "medium": 10, "low": 4, "info": 0}
ORDER = ["critical", "high", "medium", "low", "info"]
DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "k1", "k2",
                  "s1", "s2", "mail", "dkim", "smtp", "zoho", "mandrill"]
RISKY_PORTS = {21: ("FTP", "medium"), 22: ("SSH", "low"), 23: ("Telnet", "high"),
               445: ("Windows file sharing (SMB)", "high"), 2375: ("Docker API (unauthenticated)", "critical"),
               3306: ("MySQL database", "high"), 3389: ("Remote Desktop", "high"), 5432: ("PostgreSQL database", "high"),
               5984: ("CouchDB database", "high"), 6379: ("Redis database", "high"), 9200: ("Elasticsearch", "high"),
               11211: ("Memcached", "medium"), 27017: ("MongoDB database", "high")}
XSS_MARKER = "sScAn<x>9f1"
SQLI_ERRORS = [r"sql syntax", r"mysql_fetch", r"unclosed quotation mark", r"quoted string not properly terminated",
              r"pg_query\(\)", r"postgresql.*error", r"ora-\d{5}", r"sqlite3\.OperationalError", r"sqlstate\[",
              r"you have an error in your sql"]
WAF_SIGNS = [("cf-ray", "Cloudflare"), ("x-sucuri-id", "Sucuri"), ("x-akamai-transformed", "Akamai"),
            ("x-iinfo", "Incapsula"), ("server", "cloudflare"), ("x-cdn", "generic CDN/WAF")]
ADMIN_PATHS = ["/admin", "/administrator", "/wp-admin/", "/login", "/admin/login", "/user/login", "/manager/html", "/cpanel"]
TAKEOVER_CNAME_SUFFIXES = [".s3.amazonaws.com", ".s3-website", ".github.io", ".herokuapp.com", ".herokudns.com",
                           ".azurewebsites.net", ".trafficmanager.net", ".cloudapp.net", ".shopify.com", ".myshopify.com",
                           ".wordpress.com", ".fastly.net", ".surge.sh", ".bitbucket.io", ".ngrok.io", ".unbouncepages.com",
                           ".readme.io", ".helpjuice.com", ".webflow.io", ".netlify.app", ".zendesk.com"]
WEAK_CIPHERS = "ALL:eNULL:aNULL:EXPORT:RC4:@SECLEVEL=0"

TRAVERSAL_PAYLOADS = ["../../../../../../etc/passwd", "..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
                      "....//....//....//....//....//....//etc/passwd", "..\\..\\..\\..\\..\\windows\\win.ini"]
EXTRA_PATH_PROBES = [
    ("/.DS_Store", lambda b: b[:4] == "\x00\x00\x00\x01" or "Bud1" in b, "medium", "macOS .DS_Store file is public",
     "This file can reveal the names of other files and folders on the server.", "Delete .DS_Store files from the web root and add them to your deploy exclude list."),
    ("/config.php.bak", lambda b: "<html" not in b.lower() and len(b) > 10, "high", "A backup config file is public",
     "Backup files with .bak often contain database credentials in plain text.", "Remove backup files from the web root; never leave editor/deploy backups there."),
    ("/backup.sql", lambda b: re.search(r"(?i)create table|insert into", b), "critical", "A database backup (.sql) is public",
     "A SQL dump can contain your entire database, including user accounts.", "Remove it immediately, rotate any exposed credentials, and never store backups in the web root."),
    ("/swagger.json", lambda b: '"swagger"' in b or '"openapi"' in b, "low", "API documentation (Swagger/OpenAPI) is public",
     "This maps out your API's internal endpoints for anyone to read.", "Restrict API docs to authenticated or internal users in production."),
    ("/.svn/entries", lambda b: len(b) > 5 and "<html" not in b.lower(), "high", "An old Subversion repository is public",
     "Like exposed .git, this can leak your full source history.", "Remove the .svn folder from the web root and block it in your server config."),
]



def F(id, sev, title, plain, fix):
    return {"id": id, "severity": sev, "title": title, "plain": plain, "fix": fix}


# ---------- SSRF-safe networking ----------
def resolve_public(host):
    """Resolve host and refuse anything that is not a public internet address."""
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise ValueError(f"{host} does not resolve") from e
    ips = sorted({i[4][0].split("%")[0] for i in infos})
    if not ips or not all(ipaddress.ip_address(i).is_global for i in ips):
        raise ValueError(f"{host} resolves to a non-public address; refusing to scan")
    return ips


def pick_ip(ips):
    v4 = [i for i in ips if ":" not in i]
    return (v4 or ips)[0]


def safe_get(url, maxbytes=100_000, redirects=5, verify=True):
    """GET with manual redirects; every hop is re-resolved and checked."""
    for _ in range(redirects + 1):
        p = urlparse(url)
        if p.scheme not in ("http", "https") or not p.hostname:
            return None
        resolve_public(p.hostname)
        r = requests.get(url, headers=UA, timeout=TIMEOUT, allow_redirects=False,
                         stream=True, verify=verify)
        try:
            if r.is_redirect and r.headers.get("location"):
                url = urljoin(url, r.headers["location"])
                continue
            body = r.raw.read(maxbytes, decode_content=True)
            try:
                cookies = r.raw.headers.getlist("Set-Cookie")
            except Exception:
                cookies = []
            return {"status": r.status_code, "url": url, "cookies": cookies,
                    "headers": {k.lower(): v for k, v in r.headers.items()},
                    "body": body.decode("utf-8", "ignore")}
        finally:
            r.close()
    return None


# ---------- passive checks ----------
def check_tls(domain, ip):
    f, info = [], {}
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((ip, 443), timeout=TIMEOUT) as s, \
                ctx.wrap_socket(s, server_hostname=domain) as t:
            cert, info["tls_version"] = t.getpeercert(), t.version()
        exp = ssl.cert_time_to_seconds(cert["notAfter"])
        days = int((exp - time.time()) // 86400)
        subj = dict(x[0] for x in cert.get("subject", ()))
        iss = dict(x[0] for x in cert.get("issuer", ()))
        info["cert_days_left"] = days
        info["cert"] = {"subject": subj.get("commonName", ""), "issuer": iss.get("organizationName") or iss.get("commonName", ""),
                        "not_after": datetime.fromtimestamp(exp, timezone.utc).strftime("%Y-%m-%d"), "days_left": days,
                        "san": [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"][:12]}
        if days <= 30:
            sev = "high" if days <= 14 else "medium"
            f.append(F("cert_expiring", sev, f"Certificate expires in {days} days",
                       "When it expires, browsers will block visitors with a full-page warning.",
                       "Renew now and make sure auto-renewal is switched on at your host or certificate provider."))
    except ssl.SSLCertVerificationError as e:
        info["cert_error"] = e.verify_message
        f.append(F("cert_invalid", "critical", "Security certificate is not trusted",
                   f"Browsers show a scary warning to visitors ({e.verify_message}).",
                   "Reissue a certificate that covers exactly this domain name and includes the full chain. Most hosts do this in one click under SSL/Domains."))
        return f, info
    except OSError:
        f.append(F("no_https", "critical", "No working HTTPS",
                   "Connections to your site can be read or altered, and browsers warn visitors.",
                   "Turn on the free certificate your host provides (Wix, Squarespace, Shopify and WordPress.com do it automatically under Domains/SSL). On your own server use Let's Encrypt (certbot), or put Cloudflare in front."))
        return f, info
    try:  # best effort: skipped if the local OpenSSL refuses TLS 1.0/1.1 entirely
        c2 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        c2.check_hostname, c2.verify_mode = False, ssl.CERT_NONE
        c2.minimum_version, c2.maximum_version = ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1
        try:
            c2.set_ciphers("ALL:@SECLEVEL=0")
        except ssl.SSLError:
            pass
        with socket.create_connection((ip, 443), timeout=TIMEOUT) as s, \
                c2.wrap_socket(s, server_hostname=domain):
            f.append(F("old_tls", "medium", "Outdated encryption (TLS 1.0/1.1) still accepted",
                       "Old protocols have known weaknesses and are no longer allowed by modern standards.",
                       "In your host or CDN settings set the minimum TLS version to 1.2. On Cloudflare: SSL/TLS > Edge Certificates > Minimum TLS Version."))
    except Exception:
        pass
    return f, info


def check_http_redirect(domain):
    f = []
    try:
        resolve_public(domain)
        r = requests.get(f"http://{domain}/", headers=UA, timeout=TIMEOUT, allow_redirects=False)
        if not (r.is_redirect and r.headers.get("location", "").startswith("https://")):
            f.append(F("no_https_redirect", "medium", "http:// visitors are not sent to the secure site",
                       "Anyone typing the plain address or following an old link stays on an unprotected connection.",
                       "Enable 'Force HTTPS' / 'Always use HTTPS' (Cloudflare: SSL/TLS > Edge Certificates; WordPress: set both URLs to https in Settings > General; Shopify/Squarespace: SSL settings)."))
    except requests.RequestException:
        pass
    return f, {}


def check_headers(domain):
    f, info = [], {}
    t0 = time.time()
    try:
        try:
            r = safe_get(f"https://{domain}/")
        except requests.exceptions.SSLError:
            r = safe_get(f"https://{domain}/", verify=False)
    except (requests.RequestException, ValueError) as e:
        return f, {"headers_error": str(e)[:120]}
    if not r:
        return f, info
    h = r["headers"]
    info["response_ms"] = int((time.time() - t0) * 1000)
    body = r["body"].lower()
    m = re.search(r"<title[^>]*>(.*?)</title>", r["body"], re.I | re.S)
    info["title"] = re.sub(r"\s+", " ", m.group(1)).strip()[:120] if m else ""
    tech = []
    for needle, name in (("wp-content", "WordPress"), ("/_next/", "Next.js"), ("cdn.shopify.com", "Shopify"), ("wixstatic.com", "Wix"),
                         ("squarespace", "Squarespace"), ("drupal", "Drupal"), ("joomla", "Joomla"), ("webflow", "Webflow")):
        if needle in body:
            tech.append(name)
    if "cf-ray" in h:
        tech.append("Cloudflare")
    for key in ("server", "x-powered-by"):
        if h.get(key):
            tech.append(h[key][:60])
    info["tech"] = list(dict.fromkeys(tech))
    srv = h.get("server", "") + " " + h.get("x-powered-by", "")
    if re.search(r"[A-Za-z-]+/\d+(\.\d+)+", srv):
        f.append(F("version_disclosure", "low", "Server software and version are advertised",
                   f"Your server tells everyone exactly what it runs ({srv.strip()[:60]}), which helps attackers pick known exploits.",
                   "Hide version banners: nginx 'server_tokens off;', Apache 'ServerTokens Prod', PHP 'expose_php = Off'."))
    cookies = r.get("cookies", [])
    if cookies:
        names = lambda bad: ", ".join(c.split("=")[0] for c in bad[:5])
        nosec = [c for c in cookies if "secure" not in c.lower()]
        nohttp = [c for c in cookies if "httponly" not in c.lower()]
        nosame = [c for c in cookies if "samesite" not in c.lower()]
        if nosec:
            f.append(F("cookie_secure", "medium", "Cookies missing the Secure flag", f"These cookies can travel over unprotected connections: {names(nosec)}.",
                       "Set the Secure attribute on cookies (framework session settings, or your CMS security plugin)."))
        if nohttp:
            f.append(F("cookie_httponly", "low", "Cookies missing HttpOnly", f"Scripts on the page can read these cookies: {names(nohttp)}.",
                       "Set HttpOnly on session and login cookies."))
        if nosame:
            f.append(F("cookie_samesite", "low", "Cookies missing SameSite", f"These cookies are sent on cross-site requests: {names(nosame)}.",
                       "Set SameSite=Lax (or Strict) on cookies."))
    csp = h.get("content-security-policy", "")
    how = "Add it as a response header in your web server, CDN (Cloudflare Transform Rules) or hosting settings; on WordPress use a plugin such as 'HTTP Headers'."
    if "strict-transport-security" not in h:
        f.append(F("no_hsts", "medium", "Browsers are not told to always use HTTPS (HSTS)",
                   "An attacker on public Wi-Fi can downgrade a visitor's connection to plain HTTP.",
                   "Send the header  Strict-Transport-Security: max-age=31536000; includeSubDomains.  " + how))
    if not csp:
        f.append(F("no_csp", "medium", "No Content-Security-Policy",
                   "If an attacker injects a script into a page, nothing stops it from running.",
                   "Start with  Content-Security-Policy-Report-Only  to learn what your site loads, then enforce a policy. " + how))
    if h.get("x-content-type-options", "").lower() != "nosniff":
        f.append(F("no_xcto", "low", "Missing X-Content-Type-Options", "Browsers may guess file types, which can turn an upload into an attack.",
                   "Send  X-Content-Type-Options: nosniff.  " + how))
    if "x-frame-options" not in h and "frame-ancestors" not in csp:
        f.append(F("no_frame", "low", "Site can be embedded in other pages (clickjacking)", "Another site can load yours invisibly and trick visitors into clicking.",
                   "Send  X-Frame-Options: SAMEORIGIN  or CSP  frame-ancestors 'self'.  " + how))
    if "referrer-policy" not in h:
        f.append(F("no_referrer", "low", "Missing Referrer-Policy", "Full page addresses (which may contain private details) are sent to other sites you link to.",
                   "Send  Referrer-Policy: strict-origin-when-cross-origin.  " + how))
    if "permissions-policy" not in h:
        f.append(F("no_permissions_policy", "low", "Missing Permissions-Policy",
                   "Without it, embedded content and scripts can use sensitive browser features (camera, microphone, geolocation) by default.",
                   "Send e.g.  Permissions-Policy: geolocation=(), camera=(), microphone=().  " + how))
    base_host = urlparse(r["url"]).hostname or domain
    cross = re.findall(r'''<script[^>]+src=["'](https?://([^"'/]+)[^"']*)["'][^>]*>''', r["body"], re.I)
    no_sri = [u for u, host in cross if host != base_host and "integrity=" not in r["body"][max(0, r["body"].find(u) - 150):r["body"].find(u) + 150]]
    if no_sri:
        f.append(F("no_sri", "low", "Third-party scripts loaded without Subresource Integrity",
                   f"{len(no_sri)} script(s) from other domains are trusted completely; if that third party is compromised, so is your site.",
                   "Add an integrity=\"sha384-...\" attribute to external <script> tags (most CDNs provide the hash)."))
    pw_inputs = re.findall(r'''<input[^>]*type=["']password["'][^>]*>''', r["body"], re.I)
    if any("autocomplete" not in tag.lower() or "autocomplete=\"on\"" in tag.lower() for tag in pw_inputs):
        f.append(F("pw_autocomplete", "info", "Password field does not disable autocomplete",
                   "Browsers may offer to save or auto-fill the password on shared computers. Most modern browsers limit this risk themselves, so treat this as a minor hardening item.",
                   "Add  autocomplete=\"new-password\"  (signup) or leave default for login forms per current browser guidance; this is low priority."))
    info["final_url"] = r["url"]
    return f, info


def txt(name):
    try:
        ans = dns.resolver.resolve(name, "TXT", lifetime=6)
        return ["".join(p.decode("utf-8", "ignore") for p in r.strings) for r in ans]
    except Exception:
        return []


def check_email(domain):
    f, info = [], {}
    dns_how = "In your DNS provider (GoDaddy, Namecheap, Cloudflare...) add a TXT record. "
    spf = [t for t in txt(domain) if t.lower().startswith("v=spf1")]
    info["spf"] = spf
    if not spf:
        f.append(F("no_spf", "high", "Anyone can send email pretending to be you (no SPF)",
                   "Without SPF, receiving servers cannot tell real email from forged email using your domain.",
                   dns_how + "Host @, value e.g.  v=spf1 include:_spf.google.com ~all  (Google Workspace) or  v=spf1 include:spf.protection.outlook.com -all  (Microsoft 365). If the domain sends no email use  v=spf1 -all."))
    elif len(spf) > 1:
        f.append(F("multi_spf", "medium", "More than one SPF record", "Receivers treat multiple SPF records as an error, so protection silently fails.",
                   "Merge them into a single TXT record."))
    else:
        s = spf[0].lower()
        if "+all" in s or "?all" in s:
            f.append(F("weak_spf", "high", "SPF allows anyone to send as you", "Your SPF record ends in a rule that permits every sender.",
                       "End the record with  ~all  or  -all."))
        elif not re.search(r"[~-]all\b", s) and "redirect=" not in s:
            f.append(F("spf_no_all", "medium", "SPF record has no closing rule", "Without a final ~all or -all, unlisted senders are not rejected.",
                       "Append  ~all  (or  -all  once you are sure all senders are listed)."))
    dm = [t for t in txt("_dmarc." + domain) if t.lower().startswith("v=dmarc1")]
    info["dmarc"] = dm
    if not dm:
        f.append(F("no_dmarc", "high", "No DMARC policy", "Forged email that claims to be from you is not blocked, and you get no reports about it.",
                   dns_how + "Host _dmarc, value  v=DMARC1; p=none; rua=mailto:you@yourdomain.com  to start monitoring, then move to p=quarantine and p=reject."))
    else:
        m = re.search(r"\bp\s*=\s*(\w+)", dm[0], re.I)
        if (m.group(1).lower() if m else "none") == "none":
            f.append(F("dmarc_none", "medium", "DMARC is monitoring only (p=none)", "Forged email is reported but still delivered, so you are effectively unprotected.",
                       "After reviewing reports, change to  p=quarantine  and later  p=reject."))
    with ThreadPoolExecutor(8) as ex:
        hits = list(ex.map(lambda s: any("p=" in t or "v=dkim1" in t.lower() for t in txt(f"{s}._domainkey.{domain}")), DKIM_SELECTORS))
    found = [s for s, ok in zip(DKIM_SELECTORS, hits) if ok]
    info["dkim_selectors_found"] = found
    if not found:
        f.append(F("dkim_unknown", "info", "DKIM not found among common selectors",
                   "We only try common selector names, so this may be a false alarm. If you send email from this domain, confirm DKIM signing is enabled in your email provider.",
                   "Google Workspace: Admin > Apps > Gmail > Authenticate email. Microsoft 365: Defender > Email authentication > DKIM."))
    return f, info


def check_caa(domain):
    try:
        dns.resolver.resolve(domain, "CAA", lifetime=6)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return [F("no_caa", "low", "No CAA record", "Any certificate authority may issue certificates for your domain.",
                  "Add a CAA record, e.g.  0 issue \"letsencrypt.org\"  for the authority you use.")], {}
    except Exception:
        pass
    return [], {}


def check_security_txt(domain):
    try:
        r = safe_get(f"https://{domain}/.well-known/security.txt", maxbytes=2000)
        if r and r["status"] == 200 and "contact:" in r["body"].lower():
            return [], {"security_txt": True}
    except Exception:
        pass
    return [F("no_security_txt", "info", "No security.txt file", "Researchers who find a problem have no official way to tell you.",
              "Publish /.well-known/security.txt with a Contact: line (see securitytxt.org).")], {"security_txt": False}


def registrable(domain):
    p = domain.split(".")
    if len(p) >= 3 and len(p[-1]) == 2 and p[-2] in {"co", "com", "org", "net", "gov", "edu", "ac"}:
        return ".".join(p[-3:])
    return ".".join(p[-2:])


def check_dns(domain):
    f, info = [], {}
    for rtype, key in (("NS", "ns"), ("MX", "mx")):
        try:
            info[key] = sorted(r.to_text().rstrip(".") for r in dns.resolver.resolve(domain, rtype, lifetime=6))
        except Exception:
            info[key] = []
    if len(info["ns"]) == 1:
        f.append(F("single_ns", "low", "Only one nameserver", "If it goes down your whole site and email go offline.", "Add a second nameserver at your DNS provider."))
    try:
        r = safe_get(f"https://rdap.org/domain/{registrable(domain)}", maxbytes=400_000)
        for ev in json.loads(r["body"]).get("events", []):
            if ev.get("eventAction") == "expiration":
                exp = datetime.fromisoformat(ev["eventDate"].replace("Z", "+00:00"))
                days = (exp - datetime.now(timezone.utc)).days
                info["domain_expiry"], info["domain_days_left"] = exp.strftime("%Y-%m-%d"), days
                if days <= 45:
                    f.append(F("domain_expiring", "high" if days <= 14 else "medium", f"Domain registration expires in {days} days",
                               "If it lapses, your website and email stop working and someone else can register the name.",
                               "Renew at your registrar and turn on auto-renew."))
    except Exception:
        pass
    return f, info


# ---------- vulnerability scan (deep, authorized only) ----------
def check_xss(domain):
    f = []
    for param in ("q", "search", "s"):
        try:
            r = safe_get(f"https://{domain}/?{urlencode({param: XSS_MARKER})}", maxbytes=400_000)
        except Exception:
            continue
        if r and r["status"] == 200 and XSS_MARKER in r["body"] and f"&lt;x&gt;" not in r["body"]:
            f.append(F("reflected_xss", "high", f"Possible reflected XSS via '{param}' parameter",
                       "A value typed into the URL is echoed back into the page without being escaped, which can let an attacker run script in a visitor's browser.",
                       "Escape all user input before writing it into HTML output, and set a Content-Security-Policy as a second layer of defense."))
            break
    return f, {}


def check_sqli_indicator(domain):
    f = []
    for param in ("id", "page", "item"):
        try:
            r = safe_get(f"https://{domain}/?{urlencode({param: "1'"})}", maxbytes=400_000)
        except Exception:
            continue
        if r and any(re.search(p, r["body"], re.I) for p in SQLI_ERRORS):
            f.append(F("sqli_indicator", "critical", f"Possible SQL injection via '{param}' parameter",
                       "A single quote in the URL produced a database error message, which often means unsanitized input reaches a SQL query.",
                       "Use parameterized queries or an ORM everywhere, never build SQL from raw input, and turn off detailed error messages in production."))
            break
    return f, {}


def check_open_redirect(domain):
    f = []
    target = "https://sitescan-redirect-test.invalid/"
    for param in ("redirect", "next", "url", "return"):
        try:
            r = safe_get(f"https://{domain}/?{urlencode({param: target})}", redirects=0, maxbytes=500)
        except Exception:
            continue
        if r and r["status"] in (301, 302, 303, 307, 308) and target.rstrip("/") in r["headers"].get("location", ""):
            f.append(F("open_redirect", "medium", f"Open redirect via '{param}' parameter",
                       "The site redirects visitors to any address supplied in the URL, which phishing links exploit to look trustworthy.",
                       "Only redirect to a fixed allow-list of internal paths, never to a URL taken directly from user input."))
            break
    return f, {}


def check_cors(domain):
    f = []
    try:
        p = urlparse(f"https://{domain}/")
        resolve_public(p.hostname)
        r = requests.get(f"https://{domain}/", headers={**UA, "Origin": "https://sitescan-cors-test.invalid"}, timeout=TIMEOUT)
        aco, acc = r.headers.get("access-control-allow-origin", ""), r.headers.get("access-control-allow-credentials", "")
        if aco == "https://sitescan-cors-test.invalid" or aco == "*" and acc.lower() == "true":
            f.append(F("cors_misconfig", "high", "CORS allows any website to read this page with credentials",
                       "Access-Control-Allow-Origin reflects an arbitrary site and allows credentials, so another website can read private data on behalf of a logged-in visitor.",
                       "Return a fixed, specific allow-list of trusted origins; never reflect the request's Origin when credentials are allowed."))
    except Exception:
        pass
    return f, {}


def check_http_methods(domain):
    f = []
    try:
        p = urlparse(f"https://{domain}/")
        resolve_public(p.hostname)
        r = requests.options(f"https://{domain}/", headers=UA, timeout=TIMEOUT)
        allow = {m.strip().upper() for m in r.headers.get("allow", "").split(",") if m.strip()}
        risky = allow & {"PUT", "DELETE", "TRACE", "CONNECT"}
        if risky:
            f.append(F("risky_methods", "medium", f"Unusual HTTP methods allowed: {', '.join(sorted(risky))}",
                       "These methods can let a visitor upload, delete or manipulate content if the server does not check permissions carefully.",
                       "Disable methods you do not need at the web server or framework level, and require authentication for the rest."))
    except Exception:
        pass
    return f, {}


def check_mixed_content(domain):
    f = []
    try:
        r = safe_get(f"https://{domain}/")
    except Exception:
        return f, {}
    if not r:
        return f, {}
    hits = re.findall(r'''(?:src|href)=["']http://[^"']+''', r["body"], re.I)
    if hits:
        f.append(F("mixed_content", "medium", "Page loads some resources over plain HTTP",
                   f"Found {len(hits)} insecure resource link(s). Browsers block or warn about these, and they can be tampered with in transit.",
                   "Change those links to https://, or protocol-relative (//), so every resource loads securely."))
    return f, {}


def check_directory_listing(domain):
    f = []
    for path in ("/images/", "/uploads/", "/backup/", "/files/", "/assets/"):
        try:
            r = safe_get(f"https://{domain}{path}", maxbytes=2000)
        except Exception:
            continue
        if r and r["status"] == 200 and re.search(r"index of /", r["body"], re.I):
            f.append(F("dir_listing" + path.strip("/"), "medium", f"Directory listing enabled at {path}",
                       "Visitors can browse and download every file in this folder, including ones never meant to be public.",
                       "Disable directory listing in your web server config (e.g. Apache 'Options -Indexes'), or add an index.html."))
    return f, {}


def check_admin_panels(domain):
    f, found = [], []
    for path in ADMIN_PATHS:
        try:
            r = safe_get(f"https://{domain}{path}", redirects=2, maxbytes=1000)
        except Exception:
            continue
        if r and r["status"] in (200, 401, 403):
            found.append(path)
    if found:
        f.append(F("admin_panel_found", "low", f"Admin or login panel reachable: {', '.join(found)}",
                   "This does not mean it is vulnerable, but it is a visible target for password-guessing attacks.",
                   "Use a strong, unique password and multi-factor authentication; consider restricting the path by IP or moving it off a guessable URL."))
    return f, {"admin_paths_found": found}


def check_waf(domain):
    try:
        r = safe_get(f"https://{domain}/")
    except Exception:
        return [], {}
    if not r:
        return [], {}
    h = r["headers"]
    names = [name for key, name in WAF_SIGNS if key in h and (key != "server" or name.lower() in h.get("server", "").lower())]
    return [], {"waf": sorted(set(names))}


def check_subdomains(domain):
    try:
        r = safe_get(f"https://crt.sh/?q=%25.{domain}&output=json", maxbytes=2_000_000)
        if not r or r["status"] != 200:
            return [], {}
        names = set()
        for row in json.loads(r["body"]):
            for n in row.get("name_value", "").split("\n"):
                n = n.strip().lower().lstrip("*.")
                if n.endswith(domain) and n != domain:
                    names.add(n)
        subs = sorted(names)[:40]
        return [], {"subdomains": subs, "subdomain_count": len(names)}
    except Exception:
        return [], {}


# ---------- deep checks (ports and exposed files) ----------
def check_cmdi(domain):
    f = []
    linux_payloads = {"cmd": ";echo SITESCANCMDI", "exec": "|echo SITESCANCMDI", "q": "`echo SITESCANCMDI`"}
    for param, payload in linux_payloads.items():
        try:
            r = safe_get(f"https://{domain}/?{urlencode({param: payload})}", maxbytes=400_000)
        except Exception:
            continue
        if r and "SITESCANCMDI" in r["body"] and payload not in r["body"]:
            f.append(F("cmd_injection", "critical", f"Possible OS command injection via '{param}' parameter",
                       "A shell metacharacter in the URL caused its command to run and its output to appear in the page, which can let an attacker run arbitrary commands on your server.",
                       "Never pass user input to a shell command. Use safe library calls instead of shell execution, and validate/allow-list any input that must be used."))
            break
    return f, {}


def check_traversal(domain):
    f = []
    for param in ("file", "page", "path", "doc", "template"):
        for payload in TRAVERSAL_PAYLOADS:
            try:
                r = safe_get(f"https://{domain}/?{urlencode({param: payload})}", maxbytes=20_000)
            except Exception:
                continue
            if r and re.search(r"root:.*:0:0:|\[fonts\]|\[extensions\]", r["body"]):
                f.append(F("path_traversal", "critical", f"Possible directory traversal via '{param}' parameter",
                           "The server returned the contents of a system file when asked for '../../etc/passwd'-style input, which means an attacker can likely read arbitrary files.",
                           "Never build file paths from raw user input. Validate against an allow-list of permitted filenames, and run the application with minimal file-system permissions."))
                return f, {}
    return f, {}


def check_wordpress(domain):
    f, info = [], {}
    try:
        r = safe_get(f"https://{domain}/readme.html", maxbytes=3000)
    except Exception:
        r = None
    if r and r["status"] == 200:
        m = re.search(r"Version\s+([\d.]+)", r["body"])
        if m:
            info["wordpress_version"] = m.group(1)
            f.append(F("wp_version_exposed", "low", f"WordPress version {m.group(1)} is publicly visible",
                       "Knowing the exact version lets an attacker look up matching known vulnerabilities.",
                       "Delete or block readme.html, and keep WordPress core, themes and plugins updated regardless."))
    try:
        r = safe_get(f"https://{domain}/wp-json/wp/v2/users", maxbytes=20_000)
        if r and r["status"] == 200 and r["body"].strip().startswith("["):
            names = re.findall(r'"slug":"([^"]+)"', r["body"])
            if names:
                f.append(F("wp_user_enum", "medium", "WordPress usernames are exposed via the REST API",
                           f"Anyone can list valid usernames ({', '.join(names[:8])}), which narrows down a password-guessing attack to those accounts.",
                           "Block anonymous access to /wp-json/wp/v2/users with a security plugin, or disable user enumeration in your theme/firewall."))
    except Exception:
        pass
    try:
        r = safe_get(f"https://{domain}/xmlrpc.php", redirects=0, maxbytes=500)
        if r and r["status"] == 200 and "XML-RPC server accepts POST" in r["body"]:
            f.append(F("wp_xmlrpc", "low", "WordPress XML-RPC is enabled",
                       "This legacy interface is a common target for password-guessing and denial-of-service abuse.",
                       "Disable xmlrpc.php if you don't need it (via a security plugin or by blocking the file)."))
    except Exception:
        pass
    return f, info


def check_cms_version(domain):
    f = []
    try:
        r = safe_get(f"https://{domain}/CHANGELOG.txt", maxbytes=2000)
        m = r and re.search(r"Drupal\s+([\d.]+)", r["body"])
        if m:
            f.append(F("drupal_version_exposed", "low", f"Drupal version {m.group(1)} is publicly visible",
                       "Knowing the exact version lets an attacker look up matching known vulnerabilities.",
                       "Remove or block CHANGELOG.txt."))
    except Exception:
        pass
    return f, {}


def check_robots_sitemap(domain):
    f, info = [], {}
    try:
        r = safe_get(f"https://{domain}/robots.txt", maxbytes=20_000)
    except Exception:
        r = None
    if r and r["status"] == 200:
        paths = re.findall(r"(?im)^Disallow:\s*(\S+)", r["body"])
        info["robots_disallow"] = paths[:30]
        sensitive = [p for p in paths if re.search(r"admin|backup|config|\.sql|private|secret|staging|\.git|\.env", p, re.I)]
        if sensitive:
            f.append(F("robots_discloses_paths", "low", "robots.txt hints at sensitive paths",
                       f"Trying to hide pages from search engines this way instead advertises them: {', '.join(sensitive[:6])}.",
                       "Don't rely on robots.txt for secrecy; require authentication for anything sensitive, since the file itself is always public."))
    return f, info


def check_extra_paths(domain):
    f = []
    for path, test, sev, title, plain, fix in EXTRA_PATH_PROBES:
        try:
            r = safe_get(f"https://{domain}{path}", maxbytes=4000)
            if r and r["status"] == 200 and test(r["body"]):
                f.append(F("path_" + re.sub(r"\W+", "_", path.strip("/")), sev, title, plain, fix))
        except Exception:
            pass
    return f, {}


def check_zone_transfer(domain, ns_list):
    f = []
    for ns in (ns_list or [])[:5]:
        try:
            ip = socket.gethostbyname(ns)
            ipaddress.ip_address(ip)
            if not ipaddress.ip_address(ip).is_global:
                continue
            xfr = dns.query.xfr(ip, domain, timeout=6, lifetime=10)
            zone = dns.zone.from_xfr(xfr)
            if len(zone.nodes) > 0:
                f.append(F("zone_transfer", "critical", f"DNS zone transfer (AXFR) allowed by {ns}",
                           f"Anyone can download your entire DNS zone, revealing every subdomain and internal hostname ({len(zone.nodes)} records).",
                           "Disable zone transfers to arbitrary hosts in your DNS server/provider settings; only allow it to your own secondary nameservers."))
                break
        except Exception:
            continue
    return f, {}


def check_dnssec(domain):
    try:
        ans = dns.resolver.resolve(domain, "DNSKEY", lifetime=6)
        if ans:
            return [], {"dnssec": True}
    except Exception:
        pass
    return [F("no_dnssec", "info", "DNSSEC is not enabled",
              "Without DNSSEC, DNS responses for your domain cannot be cryptographically verified, making DNS spoofing attacks slightly easier.",
              "Enable DNSSEC signing at your DNS provider (most major providers support it in one click) and add a DS record at your registrar.")], {"dnssec": False}


def check_weak_tls(domain, ip):
    f = []
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
        ctx.set_ciphers(WEAK_CIPHERS)
        with socket.create_connection((ip, 443), timeout=TIMEOUT) as sock, ctx.wrap_socket(sock, server_hostname=domain) as t:
            cipher = t.cipher()
        if cipher and re.search(r"RC4|DES|EXPORT|NULL", cipher[0]):
            f.append(F("weak_cipher", "high", f"Weak encryption cipher accepted ({cipher[0]})",
                       "The server will negotiate an outdated cipher that modern cryptography considers broken or weak.",
                       "Disable weak ciphers in your server/CDN TLS settings and allow only modern cipher suites (Mozilla's 'Intermediate' config is a good default)."))
    except Exception:
        pass
    return f, {}


def check_subdomain_takeover(domain, subdomains):
    f = []
    for sub in (subdomains or [])[:25]:
        try:
            cname = str(dns.resolver.resolve(sub, "CNAME", lifetime=5)[0].target).rstrip(".")
        except Exception:
            continue
        if not any(cname.endswith(suf.lstrip(".")) or suf in cname for suf in TAKEOVER_CNAME_SUFFIXES):
            continue
        try:
            socket.gethostbyname(cname)
        except socket.gaierror:
            f.append(F("subdomain_takeover_" + sub.split(".")[0], "high", f"Possible subdomain takeover: {sub}",
                       f"{sub} points (via CNAME) to {cname}, which doesn't resolve to anything. If that service name is unclaimed, anyone can register it and serve content on your subdomain.",
                       f"Remove the DNS record for {sub} if it's unused, or re-claim the resource at {cname} with your account."))
    return f, {}


def check_mta_sts(domain):
    found = bool(txt("_mta-sts." + domain))
    try:
        r = safe_get(f"https://mta-sts.{domain}/.well-known/mta-sts.txt", maxbytes=2000)
        found = found or bool(r and r["status"] == 200 and "mode:" in r["body"])
    except Exception:
        pass
    if found:
        return [], {"mta_sts": True}
    return [F("no_mta_sts", "info", "No MTA-STS policy for inbound email",
              "SPF/DMARC protect mail claiming to be from you; MTA-STS instead protects mail sent to you from being downgraded to an unencrypted or spoofed connection.",
              "Publish an MTA-STS policy if you receive mail at this domain (see the mta-sts.{domain} well-known file and _mta-sts TXT record setup for your mail provider).")], {"mta_sts": False}


def check_ports(ip):
    def probe(port):
        try:
            socket.create_connection((ip, port), timeout=2).close()
            return port
        except OSError:
            return None
    with ThreadPoolExecutor(9) as ex:
        open_ports = [p for p in ex.map(probe, RISKY_PORTS) if p]
    f = []
    for p in open_ports:
        name, sev = RISKY_PORTS[p]
        f.append(F(f"port_{p}", sev, f"{name} is reachable from the internet (port {p})",
                   "Services meant for administrators are exposed to the whole internet, where they are constantly attacked.",
                   "Close the port in your firewall or cloud security group, or restrict it to your own IP / a VPN."))
    return f, {"open_ports": open_ports}


PATH_PROBES = [
    ("/.git/HEAD", lambda b: b.startswith("ref:"), "critical", "Your source code repository is public",
     "Anyone can download your site's code and history, which often contains passwords.", "Block /.git at the web server and remove it from the web root."),
    ("/.env", lambda b: "<html" not in b.lower() and re.search(r"^[A-Z][A-Z0-9_]{2,}=", b, re.M), "critical", "Your .env secrets file is public",
     "This file normally holds database passwords and API keys.", "Remove it from the web root, block dotfiles in your server config, and rotate every secret it contained."),
    ("/wp-config.php.bak", lambda b: "DB_PASSWORD" in b, "critical", "WordPress config backup is public",
     "It contains your database password in readable form.", "Delete the backup file and change the database password."),
    ("/phpinfo.php", lambda b: "phpinfo()" in b or "PHP Version" in b, "high", "phpinfo page is public",
     "It reveals server details that help attackers.", "Delete phpinfo.php."),
    ("/actuator/env", lambda b: "activeProfiles" in b or "propertySources" in b, "high", "Spring Boot actuator exposes configuration",
     "Application settings, sometimes including secrets, are readable by anyone.", "Disable or authenticate actuator endpoints in production."),
    ("/phpmyadmin/", lambda b: "phpmyadmin" in b.lower(), "medium", "phpMyAdmin is publicly reachable",
     "A database admin login page is exposed to the whole internet.", "Restrict it by IP or VPN, or remove it."),
    ("/server-status", lambda b: "Apache Server Status" in b, "medium", "Apache server-status page is public",
     "It reveals visitor addresses and requests.", "Restrict /server-status to localhost."),
]


def check_paths(domain):
    f = []
    for path, test, sev, title, plain, fix in PATH_PROBES:
        try:
            r = safe_get(f"https://{domain}{path}", maxbytes=4000)
            if r and r["status"] == 200 and test(r["body"]):  # body is never stored
                f.append(F("path_" + re.sub(r"\W+", "_", path.strip("/")), sev, title, plain, fix))
        except Exception:
            pass
    return f, {}


# ---------- orchestration ----------
def run_scan(domain, deep=False):
    try:
        ips = resolve_public(domain)
    except ValueError as e:
        return _result(domain, deep, [], {"error": str(e)}, [])
    ip = pick_ip(ips)
    steps = [("HTTPS & TLS", lambda: check_tls(domain, ip)), ("HTTPS & TLS", lambda: check_http_redirect(domain)),
             ("Web security", lambda: check_headers(domain)), ("Web security", lambda: check_security_txt(domain)),
             ("Email security", lambda: check_email(domain)),
             ("DNS & domain", lambda: check_caa(domain)), ("DNS & domain", lambda: check_dns(domain))]
    if deep:
        steps += [("Exposure", lambda: check_ports(ip)), ("Exposure", lambda: check_paths(domain)),
                  ("Exposure", lambda: check_extra_paths(domain)),
                  ("HTTPS & TLS", lambda: check_weak_tls(domain, ip)),
                  ("Vulnerability scan", lambda: check_xss(domain)), ("Vulnerability scan", lambda: check_sqli_indicator(domain)),
                  ("Vulnerability scan", lambda: check_cmdi(domain)), ("Vulnerability scan", lambda: check_traversal(domain)),
                  ("Vulnerability scan", lambda: check_open_redirect(domain)), ("Vulnerability scan", lambda: check_cors(domain)),
                  ("Vulnerability scan", lambda: check_http_methods(domain)), ("Vulnerability scan", lambda: check_mixed_content(domain)),
                  ("Vulnerability scan", lambda: check_directory_listing(domain)), ("Vulnerability scan", lambda: check_admin_panels(domain)),
                  ("Vulnerability scan", lambda: check_waf(domain)),
                  ("CMS & discovery", lambda: check_wordpress(domain)), ("CMS & discovery", lambda: check_cms_version(domain)),
                  ("CMS & discovery", lambda: check_robots_sitemap(domain)), ("Email security", lambda: check_mta_sts(domain)),
                  ("DNS & domain", lambda: check_dnssec(domain))]

    # steps below need another check's output (NS list, subdomains), so run the quick scan first, then these.
    findings, info = [], {"ips": ips, "errors": []}

    def run(step):
        cat, fn = step
        try:
            f, i = fn()
            err = None
        except Exception as e:
            f, i, err = [], {}, str(e)[:150]
        for x in f:
            x["category"] = cat
        return f, i, err

    with ThreadPoolExecutor(6) as ex:
        for f, i, err in ex.map(run, steps):
            findings += f
            info.update(i)
            if err:
                info["errors"].append(err)

    if deep:
        subs_f, subs_i = check_subdomains(domain)
        for x in subs_f:
            x["category"] = "Vulnerability scan"
        findings += subs_f
        info.update(subs_i)
        for cat, fn in [("DNS & domain", lambda: check_zone_transfer(domain, info.get("ns"))),
                        ("Vulnerability scan", lambda: check_subdomain_takeover(domain, info.get("subdomains")))]:
            f2, i2, err = run((cat, fn))
            findings += f2
            info.update(i2)
            if err:
                info["errors"].append(err)
    return _result(domain, deep, findings, info, {c for c, _ in steps} | ({"Vulnerability scan"} if deep else set()))



def _result(domain, deep, findings, info, cats_run):
    findings.sort(key=lambda x: ORDER.index(x["severity"]))
    if info.get("error"):
        score, grade = None, "-"
    else:
        score = max(0, 100 - sum(POINTS[x["severity"]] for x in findings))
        grade = "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 65 else "D" if score >= 50 else "F"
    return {"domain": domain, "scanned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "deep": deep, "active_checks_run": deep, "categories_run": sorted(cats_run), "score": score, "grade": grade,
            "top_fixes": [x["id"] for x in findings if x["severity"] != "info"][:3], "findings": findings, "info": info}
