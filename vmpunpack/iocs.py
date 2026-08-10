"""IOC extraction from a memory dump.

The input is an unpacked image or a heap snapshot - hundreds of MB of mostly binary noise with
strings scattered through it in several encodings. Everything here exists because a naive grep gets
this wrong in ways that quietly lose the one indicator the analyst needed.
"""
import re

TLD = (r"com|net|org|ru|su|io|xyz|top|info|biz|cc|onion|pw|club|online|site|dev|app|shop|"
       r"cyou|sbs|store|cfd|icu|monster|quest")
# re.A everywhere: without it [a-z] under re.I matches U+017F and \d matches any Unicode digit, so
# binary noise decoded as UTF-16 injects non-ASCII into the IOC sets and breaks the console write.
RE_DOM = re.compile(r"\b(?:[a-z0-9-]{2,50}\.){1,3}(?:" + TLD + r")\b", re.I | re.A)
RE_URL = re.compile(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&()*+,;=%-]{6,90}", re.A)
RE_IP = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])", re.A)
# Anchored against the registrable host only. A substring match here would drop exactly the
# Microsoft-impersonating C2 hostnames the tool most needs to surface.
NOISE_HOST = re.compile(r"^(?:[a-z0-9-]+\.)*(?:" + "|".join((
    r"microsoft\.com", r"windows\.com", r"windowsupdate\.com", r"msftconnecttest\.com", r"msftncsi\.com",
    r"live\.com", r"msn\.com", r"bing\.com", r"office\.com", r"azure\.com", r"windows\.net", r"skype\.com",
    r"w3\.org", r"xmlsoap\.org", r"openxmlformats\.org", r"mozilla\.org", r"apache\.org", r"openssl\.org",
    r"python\.org", r"letsencrypt\.org", r"nuget\.org", r"chocolatey\.org", r"oasis-open\.org",
    r"verisign\.com", r"digicert\.com", r"sectigo\.com", r"globalsign\.com", r"godaddy\.com",
    r"comodoca\.com", r"entrust\.net", r"thawte\.com", r"geotrust\.com", r"symcb\.com", r"symcd\.com",
    r"amazontrust\.com", r"usertrust\.com", r"trustwave\.com", r"identrust\.com", r"sectigo\.net",
)) + r")$", re.I)


def host_of(u):
    # take the LAST @-separated part: http://update.microsoft.com@<real-c2>/ must not read as Microsoft
    m = re.match(r"https?://([^/\s]+)", u, re.I)
    a = (m.group(1) if m else "").rsplit("@", 1)[-1]
    return a.split(":")[0].lower().rstrip(".")

def valid_ip(x):
    p = x.split(".")
    if any(not (q.isdigit() and len(q) <= 3 and int(q) <= 255) for q in p): return False
    return x not in ("0.0.0.0", "127.0.0.1", "255.255.255.255")

def _scan(text, dom, url, ip):
    for s in RE_DOM.findall(text):
        s = s.lower()
        if len(s) > 6 and not NOISE_HOST.match(s): dom.add(s)
    for x in RE_URL.findall(text):
        if not NOISE_HOST.match(host_of(x)): url.add(x)
    for x in RE_IP.findall(text):
        if valid_ip(x): ip.add(x)


def grep_iocs(b, chunk=64 << 20, overlap=1 << 12):
    """All three patterns see all three views. Chunked so a several-hundred-MB heap dump cannot
    blow memory up by decoding the whole buffer twice and concatenating it."""
    dom, url, ip = set(), set(), set()
    n = len(b)
    spans = [(0, n)] if n <= chunk else [(s, min(s + chunk + overlap, n)) for s in range(0, n, chunk)]
    for s, e in spans:
        seg = bytes(b[s:e])
        _scan(seg.decode("latin1", "ignore"), dom, url, ip)         # single-byte
        _scan(seg.decode("utf-16le", "ignore"), dom, url, ip)       # wide, even-aligned
        _scan(seg[1:].decode("utf-16le", "ignore"), dom, url, ip)   # wide, odd-aligned
    return sorted(dom), sorted(url), sorted(ip)
