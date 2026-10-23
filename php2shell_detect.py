#!/usr/bin/env python3
"""
php2shell-detect — multi-method remote PHP version detector & PHP2Shell triage.

Detects the PHP version of web hosts using as many signals as possible (not only
HTTP version banners), then flags hosts whose version is below the configured
safe-patch thresholds (default: < 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12). The headline
--php2shell mode focuses this on CVE-2026-109618 / CVE-2026-109619 ("PHP2Shell",
unauthenticated RCE, fixed 2026-10-21) to help operators find and patch exposed hosts.

Targets accepted (any mix, repeatable / one per -f line):
    - single IP            203.0.113.10
    - single domain        example.com            (optionally example.com:8443)
    - CIDR range           203.0.113.0/24
    - start-end IP range   203.0.113.10-203.0.113.40   (or shorthand ...10-40)

Detection methods implemented (see README for the research behind each):
    headers      X-Powered-By / Server  -> PHP/x.y.z           (patch, authoritative)
    phpinfo      /phpinfo.php, /info.php ... -> exact version + build + Zend + configure
    zend         Zend Engine v4.N.x  ->  PHP 8.N.x             (patch, corroboration)
    exposed      composer.json/lock, server-status/info, FPM status/ping
    easteregg    ?=PHPE9568F34-... logo GUID                   (proves PHP <= 5.4)
    errorpage    native fatal/TypeError wording                (major / minor floor)
    presence     PHPSESSID, Expires:1981, X-Pingback, X-Redirect-By, wp-json Link
    distro       Server OS token (Debian/Ubuntu/RHEL) -> backport caveat + branch guess
    cms          generator / framework fingerprints -> PHP minimum floor
    favicon      /favicon.ico mmh3 hash (Shodan-compatible)    (clustering only)
    shodan       optional passive enrichment (needs --shodan-key)

Standard library only (http.client, ssl, socket, ipaddress, concurrent.futures).

LEGAL / RESPONSIBLE USE: Only scan hosts you own or have explicit written
authorization to test. Unauthorized scanning may violate the CFAA (US), the
Computer Misuse Act (UK) and equivalents. This tool performs *detection only*; it
never attempts exploitation. Use low concurrency and respect the targets.
"""
from __future__ import annotations

import argparse
import base64
import concurrent.futures as cf
import ipaddress
import json
import os
import re
import socket
import ssl
import sys
import threading
import time
from datetime import datetime, timezone
from http.client import HTTPConnection, HTTPSConnection
from urllib.parse import urljoin, urlsplit

__version__ = "1.1.0"
USER_AGENT = "php2shell-detect/%s (+authorized-security-testing)" % __version__

# Mutable globals set by main(): current User-Agent and optional global rate limiter.
_UA = USER_AGENT
_RATE = None  # type: ignore

# Special-use / non-routable IPv4 ranges excluded by default in --survey mode
# (RFC 1918/5735/6598/5737/3927/1112 etc). Never probe these in an internet survey.
DEFAULT_EXCLUDES = [
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
    "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
    "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
    "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "255.255.255.255/32",
]

# --------------------------------------------------------------------------- #
# Signatures (consolidated from research)
# --------------------------------------------------------------------------- #

# PHP version token, as it appears in X-Powered-By / Server / phpinfo.
PHP_VER_RE = re.compile(r"PHP/(\d+(?:\.\d+){1,3})", re.I)
# phpinfo() top heading and table rows.
PHPINFO_H1_RE = re.compile(r'PHP Version\s*</?[^>]*>?\s*(\d+\.\d+\.\d+[^\s<"]*)', re.I)
PHPINFO_H1_TAG_RE = re.compile(r'<h1[^>]*>\s*PHP Version\s*(\d+\.\d+\.\d+[^<]*)</h1>', re.I)
ZEND_RE = re.compile(r"Zend Engine\s*v?(\d+)\.(\d+)\.(\d+)", re.I)
BUILD_DATE_RE = re.compile(r"Build Date\s*</td>\s*<td[^>]*>([^<]+)", re.I)
CONFIGURE_RE = re.compile(r"(--with-config-file-path=\S+|--prefix=\S+|/etc/php/\d+\.\d+)", re.I)

# PHP-presence (not version) signals.
EXPIRES_1981_RE = re.compile(r"Thu, 19 Nov 1981 08:52:00 GMT", re.I)
PHPSESSID_RE = re.compile(r"\bPHPSESSID=", re.I)

# OS / distro hint inside Server header parentheses.
DISTRO_RE = re.compile(r"\((debian|ubuntu|red[\s-]?hat|centos|rocky|alma|fedora|freebsd|win(?:32|64|dows)?|unix)\b[^)]*\)", re.I)

# Native PHP error-page wording -> major version floor.
ERR_PHP8_RE = re.compile(r"(ValueError|must be of type|Passing null to parameter)", re.I)
ERR_PHP7_RE = re.compile(r"Uncaught (?:Error|TypeError).*Stack trace:", re.I | re.S)
ERR_ANY_RE = re.compile(r"(Fatal error|Parse error|Warning|Deprecated|Notice):", re.I)
ERR_PATH_RE = re.compile(r"\bin\s+(/[^\s:<]+\.php)(?::|\s+on line\s+)(\d+)", re.I)

# Easter-egg logo GUIDs (work only on PHP <= 5.4 with expose_php=On).
EGG_GUIDS = {
    "php_logo": "PHPE9568F34-D428-11d2-A769-00AA001ACF42",
    "zend_logo": "PHPE9568F35-D428-11d2-A769-00AA001ACF42",
    "egg_logo": "PHPE9568F36-D428-11d2-A769-00AA001ACF42",
    "credits": "PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000",
}

# Probe paths.
PHPINFO_PATHS = [
    "/phpinfo.php", "/info.php", "/i.php", "/test.php", "/php.php",
    "/phpversion.php", "/php_info.php", "/pi.php", "/php-info.php",
]
EXPOSED_PATHS = [
    "/composer.json", "/composer.lock",
    "/server-status", "/server-info",
    "/status?json&full", "/ping",
]
# Fast/default set keeps noise low; --deep adds the rest.
DEFAULT_PROBE_PATHS = ["/phpinfo.php", "/info.php", "/composer.json"]

CDN_HEADER_HINTS = ("cf-ray", "x-served-by", "x-fastly", "x-akamai", "x-amz-cf-id", "fly-request-id")

# CMS/framework -> PHP minimum floor (weak lower-bound only).
CMS_FLOORS = [
    (re.compile(r'name="generator" content="WordPress\s*([\d.]+)', re.I), "WordPress", (7, 2)),
    (re.compile(r"laravel_session=|XSRF-TOKEN=", re.I), "Laravel", (8, 1)),
    (re.compile(r'name="generator" content="Drupal\s*(\d+)', re.I), "Drupal", (8, 1)),
    (re.compile(r'name="generator" content="Joomla', re.I), "Joomla", (7, 2)),
    (re.compile(r"/wp-content/|/wp-includes/|xmlrpc\.php", re.I), "WordPress", (7, 2)),
]

# --------------------------------------------------------------------------- #
# Version handling & verdict
# --------------------------------------------------------------------------- #

try:
    from packaging.version import Version as _PkgVersion, InvalidVersion as _InvalidVersion  # type: ignore
    _HAVE_PACKAGING = True
except Exception:  # pragma: no cover - packaging is optional
    _HAVE_PACKAGING = False


def ver_tuple(s: str) -> tuple[int, ...] | None:
    """Parse a version string into a tuple of ints; None if unparseable."""
    m = re.match(r"\s*(\d+(?:\.\d+)*)", s or "")
    if not m:
        return None
    return tuple(int(p) for p in m.group(1).split("."))


def ver_lt(a: str, b: str) -> bool:
    """Return True if version a < version b, padding missing components with 0."""
    if _HAVE_PACKAGING:
        try:
            return _PkgVersion(a) < _PkgVersion(b)
        except _InvalidVersion:
            pass
    ta, tb = ver_tuple(a), ver_tuple(b)
    if ta is None or tb is None:
        return False
    n = max(len(ta), len(tb))
    ta += (0,) * (n - len(ta))
    tb += (0,) * (n - len(tb))
    return ta < tb


def load_thresholds(path: str | None) -> dict:
    default = {
        "safe_min": {"8.2": "8.2.35", "8.3": "8.3.36", "8.4": "8.4.27", "8.5": "8.5.12"},
        "eol_below": "8.2",
    }
    if path:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        default["safe_min"] = data.get("safe_min", default["safe_min"])
        default["eol_below"] = data.get("eol_below", default["eol_below"])
    else:
        here = os.path.join(os.path.dirname(os.path.abspath(__file__)), "thresholds.json")
        if os.path.exists(here):
            try:
                with open(here, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                default["safe_min"] = data.get("safe_min", default["safe_min"])
                default["eol_below"] = data.get("eol_below", default["eol_below"])
            except Exception:
                pass
    return default


def verdict(ver_str: str | None, thresholds: dict) -> tuple[str, str]:
    """Return (status, detail). status in {vulnerable, ok, eol, unknown}."""
    if not ver_str:
        return ("unknown", "no version detected")
    t = ver_tuple(ver_str)
    if not t or len(t) < 2:
        return ("unknown", "unparseable version %r" % ver_str)
    branch = "%d.%d" % (t[0], t[1])
    eol_below = thresholds.get("eol_below", "8.2")
    if ver_lt(branch + ".0", eol_below + ".0"):
        return ("eol", "%s branch is end-of-life (< %s), unsupported" % (branch, eol_below))
    safe = thresholds["safe_min"].get(branch)
    if not safe:
        return ("unknown", "%s: no threshold for branch %s (newer than tracked?)" % (ver_str, branch))
    partial = len(t) < 3
    if ver_lt(ver_str, safe):
        note = " (patch level unknown -> assumed vulnerable)" if partial else ""
        return ("vulnerable", "%s < %s%s" % (ver_str, safe, note))
    return ("ok", "%s >= %s" % (ver_str, safe))


# --------------------------------------------------------------------------- #
# Target expansion
# --------------------------------------------------------------------------- #

RANGE_RE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3})\s*-\s*(\d{1,3}(?:\.\d{1,3}){3}|\d{1,3})$")


def expand_target(token: str) -> list[str]:
    """Expand one input token into a list of host strings (IPs or a domain)."""
    token = token.strip()
    if not token or token.startswith("#"):
        return []

    # start-end IPv4 range (full or last-octet shorthand)
    m = RANGE_RE.match(token)
    if m:
        start = ipaddress.IPv4Address(m.group(1))
        end_tok = m.group(2)
        if "." not in end_tok:
            end_tok = str(start).rsplit(".", 1)[0] + "." + end_tok
        end = ipaddress.IPv4Address(end_tok)
        if end < start:
            raise ValueError("range end before start: %s" % token)
        return [str(ipaddress.IPv4Address(i)) for i in range(int(start), int(end) + 1)]

    # CIDR
    if "/" in token and ":" not in token.split("/")[0] or ("/" in token and ":" in token):
        try:
            net = ipaddress.ip_network(token, strict=False)
            hosts = [str(h) for h in net.hosts()]
            return hosts or [str(net.network_address)]
        except ValueError:
            pass  # fall through: might be a URL-ish token, treat as domain below

    # strip optional scheme/port for classification, but keep host:port for probing
    bare = token
    if "://" in bare:
        bare = urlsplit(token).netloc or token
    hostpart = bare.split(":")[0]

    try:
        ipaddress.ip_address(hostpart)
        return [bare]  # valid single IP (optionally with :port)
    except ValueError:
        return [bare]  # treat as domain/hostname (optionally with :port)


def build_hostlist(tokens: list[str], max_hosts: int = 0) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for tok in tokens:
        for h in expand_target(tok):
            if h not in seen:
                seen.add(h)
                out.append(h)
    if max_hosts and len(out) > max_hosts:
        raise SystemExit(
            "Refusing to scan %d hosts (safety cap --max-hosts=%d). "
            "Narrow the range or raise the cap (0 = unlimited)." % (len(out), max_hosts)
        )
    return out


# --------------------------------------------------------------------------- #
# Internet-wide survey engine: streaming, exclusions, sharding, randomization
# --------------------------------------------------------------------------- #

class RateLimiter:
    """Thread-safe token bucket limiting outbound connections to `rate` per second."""

    def __init__(self, rate: float):
        self.rate = float(rate)
        self.capacity = max(1.0, float(rate))
        self.tokens = self.capacity
        self.updated = time.monotonic()
        self.lock = threading.Lock()

    def acquire(self) -> None:
        if self.rate <= 0:
            return
        while True:
            with self.lock:
                now = time.monotonic()
                self.tokens = min(self.capacity, self.tokens + (now - self.updated) * self.rate)
                self.updated = now
                if self.tokens >= 1.0:
                    self.tokens -= 1.0
                    return
                wait = (1.0 - self.tokens) / self.rate
            time.sleep(min(wait, 1.0))


class ExcludeSet:
    """Fast IPv4 membership test against a set of CIDR networks."""

    def __init__(self, cidrs):
        self.nets = []
        for c in cidrs:
            try:
                self.nets.append(ipaddress.ip_network(c.strip(), strict=False))
            except ValueError:
                continue

    def contains(self, ip_int: int) -> bool:
        addr = ipaddress.IPv4Address(ip_int)
        for net in self.nets:
            if net.version == 4 and addr in net:
                return True
        return False


class IPv4Space:
    """A set of IPv4 networks addressed as one contiguous index space [0, N),
    with a reversible affine permutation so hosts are emitted in pseudo-random
    order (spreading load across networks) without materializing the list."""

    def __init__(self, networks):
        self.blocks = []  # (cum_offset, start_int, size)
        cum = 0
        for net in networks:
            size = net.num_addresses
            if size <= 0:
                continue
            self.blocks.append((cum, int(net.network_address), size))
            cum += size
        self.total = cum

    def index_to_ip_int(self, idx: int) -> int:
        lo, hi = 0, len(self.blocks)
        while lo < hi - 1:
            mid = (lo + hi) // 2
            if self.blocks[mid][0] <= idx:
                lo = mid
            else:
                hi = mid
        cum, start, _size = self.blocks[lo]
        return start + (idx - cum)

    @staticmethod
    def _coprime_multiplier(n: int, seed: int) -> int:
        if n <= 1:
            return 1
        import math
        a = int(n * 0.6180339887498949) | 1  # near golden ratio, odd
        a = (a + seed * 2) % n or 1
        while math.gcd(a, n) != 1:
            a = (a + 2) % n or 1
        return a

    def iter_ips(self, seed: int = 0, randomize: bool = True):
        n = self.total
        if n == 0:
            return
        if not randomize:
            for k in range(n):
                yield k, self.index_to_ip_int(k)
            return
        a = self._coprime_multiplier(n, seed)
        b = seed % n
        for k in range(n):
            idx = (a * k + b) % n
            yield k, self.index_to_ip_int(idx)


def _parse_networks(tokens):
    """Turn input tokens (CIDR / range / single IP) into IPv4 network objects."""
    nets = []
    for tok in tokens:
        tok = tok.strip()
        if not tok or tok.startswith("#"):
            continue
        m = RANGE_RE.match(tok)
        if m:
            start = ipaddress.IPv4Address(m.group(1))
            end_tok = m.group(2)
            if "." not in end_tok:
                end_tok = str(start).rsplit(".", 1)[0] + "." + end_tok
            end = ipaddress.IPv4Address(end_tok)
            nets.extend(ipaddress.summarize_address_range(start, end))
            continue
        try:
            nets.append(ipaddress.ip_network(tok, strict=False))
        except ValueError:
            try:
                nets.append(ipaddress.ip_network(tok + "/32", strict=False))
            except ValueError:
                continue
    return nets


def survey_targets(tokens, excludes: ExcludeSet, shard_id: int, shard_n: int,
                   seed: int, randomize: bool, limit: int):
    """Yield IPv4 address strings for an internet survey: randomized order,
    default+user exclusions applied, sharded, optionally capped. Streaming."""
    space = IPv4Space(_parse_networks(tokens))
    emitted = 0
    for k, ip_int in space.iter_ips(seed=seed, randomize=randomize):
        if shard_n > 1 and (k % shard_n) != shard_id:
            continue
        if excludes.contains(ip_int):
            continue
        yield str(ipaddress.IPv4Address(ip_int))
        emitted += 1
        if limit and emitted >= limit:
            return


def file_targets(path, shard_id: int, shard_n: int, limit: int):
    """Stream and expand targets from a file (one token per line)."""
    emitted = 0
    k = 0
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            for h in expand_target(line):
                if shard_n > 1 and (k % shard_n) != shard_id:
                    k += 1
                    continue
                k += 1
                yield h
                emitted += 1
                if limit and emitted >= limit:
                    return


_IPV4_RE = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")


def mask_ip(val):
    """Mask the last two octets of an IPv4 address for census sharing: 203.0.113.5 ->
    203.0.x.x. Preserves an optional :port. Non-IPv4 values are returned unchanged."""
    if not val:
        return val
    host, port = val, ""
    if val.count(":") == 1 and "." in val:
        host, p = val.rsplit(":", 1)
        port = ":" + p
    parts = host.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return "%s.%s.x.x%s" % (parts[0], parts[1], port)
    return val


def _mask_ipv4_text(s):
    """Mask the last two octets of every IPv4 literal embedded in a string."""
    if not s:
        return s
    return _IPV4_RE.sub(lambda m: "%s.%s.x.x" % (m.group(1), m.group(2)), str(s))


def mask_record(rec):
    """Partially anonymize a record in place for census mode: mask the IP everywhere it
    can appear (target, resolved_ip, final_url, error strings, evidence detail) and drop
    the reverse-DNS name, so shared --jsonl/--json census output never carries a full IP."""
    rec["target"] = mask_ip(rec.get("target"))
    rec["resolved_ip"] = mask_ip(rec.get("resolved_ip"))
    rec["host_header"] = None  # reverse-DNS name would defeat the masking
    rec["final_url"] = _mask_ipv4_text(rec.get("final_url"))
    if rec.get("errors"):
        rec["errors"] = [_mask_ipv4_text(e) for e in rec["errors"]]
    for e in rec.get("evidence", []):
        if e.get("detail"):
            e["detail"] = _mask_ipv4_text(e["detail"])
    return rec


class Aggregate:
    """Anonymized, shareable counters for survey mode (no IPs retained)."""

    def __init__(self):
        self.total = 0
        self.reachable = 0
        self.is_php = 0
        self.proxied = 0
        self.by_status = {}
        self.by_php2shell = {}
        self.by_branch = {}
        self.by_version = {}
        self.by_source = {}
        self.php_hosts = []          # masked IPs where PHP was found (safe to share)
        self.php_hosts_cap = 200000
        self.php_hosts_truncated = False
        self.lock = threading.Lock()

    def add(self, rec: dict) -> None:
        with self.lock:
            self.total += 1
            if rec.get("reachable"):
                self.reachable += 1
            if rec.get("is_php"):
                self.is_php += 1
                if len(self.php_hosts) < self.php_hosts_cap:
                    self.php_hosts.append({
                        "ip": rec.get("resolved_ip") or rec.get("target"),  # masked upstream in census mode
                        "php_version": rec.get("php_version"),
                        "php2shell": rec.get("php2shell"),
                        "status": rec.get("status"),
                    })
                else:
                    self.php_hosts_truncated = True
            if rec.get("proxy"):
                self.proxied += 1
            self.by_status[rec["status"]] = self.by_status.get(rec["status"], 0) + 1
            p2 = rec.get("php2shell", "n/a")
            self.by_php2shell[p2] = self.by_php2shell.get(p2, 0) + 1
            v = rec.get("php_version")
            if v:
                self.by_version[v] = self.by_version.get(v, 0) + 1
                t = ver_tuple(v)
                if t and len(t) >= 2:
                    br = "%d.%d" % (t[0], t[1])
                    self.by_branch[br] = self.by_branch.get(br, 0) + 1
            src = rec.get("php_version_source")
            if src:
                self.by_source[src] = self.by_source.get(src, 0) + 1

    def report(self, thresholds: dict, meta: dict) -> dict:
        with self.lock:
            return {
                "tool": "php2shell-detect",
                "tool_version": __version__,
                "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "note": "Anonymized aggregate survey data (no IP addresses retained). "
                        "Safe to share with the community.",
                "meta": meta,
                "thresholds": thresholds,
                "totals": {
                    "scanned": self.total,
                    "reachable": self.reachable,
                    "confirmed_php": self.is_php,
                    "behind_proxy_cdn": self.proxied,
                },
                "hosts_with_php_masked": list(self.php_hosts),
                "hosts_with_php_truncated": self.php_hosts_truncated,
                "by_status": dict(sorted(self.by_status.items(), key=lambda x: -x[1])),
                "by_php2shell": dict(sorted(self.by_php2shell.items(), key=lambda x: -x[1])),
                "by_branch": dict(sorted(self.by_branch.items(), key=lambda x: -x[1])),
                "by_source": dict(sorted(self.by_source.items(), key=lambda x: -x[1])),
                "top_versions": dict(sorted(self.by_version.items(), key=lambda x: -x[1])[:50]),
            }


# --------------------------------------------------------------------------- #
# HTTP client (stdlib, with manual redirects)
# --------------------------------------------------------------------------- #

def _split_host_port(target: str, default_port: int) -> tuple[str, int]:
    if target.startswith("[") and "]" in target:  # bracketed IPv6
        host = target[1:target.index("]")]
        rest = target[target.index("]") + 1:]
        port = int(rest[1:]) if rest.startswith(":") else default_port
        return host, port
    if target.count(":") == 1:
        host, p = target.rsplit(":", 1)
        if p.isdigit():
            return host, int(p)
    return target, default_port


def _unverified_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_alpn_protocols(["http/1.1"])
    except Exception:
        pass
    return ctx


def _verified_ctx() -> ssl.SSLContext:
    """Normal cert-verifying context — for trusted first-party APIs (e.g. Shodan),
    NOT for scanning arbitrary target hosts."""
    return ssl.create_default_context()


def _reg_domain(h):
    if not h:
        return h
    parts = h.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else h


def _blocked_redirect(origin, nh):
    """True if a redirect from `origin` host to `nh` host should NOT be followed.
    Blocks off-target steering (SSRF): different registrable domain, or any off-origin
    private/reserved/link-local/loopback/metadata IP literal. Same-host (incl. a private
    IP you are deliberately scanning) and same registrable domain are allowed."""
    if not nh:
        return True
    if nh.lower() == (origin or "").lower():
        return False
    try:
        ip = ipaddress.ip_address(nh)
        return (ip.is_private or ip.is_reserved or ip.is_loopback or ip.is_link_local
                or ip.is_multicast or ip.is_unspecified)
    except ValueError:
        return _reg_domain(nh).lower() != _reg_domain(origin or "").lower()


def http_get(url: str, host_header: str | None, timeout: float,
             max_redirects: int = 4, max_body: int = 262144, verify: bool = False) -> dict:
    """GET a URL; follow redirects manually. Returns a result dict (never raises).
    `verify=True` enables TLS certificate verification (use only for trusted APIs).
    Redirects are restricted to the same host / registrable domain (see _blocked_redirect)."""
    result = {"url": url, "final_url": url, "status": None, "headers": [],
              "body": b"", "error": None, "scheme": None}
    seen_urls = set()
    cur = url
    origin_host = urlsplit(url).hostname
    for _ in range(max_redirects + 1):
        if cur in seen_urls:
            result["error"] = "redirect loop"
            return result
        seen_urls.add(cur)
        parts = urlsplit(cur)
        scheme = parts.scheme or "http"
        result["scheme"] = scheme
        default_port = 443 if scheme == "https" else 80
        host, port = parts.hostname, parts.port or default_port
        if host is None:
            result["error"] = "bad url"
            return result
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        hdr_host = host_header or (host if port in (80, 443) else "%s:%d" % (host, port))
        headers = {
            "Host": hdr_host,
            "User-Agent": _UA,
            "Accept": "*/*",
            "Connection": "close",
        }
        if _RATE is not None:
            _RATE.acquire()
        try:
            if scheme == "https":
                # For scanning arbitrary targets, verification is deliberately disabled so
                # self-signed/expired certs never block version detection (verify=False). A
                # verified context is used for trusted first-party APIs (verify=True).
                ctx = _verified_ctx() if verify else _unverified_ctx()
                conn = HTTPSConnection(host, port, timeout=timeout, context=ctx)  # nosemgrep: python.lang.security.audit.httpsconnection-detected.httpsconnection-detected
            else:
                conn = HTTPConnection(host, port, timeout=timeout)
            conn.request("GET", path, headers=headers)
            resp = conn.getresponse()
            status = resp.status
            hdrs = resp.getheaders()
            body = resp.read(max_body)
            conn.close()
        except Exception as e:  # DNS, refused, timeout, TLS, reset ...
            result["error"] = "%s: %s" % (type(e).__name__, e)
            return result

        result["status"] = status
        result["headers"] = hdrs
        result["body"] = body
        result["final_url"] = cur

        if status in (301, 302, 303, 307, 308):
            loc = next((v for k, v in hdrs if k.lower() == "location"), None)
            if loc:
                nxt = urljoin(cur, loc)
                nh = urlsplit(nxt).hostname
                if _blocked_redirect(origin_host, nh):
                    result["error"] = "off-target redirect blocked: %s" % nh
                    return result
                cur = nxt
                continue
        return result
    result["error"] = "too many redirects"
    return result


def header_get(headers: list[tuple[str, str]], name: str) -> list[str]:
    name = name.lower()
    return [v for k, v in headers if k.lower() == name]


# --------------------------------------------------------------------------- #
# mmh3 (MurmurHash3 x86 32-bit) — pure Python, Shodan-compatible favicon hash
# --------------------------------------------------------------------------- #

def mmh3_32(data: bytes, seed: int = 0) -> int:
    c1, c2 = 0xCC9E2D51, 0x1B873593
    length = len(data)
    h1 = seed & 0xFFFFFFFF
    rounded = (length // 4) * 4
    for i in range(0, rounded, 4):
        k1 = int.from_bytes(data[i:i + 4], "little")
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xE6546B64) & 0xFFFFFFFF
    k1 = 0
    tail = data[rounded:]
    if len(tail) >= 3:
        k1 ^= tail[2] << 16
    if len(tail) >= 2:
        k1 ^= tail[1] << 8
    if len(tail) >= 1:
        k1 ^= tail[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85EBCA6B) & 0xFFFFFFFF
    h1 ^= h1 >> 13
    h1 = (h1 * 0xC2B2AE35) & 0xFFFFFFFF
    h1 ^= h1 >> 16
    # Shodan reports the signed 32-bit value.
    return h1 - 0x100000000 if h1 & 0x80000000 else h1


def shodan_favicon_hash(body: bytes) -> int:
    b64 = base64.encodebytes(body)  # MIME base64 w/ newlines, as Shodan does
    return mmh3_32(b64)


# --------------------------------------------------------------------------- #
# Evidence model
# --------------------------------------------------------------------------- #

CONF = {"authoritative": 100, "high": 80, "medium": 55, "low": 30, "floor": 20, "none": 0}


def ev(method, confidence, detail, version=None, granularity=None, base_only=False):
    return {
        "method": method, "confidence": CONF.get(confidence, 0), "conf_label": confidence,
        "detail": detail, "version": version, "granularity": granularity,
        "base_only": base_only,
    }


def parse_distro(server: str) -> str | None:
    m = DISTRO_RE.search(server or "")
    return m.group(1).lower().replace(" ", "").replace("-", "") if m else None


# --------------------------------------------------------------------------- #
# Per-host scan
# --------------------------------------------------------------------------- #

def scan_host(target: str, args, thresholds: dict) -> dict:
    started = time.time()
    rec = {
        "target": target,
        "resolved_ip": None,
        "host_header": None,
        "reachable": False,
        "scheme": None,
        "final_url": None,
        "is_php": False,
        "php_version": None,
        "php_version_source": None,
        "php_version_granularity": None,
        "version_base_only": False,
        "status": "unknown",
        "detail": "",
        "distro": None,
        "sapi_hint": None,
        "proxy": None,
        "favicon_hash": None,
        "evidence": [],
        "paths_hit": [],
        "errors": [],
        "scanned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    evidence: list[dict] = rec["evidence"]

    host_only, _ = _split_host_port(target, 0)
    # Resolve + reverse-DNS for a Host header when scanning a raw IP (name-based vhosts).
    host_header = None
    is_ip = False
    try:
        ipaddress.ip_address(host_only)
        is_ip = True
        rec["resolved_ip"] = host_only
        # Reverse DNS sets the Host header for name-based vhosts, but it is a blocking,
        # un-timed lookup and leaks scan activity to PTR operators — skip it in surveys.
        if not getattr(args, "survey", False):
            try:
                host_header = socket.gethostbyaddr(host_only)[0]
            except Exception:
                host_header = None
    except ValueError:
        try:
            rec["resolved_ip"] = socket.gethostbyname(host_only)
        except Exception:
            rec["resolved_ip"] = None
    rec["host_header"] = host_header if is_ip else None

    schemes = ["https", "http"] if args.scheme == "auto" else [args.scheme]

    base = None
    for scheme in schemes:
        url = "%s://%s/" % (scheme, target)
        r = http_get(url, host_header if is_ip else None, args.timeout,
                     max_redirects=args.max_redirects)
        if r["status"] is not None:
            base = r
            rec["reachable"] = True
            rec["scheme"] = r["scheme"]
            rec["final_url"] = r["final_url"]
            break
        else:
            rec["errors"].append("%s: %s" % (scheme, r["error"]))

    if base is None:
        rec["status"] = "unreachable"
        rec["detail"] = "; ".join(rec["errors"][-2:]) or "no response"
        rec["elapsed"] = round(time.time() - started, 2)
        return rec

    headers = base["headers"]
    body = base["body"]
    body_txt = body.decode("latin-1", "replace")
    server = " ".join(header_get(headers, "server"))
    xpb = " ".join(header_get(headers, "x-powered-by"))
    set_cookies = " ".join(header_get(headers, "set-cookie"))

    # --- proxy / CDN detection ---
    proxy_bits = []
    if "cloudflare" in server.lower():
        proxy_bits.append("cloudflare")
    for h in CDN_HEADER_HINTS:
        if header_get(headers, h):
            proxy_bits.append(h)
    via = header_get(headers, "via")
    if via:
        proxy_bits.append("via:" + via[0][:40])
    if proxy_bits:
        rec["proxy"] = ",".join(proxy_bits)

    # --- distro / SAPI hints ---
    rec["distro"] = parse_distro(server)
    if re.search(r"\bphp-fpm\b|fpm", server, re.I):
        rec["sapi_hint"] = "fpm"
    elif re.search(r"mod_php|PHP/", server):
        rec["sapi_hint"] = "mod_php"

    # --- method: headers (authoritative version) ---
    for src, val in (("X-Powered-By", xpb), ("Server", server)):
        m = PHP_VER_RE.search(val)
        if m:
            base_only = rec["distro"] in ("debian", "ubuntu", "redhat", "centos", "rocky", "alma")
            evidence.append(ev(
                "headers", "authoritative",
                "%s: %s" % (src, val.strip()[:120]),
                version=m.group(1),
                granularity="patch",
                base_only=base_only,
            ))

    # --- method: presence signals (is PHP, no version) ---
    presence = []
    if PHPSESSID_RE.search(set_cookies):
        presence.append("PHPSESSID cookie")
    if EXPIRES_1981_RE.search(" ".join(header_get(headers, "expires"))):
        presence.append("Expires:1981 (session_cache_limiter)")
    xpingback = header_get(headers, "x-pingback")
    if xpingback and ".php" in xpingback[0].lower():
        presence.append("X-Pingback:%s" % xpingback[0].split("/")[-1])
    xredir = header_get(headers, "x-redirect-by")
    if xredir:
        presence.append("X-Redirect-By:%s" % xredir[0])
    if any(".php" in (v.lower()) for v in header_get(headers, "link")) or "/wp-json/" in body_txt:
        presence.append("wp-json/Link")
    if "PHP" in xpb.upper():
        presence.append("X-Powered-By:PHP")
    if presence:
        rec["is_php"] = True
        evidence.append(ev("presence", "medium", "; ".join(presence)))

    # --- method: CMS/framework floor ---
    for rx, name, floor in CMS_FLOORS:
        mm = rx.search(body_txt) or rx.search(set_cookies)
        if mm:
            rec["is_php"] = True
            evidence.append(ev(
                "cms", "floor",
                "%s detected -> PHP >= %d.%d" % (name, floor[0], floor[1]),
                version="%d.%d" % floor, granularity="minor-floor",
            ))
            break

    # --- method: error-page wording from the baseline body ---
    _classify_error_page(body_txt, evidence, rec)

    # --- active probes (phpinfo / exposed files / easter egg / error trigger) ---
    if not args.no_active:
        scheme = rec["scheme"]
        netloc = target

        # dummy non-existent *.php probe: catches PHP when GET / is static (one request).
        # Skip only if the baseline already gave us a concrete version.
        if not any(e.get("version") for e in evidence):
            _probe_dummy_php(scheme, netloc, host_header if is_ip else None, args, evidence, rec)

        probe_paths = list(DEFAULT_PROBE_PATHS)
        if args.deep:
            probe_paths = list(dict.fromkeys(PHPINFO_PATHS + EXPOSED_PATHS))

        for path in probe_paths:
            url = "%s://%s%s" % (scheme, netloc, path)
            r = http_get(url, host_header if is_ip else None, args.timeout,
                         max_redirects=1)
            if r["status"] != 200 or not r["body"]:
                continue
            txt = r["body"].decode("latin-1", "replace")
            if _parse_phpinfo(txt, path, evidence, rec):
                rec["paths_hit"].append(path)
            elif path in ("/composer.json", "/composer.lock"):
                if _parse_composer(txt, path, evidence, rec):
                    rec["paths_hit"].append(path)
            elif path in ("/server-status", "/server-info"):
                m = PHP_VER_RE.search(txt)
                if m or "Apache Server Status" in txt or "mod_" in txt:
                    rec["paths_hit"].append(path)
                    rec["is_php"] = rec["is_php"] or bool(m)
                    if m:
                        evidence.append(ev("exposed", "high", "%s leaks PHP/%s" % (path, m.group(1)),
                                           version=m.group(1), granularity="patch"))
            elif path.startswith("/status") or path == "/ping":
                if "pool:" in txt or txt.strip() == "pong" or "accepted conn" in txt:
                    rec["is_php"] = True
                    rec["paths_hit"].append(path)
                    evidence.append(ev("exposed", "medium", "PHP-FPM status/ping exposed at %s" % path))

        # legacy easter-egg GUID probe (proves PHP <= 5.4)
        if args.deep and rec["php_version"] is None:
            _probe_easter_egg(scheme, netloc, host_header if is_ip else None, args, evidence, rec)

    # --- favicon hash (clustering) ---
    if not args.no_favicon:
        try:
            r = http_get("%s://%s/favicon.ico" % (rec["scheme"], target),
                         host_header if is_ip else None, args.timeout, max_redirects=2)
            if r["status"] == 200 and r["body"]:
                rec["favicon_hash"] = shodan_favicon_hash(r["body"])
                evidence.append(ev("favicon", "low", "favicon mmh3=%d (Shodan http.favicon.hash)" % rec["favicon_hash"]))
        except Exception:
            pass

    # --- shodan passive enrichment ---
    if args.shodan_key and rec["resolved_ip"]:
        _shodan_enrich(rec["resolved_ip"], args.shodan_key, args.timeout, evidence, rec)

    _finalize(rec, thresholds)
    rec["elapsed"] = round(time.time() - started, 2)
    return rec


def _classify_error_page(txt: str, evidence: list, rec: dict) -> None:
    if not ERR_ANY_RE.search(txt):
        return
    rec["is_php"] = True
    pm = ERR_PATH_RE.search(txt)
    path_note = (" path=%s" % pm.group(1)) if pm else ""
    if ERR_PHP8_RE.search(txt):
        evidence.append(ev("errorpage", "low", "PHP 8.x error wording" + path_note,
                           version="8.0", granularity="major-floor"))
    elif ERR_PHP7_RE.search(txt):
        evidence.append(ev("errorpage", "low", "PHP 7.x Throwable error wording" + path_note,
                           version="7.0", granularity="major-floor"))
    else:
        evidence.append(ev("errorpage", "low", "native PHP error page" + path_note))


def _parse_phpinfo(txt: str, path: str, evidence: list, rec: dict) -> bool:
    if "phpinfo()" not in txt and "<title>phpinfo()" not in txt and 'class="e">PHP Version' not in txt:
        # still try the h1 form
        if "PHP Version" not in txt:
            return False
    ver = None
    m = PHPINFO_H1_TAG_RE.search(txt) or PHPINFO_H1_RE.search(txt)
    if m:
        ver = m.group(1).strip()
    extra = []
    zm = ZEND_RE.search(txt)
    if zm:
        zmaj, zmin, zpat = (int(zm.group(1)), int(zm.group(2)), int(zm.group(3)))
        if zmaj == 4:
            zver = "8.%d.%d" % (zmin, zpat)
            extra.append("Zend v%d.%d.%d->PHP %s" % (zmaj, zmin, zpat, zver))
            if not ver:
                ver = zver
    bm = BUILD_DATE_RE.search(txt)
    if bm:
        extra.append("build=%s" % bm.group(1).strip())
    cm = CONFIGURE_RE.search(txt)
    if cm:
        extra.append("cfg=%s" % cm.group(1))
        if "/etc/php/" in cm.group(1):
            rec["distro"] = rec["distro"] or "debian/ubuntu"
        elif "/etc/php.d" in txt or "/opt/remi" in txt:
            rec["distro"] = rec["distro"] or "rhel/remi"
    if ver:
        rec["is_php"] = True
        evidence.append(ev("phpinfo", "authoritative",
                           "phpinfo at %s -> PHP %s%s" % (path, ver, (" | " + "; ".join(extra)) if extra else ""),
                           version=ver, granularity="patch"))
        return True
    return False


def _parse_composer(txt: str, path: str, evidence: list, rec: dict) -> bool:
    try:
        data = json.loads(txt)
    except Exception:
        return False
    rec["is_php"] = True
    php_req = None
    if path == "/composer.json":
        php_req = (data.get("require", {}) or {}).get("php") \
            or (data.get("config", {}).get("platform", {}) or {}).get("php")
        if php_req:
            mm = re.search(r"(\d+\.\d+(?:\.\d+)?)", php_req)
            if mm:
                evidence.append(ev("exposed", "floor",
                                   "composer.json require.php=%s -> floor %s" % (php_req, mm.group(1)),
                                   version=mm.group(1), granularity="minor-floor"))
                return True
    else:  # composer.lock
        plat = (data.get("platform-overrides", {}) or {}).get("php") \
            or (data.get("platform", {}) or {}).get("php")
        if plat:
            mm = re.search(r"(\d+\.\d+(?:\.\d+)?)", str(plat))
            if mm:
                evidence.append(ev("exposed", "medium",
                                   "composer.lock platform php=%s" % plat,
                                   version=mm.group(1),
                                   granularity="patch" if mm.group(1).count(".") == 2 else "minor"))
                return True
    evidence.append(ev("exposed", "low", "%s exposed (PHP app)" % path))
    return True


def _probe_dummy_php(scheme, netloc, host_header, args, evidence, rec) -> None:
    """Request a random non-existent *.php path and inspect the response. Even when the
    site index is static, a .php request is routed through the PHP SAPI by many setups,
    which can emit X-Powered-By / Server PHP tokens or a PHP-styled 404 body — revealing
    PHP (and sometimes the version) that a plain GET / would miss."""
    rand = base64.b32encode(os.urandom(6)).decode("ascii").strip("=").lower()
    url = "%s://%s/%s404.php" % (scheme, netloc, rand)
    r = http_get(url, host_header, args.timeout, max_redirects=1)
    if r["status"] is None:
        return
    hdrs = r["headers"]
    server = " ".join(header_get(hdrs, "server"))
    xpb = " ".join(header_get(hdrs, "x-powered-by"))
    for src, val in (("X-Powered-By", xpb), ("Server", server)):
        m = PHP_VER_RE.search(val)
        if m:
            base_only = rec.get("distro") in ("debian", "ubuntu", "redhat", "centos", "rocky", "alma")
            evidence.append(ev("dummyphp", "authoritative",
                               "dummy .php %s: %s" % (src, val.strip()[:100]),
                               version=m.group(1), granularity="patch", base_only=base_only))
    # PHP-presence from the 404/error body or PHP cookies even without a version
    body_txt = r["body"].decode("latin-1", "replace")
    if "PHP" in xpb.upper() or PHPSESSID_RE.search(" ".join(header_get(hdrs, "set-cookie"))) \
            or ERR_ANY_RE.search(body_txt):
        rec["is_php"] = True
        if not any(e["method"] == "dummyphp" for e in evidence):
            evidence.append(ev("dummyphp", "medium",
                               "dummy .php request routed through PHP (status %s)" % r["status"]))


def _probe_easter_egg(scheme, netloc, host_header, args, evidence, rec) -> None:
    url = "%s://%s/?=%s" % (scheme, netloc, EGG_GUIDS["php_logo"])
    r = http_get(url, host_header, args.timeout, max_redirects=1)
    if r["status"] == 200 and r["body"][:4] == b"\x89PNG":
        rec["is_php"] = True
        evidence.append(ev("easteregg", "high",
                           "expose_php logo GUID returned PNG -> PHP <= 5.4",
                           version="5.4", granularity="major-ceiling"))


def _shodan_enrich(ip, key, timeout, evidence, rec) -> None:
    try:
        url = "https://api.shodan.io/shodan/host/%s?key=%s" % (ip, key)
        # Trusted first-party API: verify the certificate so the API key can't be
        # captured by a TLS MITM (unlike target scanning, which is intentionally unverified).
        r = http_get(url, None, timeout, max_redirects=2, verify=True)
        if r["status"] != 200:
            rec["errors"].append("shodan:%s" % r["status"])
            return
        data = json.loads(r["body"].decode("utf-8", "replace"))
        ver = None
        for svc in data.get("data", []):
            comps = svc.get("http", {}).get("components", {})
            if "PHP" in comps:
                rec["is_php"] = True
            for line in (svc.get("data", "") or "").splitlines():
                m = PHP_VER_RE.search(line)
                if m:
                    ver = m.group(1)
            for cpe in svc.get("cpe23", []) + svc.get("cpe", []):
                m = re.search(r"php:php:(\d+\.\d+(?:\.\d+)?)", cpe)
                if m:
                    ver = m.group(1)
        if ver:
            evidence.append(ev("shodan", "high", "Shodan passive -> PHP %s" % ver,
                               version=ver, granularity="patch" if ver.count(".") == 2 else "minor"))
    except Exception as e:
        rec["errors"].append("shodan:%s" % e)


# PHP2Shell == CVE-2026-109618 / CVE-2026-109619 (released 2026-10-21; CVSSv4 9.2;
# unauthenticated RCE; exploited in the wild). Any PHP below the branch fix is affected,
# AND every branch older than the tracked set (PHP <= 8.1, 8.0, 7.x, 5.x ...) is also
# affected because those EOL branches did not receive a new release. Detection is purely
# version-based: the tool NEVER sends the exploit.
PHP2SHELL_CVES = "CVE-2026-109618/CVE-2026-109619"


def php2shell_status(rec: dict, thresholds: dict) -> tuple[str, str]:
    """Return (status, detail) focused on PHP2Shell exposure.
    status in {affected, patched, suspect, unknown, n/a}."""
    if not rec.get("is_php"):
        return ("n/a", "not identified as PHP")
    v = rec.get("php_version")
    if not v:
        return ("suspect", "PHP confirmed but version undisclosed — verify manually (%s)" % PHP2SHELL_CVES)
    t = ver_tuple(v)
    if not t or len(t) < 2:
        return ("unknown", "unparseable version %r" % v)
    branch = "%d.%d" % (t[0], t[1])
    safe_map = thresholds["safe_min"]
    safe = safe_map.get(branch)
    if safe is None:
        lowest = min(safe_map, key=lambda b: ver_tuple(b))
        if ver_lt("%d.%d.0" % (t[0], t[1]), lowest + ".0"):
            return ("affected", "%s is an EOL/unpatched branch — affected by %s" % (v, PHP2SHELL_CVES))
        return ("unknown", "%s: branch newer than tracked; confirm it includes the %s fix" % (v, PHP2SHELL_CVES))
    partial = len(t) < 3
    if ver_lt(v, safe):
        note = " (patch level unknown -> assumed affected)" if partial else ""
        extra = " [distro backport may already patch this]" if rec.get("version_base_only") else ""
        return ("affected", "%s < %s%s — vulnerable to %s%s" % (v, safe, note, PHP2SHELL_CVES, extra))
    return ("patched", "%s >= %s — %s fixed" % (v, safe, PHP2SHELL_CVES))


# When two evidence items tie on confidence, prefer the more trustworthy source: an
# exact phpinfo/Zend reading beats a (possibly distro-frozen) banner.
SRC_PREF = {"phpinfo": 5, "zend": 4, "exposed": 3, "shodan": 3, "headers": 2,
            "dummyphp": 2, "errorpage": 1, "cms": 1, "presence": 0, "favicon": 0}


def _finalize(rec: dict, thresholds: dict) -> None:
    """Pick the best version evidence and compute the vulnerability verdict."""
    def sort_key(e):
        has_patch = 1 if (e.get("version") and str(e["version"]).count(".") >= 2) else 0
        # Prefer: higher confidence, patch-level, trusted source, and a non-base_only
        # (not distro-frozen) reading over a backport-ambiguous banner.
        return (e["confidence"], has_patch, SRC_PREF.get(e["method"], 0),
                0 if e.get("base_only") else 1)

    versioned = [e for e in rec["evidence"] if e.get("version")]
    if versioned:
        best = max(versioned, key=sort_key)
        rec["php_version"] = best["version"]
        rec["php_version_source"] = best["method"]
        rec["php_version_granularity"] = best.get("granularity")
        rec["version_base_only"] = best.get("base_only", False)
        rec["is_php"] = True

    st, detail = verdict(rec["php_version"], thresholds)
    if st == "unknown" and rec["is_php"] and not rec["php_version"]:
        detail = "confirmed PHP, version not disclosed"
    if rec["version_base_only"] and st == "vulnerable":
        detail += " [distro-packaged: patch backported, numeric version may understate real patch level]"
    rec["status"] = st
    rec["detail"] = detail

    p2_st, p2_detail = php2shell_status(rec, thresholds)
    rec["php2shell"] = p2_st
    rec["php2shell_detail"] = p2_detail
    # Surface PHP2Shell exposure in the default (non --php2shell) outputs too, so a
    # vulnerable version is never silently reported as merely 'eol'/'vulnerable'
    # without naming the exposure. In --php2shell mode the dedicated php2shell_detail
    # column is shown instead, so this prefix only affects the version-mode view.
    if p2_st == "affected":
        rec["detail"] = "PHP2Shell-vulnerable — " + rec["detail"]


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #

COLORS = {
    "vulnerable": "\033[91m", "eol": "\033[95m", "ok": "\033[92m",
    "unknown": "\033[90m", "unreachable": "\033[90m",
    "affected": "\033[91m", "patched": "\033[92m", "suspect": "\033[93m", "n/a": "\033[90m",
    "reset": "\033[0m",
}


def colorize(text, status, enable):
    if not enable:
        return text
    return "%s%s%s" % (COLORS.get(status, ""), text, COLORS["reset"])


def print_table(records, use_color, status_key="status", status_hdr="STATUS", detail_key="detail"):
    cols = [("TARGET", 26), ("IP", 16), ("PHP", 14), (status_hdr, 11), ("SRC", 10), ("DETAIL", 44)]
    header = "  ".join(name.ljust(w) for name, w in cols)
    print(header)
    print("-" * len(header))
    for r in records:
        st = r.get(status_key, "unknown")
        row = [
            (r.get("target") or "")[:26].ljust(26),
            (r.get("resolved_ip") or "")[:16].ljust(16),
            (r.get("php_version") or "-")[:14].ljust(14),
            str(st)[:11].ljust(11),
            (r.get("php_version_source") or "-")[:10].ljust(10),
            (r.get(detail_key) or "")[:44],
        ]
        print(colorize("  ".join(row), st, use_color))


def print_summary(records, status_key="status"):
    counts: dict[str, int] = {}
    for r in records:
        st = r.get(status_key, "unknown")
        counts[st] = counts.get(st, 0) + 1
    order = ["vulnerable", "affected", "eol", "suspect", "ok", "patched", "unknown", "n/a", "unreachable"]
    parts = ["%s=%d" % (k, counts[k]) for k in order if k in counts]
    for k, v in counts.items():
        if k not in order:
            parts.append("%s=%d" % (k, v))
    print("\nSummary: %d host(s) | %s" % (len(records), ", ".join(parts)))
    if status_key != "php2shell":
        affected = sum(1 for r in records if r.get("php2shell") == "affected")
        if affected:
            print("⚠ PHP2Shell (%s): %d affected host(s) — run with --php2shell "
                  "for the full triage view." % (PHP2SHELL_CVES, affected))


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def parse_args(argv):
    p = argparse.ArgumentParser(
        prog="php2shell-detect",
        description="Multi-method remote PHP version detector & PHP2Shell (CVE-2026-109618/"
                    "CVE-2026-109619) vulnerability triage.",
        epilog="Only scan hosts you are authorized to test. Detection only; no exploitation.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("targets", nargs="*",
                   help="IP, domain, CIDR (1.2.3.0/24), or range (1.2.3.10-1.2.3.40 / ...10-40)")
    p.add_argument("-f", "--file", help="file with one target per line (# comments allowed)")
    p.add_argument("-w", "--workers", type=int, default=5, help="concurrent worker threads (default: 5)")
    p.add_argument("-t", "--timeout", type=float, default=7.0, help="per-request timeout seconds (default: 7)")
    p.add_argument("--scheme", choices=["auto", "http", "https"], default="auto",
                   help="scheme to probe (default: auto = https then http)")
    p.add_argument("--max-redirects", type=int, default=4, help="max redirects to follow (default: 4)")
    p.add_argument("--deep", action="store_true",
                   help="probe the full phpinfo/exposed-file path list and the legacy easter-egg GUID (noisier)")
    p.add_argument("--no-active", action="store_true",
                   help="only read the baseline GET / (no extra path probing)")
    p.add_argument("--no-favicon", action="store_true", help="skip favicon hashing")
    p.add_argument("--shodan-key", default=os.environ.get("SHODAN_API_KEY"),
                   help="Shodan API key for passive enrichment (or set SHODAN_API_KEY)")
    p.add_argument("--max-hosts", type=int, default=0,
                   help="safety cap on expanded host count in normal mode (0 = unlimited, the default)")
    p.add_argument("--thresholds", help="path to thresholds JSON (default: ./thresholds.json)")
    p.add_argument("--targets-from", help="stream targets from a file (IP/domain/CIDR/range per line); memory-light")
    p.add_argument("--json", dest="json_out", help="write full results as JSON array to this file")
    p.add_argument("--jsonl", action="store_true", help="stream one JSON object per host to stdout")
    p.add_argument("--html", help="write an HTML report to this file")
    p.add_argument("--md", help="write a Markdown report to this file")
    p.add_argument("--csv", help="write a CSV report to this file")
    p.add_argument("--xlsx", help="write an XLSX (Excel) report to this file")
    p.add_argument("--only-vuln", action="store_true",
                   help="show only vulnerable/affected hosts in the table")
    p.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    p.add_argument("--no-progress", action="store_true",
                   help="disable the live progress bar (shown on stderr while scanning)")
    p.add_argument("--yes", action="store_true", help="acknowledge authorization and skip the confirmation prompt")

    g2 = p.add_argument_group("PHP2Shell (CVE-2026-109618/CVE-2026-109619)")
    g2.add_argument("--php2shell", action="store_true",
                    help="triage mode focused on the PHP2Shell RCE: flag every PHP below the "
                         "2026-10-21 fix (8.2.35/8.3.36/8.4.27/8.5.12) or on an EOL branch as AFFECTED "
                         "(detection only; never exploits)")

    g = p.add_argument_group("internet-wide survey (use responsibly)")
    g.add_argument("--survey", action="store_true",
                   help="streaming survey mode: randomized order, default special-use exclusions, "
                        "sharding and rate limiting; for sharing aggregate data with the community")
    g.add_argument("--contact", help="REQUIRED in --survey mode: abuse/opt-out contact (email or URL) "
                                      "advertised in the User-Agent so admins can reach you / opt out")
    g.add_argument("--shard", help="process only shard i of n, as i/n (e.g. 0/16) to split work across runs")
    g.add_argument("--rate", type=float, default=0.0,
                   help="global max outbound connections per second (0 = unlimited; be polite in surveys)")
    g.add_argument("--exclude", action="append", default=[],
                   help="file of CIDR ranges to never scan (repeatable); merged with built-in special-use list")
    g.add_argument("--seed", type=int, default=0, help="permutation seed for reproducible survey ordering")
    g.add_argument("--no-randomize", action="store_true", help="survey in sequential order (not recommended)")
    g.add_argument("--limit", type=int, default=0, help="stop after scanning this many hosts (0 = no limit)")
    g.add_argument("--survey-report", help="write an anonymized aggregate JSON report (safe to share)")
    g.add_argument("--no-mask-ips", action="store_true",
                   help="survey mode masks the last two octets of IPs (203.0.x.x) in output and "
                        "reports by default; pass this to keep full IPs (for your own private data)")

    p.add_argument("-v", "--version", action="version", version="php2shell-detect " + __version__)
    return p.parse_args(argv)


def _load_excludes(files) -> ExcludeSet:
    cidrs = list(DEFAULT_EXCLUDES)
    for path in files or []:
        try:
            with open(path, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        cidrs.append(line.split()[0])
        except OSError as e:
            print("warning: cannot read exclude file %s: %s" % (path, e), file=sys.stderr)
    return ExcludeSet(cidrs)


def _parse_shard(spec):
    if not spec:
        return 0, 1
    m = re.fullmatch(r"(\d+)\s*/\s*(\d+)", spec.strip())
    if not m:
        raise SystemExit("--shard must look like i/n (e.g. 0/16)")
    i, n = int(m.group(1)), int(m.group(2))
    if n < 1 or i < 0 or i >= n:
        raise SystemExit("--shard i/n requires 0 <= i < n")
    return i, n


def run_bounded(host_iter, workers, make_result, on_result):
    """Run make_result over a (possibly huge/streaming) host iterator with a bounded
    in-flight window so memory stays flat regardless of input size."""
    workers = max(1, workers)
    window = max(workers * 4, workers)
    it = iter(host_iter)
    with cf.ThreadPoolExecutor(max_workers=workers) as pool:
        inflight = set()
        exhausted = False
        while True:
            while not exhausted and len(inflight) < window:
                try:
                    h = next(it)
                except StopIteration:
                    exhausted = True
                    break
                inflight.add(pool.submit(make_result, h))
            if not inflight:
                break
            done, inflight = cf.wait(inflight, return_when=cf.FIRST_COMPLETED)
            for fut in done:
                on_result(fut.result())


def _safe_scan(h, args, thresholds):
    try:
        return scan_host(h, args, thresholds)
    except Exception as e:  # never let one host kill the run
        return {"target": h, "status": "unknown", "php2shell": "unknown",
                "detail": "scan error: %s" % e, "php2shell_detail": "scan error",
                "php_version": None, "resolved_ip": None, "php_version_source": None,
                "is_php": False, "reachable": False, "evidence": []}


class Progress:
    """Live scan progress on stderr. Uses tqdm when it is installed (a common,
    optional module) and otherwise a dependency-free stdlib bar. On a TTY it draws
    an updating bar; off a TTY (piped/log) it emits an occasional newline-terminated
    status line so long runs still leave a trail. Never touches stdout, so report
    and --jsonl output are unaffected."""

    def __init__(self, total, enabled=True, stream=None):
        self.total = int(total) if total and total > 0 else 0
        self.n = 0
        self.flagged = 0
        self.stream = stream or sys.stderr
        self.enabled = bool(enabled)
        self.t0 = time.monotonic()
        self._last = 0.0
        self._tty = False
        self._tqdm = None
        if not self.enabled:
            return
        try:
            self._tty = self.stream.isatty()
        except Exception:
            self._tty = False
        if self._tty:
            try:
                from tqdm import tqdm  # optional; falls back to the stdlib bar below
                self._tqdm = tqdm(total=self.total or None, unit="host",
                                  dynamic_ncols=True, leave=False, file=self.stream)
            except Exception:
                self._tqdm = None

    def update(self, flagged=False):
        self.n += 1
        if flagged:
            self.flagged += 1
        if not self.enabled:
            return
        if self._tqdm is not None:
            self._tqdm.update(1)
            if self.flagged:
                self._tqdm.set_postfix_str("flagged=%d" % self.flagged, refresh=False)
            return
        now = time.monotonic()
        if self._tty:
            # throttle redraws; always draw the final tick of a known total
            if now - self._last < 0.2 and not (self.total and self.n >= self.total):
                return
            self._last = now
            self._write(self._bar(now) + "\r", flush=True)
        else:
            if (self.n % 2000) and (now - self._last) < 30.0:
                return
            self._last = now
            self._write(self._bar(now) + "\n", flush=True)

    def _bar(self, now):
        elapsed = now - self.t0
        rate = self.n / elapsed if elapsed > 0 else 0.0
        if self.total:
            frac = min(1.0, self.n / self.total)
            width = 28
            filled = int(frac * width)
            return "  [%s] %d/%d %3.0f%%  %.0f/s  flagged=%d  %.0fs" % (
                "#" * filled + "-" * (width - filled), self.n, self.total,
                frac * 100.0, rate, self.flagged, elapsed)
        return "  scanned=%d  flagged=%d  %.0f/s  %.0fs" % (
            self.n, self.flagged, rate, elapsed)

    def _write(self, text, flush=False):
        try:
            self.stream.write(text)
            if flush:
                self.stream.flush()
        except Exception:
            pass

    def close(self):
        if not self.enabled:
            return
        if self._tqdm is not None:
            try:
                self._tqdm.close()
            except Exception:
                pass
            return
        if self.n:
            # leave a final, newline-terminated summary of the bar
            self._write("\r" + self._bar(time.monotonic()) + "\n" if self._tty
                        else self._bar(time.monotonic()) + "\n", flush=True)


def main(argv=None):
    args = parse_args(argv if argv is not None else sys.argv[1:])
    global _UA, _RATE

    tokens = list(args.targets)
    if args.file:
        with open(args.file, "r", encoding="utf-8") as fh:
            tokens += [ln.strip() for ln in fh if ln.strip() and not ln.strip().startswith("#")]

    thresholds = load_thresholds(args.thresholds)
    shard_id, shard_n = _parse_shard(args.shard)
    excludes = _load_excludes(args.exclude)
    status_key = "php2shell" if args.php2shell else "status"
    detail_key = "php2shell_detail" if args.php2shell else "detail"
    status_hdr = "PHP2SHELL" if args.php2shell else "STATUS"
    bad_states = ("affected", "suspect") if args.php2shell else ("vulnerable", "eol")

    # --- survey-mode validation & politeness wiring ---
    survey = bool(args.survey)
    streaming = survey or bool(args.targets_from)
    if survey:
        if not tokens:
            print("error: --survey needs target ranges (e.g. 0.0.0.0/0, or a list of CIDRs).", file=sys.stderr)
            return 2
        if not args.contact:
            print("error: --survey requires --contact <email|url> so admins can reach you and opt out.",
                  file=sys.stderr)
            return 2
        if not (args.survey_report or args.jsonl or args.json_out):
            print("error: --survey needs an output sink (--survey-report / --jsonl / --json) to be useful.",
                  file=sys.stderr)
            return 2
    if args.contact:
        _UA = "php2shell-detect/%s (+authorized-security-testing; contact: %s)" % (__version__, args.contact)
    if args.rate and args.rate > 0:
        _RATE = RateLimiter(args.rate)

    if not tokens and not args.targets_from:
        print("error: no targets (positional, -f FILE, or --targets-from). See --help.", file=sys.stderr)
        return 2

    # --- build the host source ---
    if args.targets_from:
        host_source = file_targets(args.targets_from, shard_id, shard_n, args.limit)
        total_hint = None
    elif survey:
        host_source = survey_targets(tokens, excludes, shard_id, shard_n, args.seed,
                                     not args.no_randomize, args.limit)
        try:
            total_hint = IPv4Space(_parse_networks(tokens)).total
        except Exception:
            total_hint = None
    else:
        # Cheap pre-count so a huge CIDR in normal mode doesn't silently materialize
        # millions of hosts in memory (the cap is off by default per design).
        if not args.max_hosts:
            try:
                approx = sum(n.num_addresses for n in _parse_networks(tokens))
            except Exception:
                approx = 0
            if approx > 262144:
                sys.stderr.write(
                    "warning: ~%d hosts expand in memory in normal mode. For internet-scale "
                    "ranges use --survey (streams, flat memory) or --targets-from, or set "
                    "--max-hosts.\n" % approx)
        host_list = build_hostlist(tokens, args.max_hosts)
        if shard_n > 1:
            host_list = [h for i, h in enumerate(host_list) if i % shard_n == shard_id]
        if args.limit:
            host_list = host_list[:args.limit]
        host_source = host_list
        total_hint = len(host_list)

    # --- authorization gate ---
    if not args.yes:
        scope = ("up to ~%d addresses (minus exclusions/shard)" % total_hint) if total_hint else "a streamed target list"
        sys.stderr.write(
            "\n*** AUTHORIZED USE ONLY ***\n"
            "You are about to actively probe %s.\n"
            "%sOnly continue if you own these hosts or have explicit written authorization.\n"
            "Unauthorized scanning may violate the CFAA / Computer Misuse Act and similar laws.\n"
            % (scope,
               "SURVEY MODE: please also honor opt-out requests and keep --rate polite.\n" if survey else ""))
        if sys.stdin is not None and sys.stdin.isatty():
            try:
                ans = input("Type 'yes' to proceed: ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                ans = ""
            if ans != "yes":
                print("Aborted.", file=sys.stderr)
                return 1
        else:
            print("Non-interactive run without --yes; aborting for safety.", file=sys.stderr)
            return 1

    use_color = (not args.no_color) and sys.stdout.isatty()
    t0 = time.time()

    agg = Aggregate() if streaming else None
    records: list[dict] = [] if not streaming else []  # in streaming mode we keep none long-term
    json_fh = open(args.json_out, "w", encoding="utf-8") if (args.json_out and streaming) else None
    if json_fh:
        json_fh.write("[\n")
    first_json = [True]
    seen = [0]
    found = [0]

    mask_ips = survey and not args.no_mask_ips

    # Live progress on stderr (never stdout). Use a known total when we have one and
    # it is not internet-scale; an unbounded survey shows an indeterminate counter.
    progress_total = args.limit if (survey and args.limit) else total_hint
    if progress_total and progress_total > 10_000_000:
        progress_total = 0
    progress = Progress(progress_total, enabled=not args.no_progress)

    def on_result(rec):
        seen[0] += 1
        if mask_ips:
            mask_record(rec)
        flagged = rec.get(status_key) in bad_states
        if flagged:
            found[0] += 1
        if args.jsonl:
            print(json.dumps(rec, default=str))
            sys.stdout.flush()
        if agg is not None:
            agg.add(rec)
            if json_fh:
                json_fh.write(("" if first_json[0] else ",\n") + json.dumps(rec, default=str))
                first_json[0] = False
        else:
            records.append(rec)
        progress.update(flagged=flagged)

    run_bounded(host_source, args.workers, lambda h: _safe_scan(h, args, thresholds), on_result)
    progress.close()

    # --- output ---
    if not streaming:
        order = {h: i for i, h in enumerate(host_source)}
        records.sort(key=lambda r: order.get(r.get("target"), 1 << 30))
        shown = [r for r in records if r.get(status_key) in bad_states] if args.only_vuln else records
        if not args.jsonl:
            print_table(shown, use_color, status_key, status_hdr, detail_key)
            print_summary(records, status_key)
            print("Elapsed: %.1fs with %d worker(s)." % (time.time() - t0, args.workers))
        if args.json_out:
            with open(args.json_out, "w", encoding="utf-8") as fh:
                json.dump(records, fh, indent=2, default=str)
            if not args.jsonl:
                print("Wrote JSON results to %s" % args.json_out)
        if args.html or args.md:
            norm_agg = Aggregate()
            for r in records:
                norm_agg.add(r)
            meta = {"mode": "php2shell" if args.php2shell else "version",
                    "shard": "%d/%d" % (shard_id, shard_n)}
            write_reports(args, thresholds, meta, status_key, norm_agg, records)
    else:
        if json_fh:
            json_fh.write("\n]\n")
            json_fh.close()
        if not args.jsonl:
            print_summary_streaming(agg, status_key, t0, args.workers)
        if args.survey_report and agg is not None:
            meta = {"shard": "%d/%d" % (shard_id, shard_n), "seed": args.seed,
                    "randomized": not args.no_randomize, "rate_per_sec": args.rate,
                    "contact": args.contact, "limit": args.limit or None,
                    "php2shell_focus": bool(args.php2shell), "ip_masking": mask_ips}
            rep = agg.report(thresholds, meta)
            with open(args.survey_report, "w", encoding="utf-8") as fh:
                json.dump(rep, fh, indent=2, default=str)
            if not args.jsonl:
                print("Wrote anonymized survey report to %s (safe to share)." % args.survey_report)
        if (args.html or args.md) and agg is not None:
            meta = {"mode": "php2shell" if args.php2shell else "version",
                    "shard": "%d/%d" % (shard_id, shard_n), "seed": args.seed,
                    "survey": True, "contact": args.contact}
            write_reports(args, thresholds, meta, status_key, agg, [])

    return 3 if found[0] else 0


def print_summary_streaming(agg, status_key, t0, workers):
    if agg is None:
        return
    rep_counts = agg.by_php2shell if status_key == "php2shell" else agg.by_status
    label = "PHP2Shell" if status_key == "php2shell" else "Version"
    print("\nSurvey complete: %d scanned, %d reachable, %d confirmed PHP (%.1fs, %d workers)."
          % (agg.total, agg.reachable, agg.is_php, time.time() - t0, workers))
    top_branch = sorted(agg.by_branch.items(), key=lambda x: -x[1])[:8]
    if top_branch:
        print("Top branches: " + ", ".join("%s=%d" % kv for kv in top_branch))
    print("%s tally: " % label + ", ".join("%s=%d" % kv for kv in sorted(rep_counts.items(), key=lambda x: -x[1])))
    if status_key != "php2shell":
        affected = agg.by_php2shell.get("affected", 0)
        if affected:
            print("⚠ PHP2Shell (%s): %d affected host(s) — run with --php2shell "
                  "for the full triage view." % (PHP2SHELL_CVES, affected))


# --------------------------------------------------------------------------- #
# HTML / Markdown reports
# --------------------------------------------------------------------------- #

def build_report_model(thresholds, meta, status_key, agg, rows):
    rep = agg.report(thresholds, meta)
    rep["status_key"] = status_key
    rep["rows"] = rows or []
    return rep


def _rows_tally(rep, status_key):
    return rep["by_php2shell"] if status_key == "php2shell" else rep["by_status"]


def render_markdown(rep) -> str:
    sk = rep["status_key"]
    focus = "PHP2Shell (CVE-2026-109618 / CVE-2026-109619)" if sk == "php2shell" else "PHP version"
    t = rep["totals"]
    out = []
    out.append("# php2shell-detect report — %s" % focus)
    out.append("")
    out.append("- Generated: `%s`" % rep["generated_at"])
    out.append("- Tool: php2shell-detect v%s" % rep["tool_version"])
    out.append("- Thresholds (safe minimum): " +
               ", ".join("%s≥%s" % (k, v) for k, v in rep["thresholds"]["safe_min"].items()))
    out.append("")
    out.append("## Totals")
    out.append("")
    out.append("| Metric | Count |")
    out.append("|---|---|")
    out.append("| Scanned | %d |" % t["scanned"])
    out.append("| Reachable | %d |" % t["reachable"])
    out.append("| Confirmed PHP | %d |" % t["confirmed_php"])
    out.append("| Behind proxy/CDN | %d |" % t["behind_proxy_cdn"])
    out.append("")
    out.append("## %s status" % ("PHP2Shell" if sk == "php2shell" else "Version"))
    out.append("")
    out.append("| Status | Count |")
    out.append("|---|---|")
    for k, v in sorted(_rows_tally(rep, sk).items(), key=lambda x: -x[1]):
        out.append("| %s | %d |" % (k, v))
    out.append("")
    if rep["by_branch"]:
        out.append("## PHP branch distribution")
        out.append("")
        out.append("| Branch | Count |")
        out.append("|---|---|")
        for k, v in rep["by_branch"].items():
            out.append("| %s | %d |" % (k, v))
        out.append("")
    if rep["rows"]:
        out.append("## Hosts")
        out.append("")
        out.append("| Target | IP | PHP | Status | Source | Detail |")
        out.append("|---|---|---|---|---|---|")
        for r in rep["rows"]:
            detail = (r.get("php2shell_detail" if sk == "php2shell" else "detail") or "").replace("|", "\\|")
            out.append("| %s | %s | %s | %s | %s | %s |" % (
                r.get("target") or "", r.get("resolved_ip") or "",
                r.get("php_version") or "-", r.get(sk) or "unknown",
                r.get("php_version_source") or "-", detail[:160]))
        out.append("")
    out.append("---")
    out.append("")
    out.append("_Detection only; no exploitation performed. Scan authorized targets only._")
    return "\n".join(out) + "\n"


def render_html(rep) -> str:
    import html
    sk = rep["status_key"]
    focus = "PHP2Shell — CVE-2026-109618 / CVE-2026-109619" if sk == "php2shell" else "PHP version"
    t = rep["totals"]
    badge = {"affected": "#c0392b", "vulnerable": "#c0392b", "eol": "#8e44ad",
             "suspect": "#d68910", "ok": "#1e8449", "patched": "#1e8449",
             "unknown": "#7f8c8d", "n/a": "#7f8c8d", "unreachable": "#95a5a6"}

    def esc(s):
        return html.escape(str(s if s is not None else ""))

    def tally_rows(d):
        return "".join(
            "<tr><td><span class='pill' style='background:%s'>%s</span></td><td>%d</td></tr>"
            % (badge.get(k, "#7f8c8d"), esc(k), v)
            for k, v in sorted(d.items(), key=lambda x: -x[1]))

    host_rows = ""
    for r in rep["rows"]:
        st = r.get(sk) or "unknown"
        detail = r.get("php2shell_detail" if sk == "php2shell" else "detail")
        host_rows += ("<tr><td>%s</td><td>%s</td><td><b>%s</b></td>"
                      "<td><span class='pill' style='background:%s'>%s</span></td>"
                      "<td>%s</td><td class='detail'>%s</td></tr>") % (
            esc(r.get("target")), esc(r.get("resolved_ip")), esc(r.get("php_version") or "-"),
            badge.get(st, "#7f8c8d"), esc(st), esc(r.get("php_version_source") or "-"), esc(detail))
    hosts_section = ("<h2>Hosts</h2><table class='grid'><thead><tr><th>Target</th><th>IP</th>"
                     "<th>PHP</th><th>Status</th><th>Source</th><th>Detail</th></tr></thead>"
                     "<tbody>%s</tbody></table>" % host_rows) if rep["rows"] else ""
    branch_section = ""
    if rep["by_branch"]:
        branch_section = ("<h2>PHP branch distribution</h2><table class='grid'><thead><tr>"
                          "<th>Branch</th><th>Count</th></tr></thead><tbody>%s</tbody></table>" %
                          "".join("<tr><td>%s</td><td>%d</td></tr>" % (esc(k), v)
                                  for k, v in rep["by_branch"].items()))
    thr = ", ".join("%s&ge;%s" % (esc(k), esc(v)) for k, v in rep["thresholds"]["safe_min"].items())

    return """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>php2shell-detect report</title>
<style>
 :root{color-scheme:light dark}
 body{font:14px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;margin:0;padding:2rem;
      background:#f5f6f8;color:#1b1f24}
 @media (prefers-color-scheme:dark){body{background:#0e1116;color:#e6edf3}
   .card,.grid{background:#161b22;border-color:#30363d}.grid th{background:#21262d}}
 h1{font-size:1.5rem;margin:0 0 .25rem}h2{font-size:1.1rem;margin:1.5rem 0 .5rem}
 .sub{color:#6b7280;margin:0 0 1.5rem}
 .cards{display:flex;flex-wrap:wrap;gap:1rem;margin:1rem 0}
 .card{background:#fff;border:1px solid #e5e7eb;border-radius:10px;padding:1rem 1.25rem;min-width:140px}
 .card .n{font-size:1.8rem;font-weight:700}.card .l{color:#6b7280;font-size:.8rem;text-transform:uppercase;letter-spacing:.04em}
 table.grid{border-collapse:collapse;width:100%%;background:#fff;border:1px solid #e5e7eb;border-radius:10px;overflow:hidden}
 .grid th,.grid td{padding:.5rem .7rem;border-bottom:1px solid #e5e7eb;text-align:left;vertical-align:top}
 .grid th{background:#f3f4f6;font-size:.78rem;text-transform:uppercase;letter-spacing:.03em}
 .pill{color:#fff;padding:.1rem .5rem;border-radius:999px;font-size:.75rem;font-weight:600}
 .detail{color:#6b7280;font-size:.85rem}
 footer{margin-top:2rem;color:#6b7280;font-size:.8rem}
 .two{display:flex;flex-wrap:wrap;gap:2rem}
</style></head><body>
<h1>php2shell-detect &mdash; %(focus)s</h1>
<p class="sub">Generated %(generated)s &middot; tool v%(ver)s &middot; safe thresholds: %(thr)s<br>
Detection only &mdash; no exploitation performed.</p>
<div class="cards">
 <div class="card"><div class="n">%(scanned)d</div><div class="l">Scanned</div></div>
 <div class="card"><div class="n">%(reachable)d</div><div class="l">Reachable</div></div>
 <div class="card"><div class="n">%(php)d</div><div class="l">Confirmed PHP</div></div>
 <div class="card"><div class="n">%(proxy)d</div><div class="l">Behind proxy/CDN</div></div>
</div>
<div class="two">
<div><h2>%(statuslabel)s status</h2>
<table class="grid"><thead><tr><th>Status</th><th>Count</th></tr></thead><tbody>%(tally)s</tbody></table></div>
<div>%(branch)s</div>
</div>
%(hosts)s
<footer>php2shell-detect v%(ver)s. CVE-2026-109618 / CVE-2026-109619 fixed in PHP 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12
(released 2026-10-21). Scan only hosts you are authorized to test.</footer>
</body></html>
""" % {
        "focus": esc(focus), "generated": esc(rep["generated_at"]), "ver": esc(rep["tool_version"]),
        "thr": thr, "scanned": t["scanned"], "reachable": t["reachable"], "php": t["confirmed_php"],
        "proxy": t["behind_proxy_cdn"],
        "statuslabel": "PHP2Shell" if sk == "php2shell" else "Version",
        "tally": tally_rows(_rows_tally(rep, sk)), "branch": branch_section, "hosts": hosts_section,
    }


def _tabular_sheets(rep, status_key):
    """Return an ordered {sheet_name: [header_row, *data_rows]} model for CSV/XLSX."""
    sheets = {}
    t = rep["totals"]
    sheets["Summary"] = [
        ["metric", "value"],
        ["scanned", t["scanned"]], ["reachable", t["reachable"]],
        ["confirmed_php", t["confirmed_php"]], ["behind_proxy_cdn", t["behind_proxy_cdn"]],
        ["generated_at", rep["generated_at"]], ["tool_version", rep["tool_version"]],
        ["thresholds", ", ".join("%s>=%s" % kv for kv in rep["thresholds"]["safe_min"].items())],
    ]
    tally = rep["by_php2shell"] if status_key == "php2shell" else rep["by_status"]
    sheets["Status"] = [["status", "count"]] + [[k, v] for k, v in sorted(tally.items(), key=lambda x: -x[1])]
    if rep.get("by_branch"):
        sheets["Branches"] = [["branch", "count"]] + [[k, v] for k, v in rep["by_branch"].items()]
    if rep.get("top_versions"):
        sheets["Versions"] = [["version", "count"]] + [[k, v] for k, v in rep["top_versions"].items()]
    if rep["rows"]:
        hdr = ["target", "resolved_ip", "php_version", "status", "php2shell", "source",
               "granularity", "is_php", "distro", "proxy", "detail"]
        data = [hdr]
        for r in rep["rows"]:
            data.append([
                r.get("target"), r.get("resolved_ip"), r.get("php_version"),
                r.get("status"), r.get("php2shell"), r.get("php_version_source"),
                r.get("php_version_granularity"), r.get("is_php"), r.get("distro"),
                r.get("proxy"),
                r.get("php2shell_detail") if status_key == "php2shell" else r.get("detail"),
            ])
        sheets["Hosts"] = data
    return sheets


def _csv_safe(v):
    """Neutralize CSV formula injection: spreadsheet apps execute a cell whose text
    starts with = + - @ (or a leading tab/CR). Remote banners/bodies feed these cells,
    so prefix such values with a single quote."""
    if isinstance(v, str) and v and v[0] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + v
    return v


def write_csv(path, rep, status_key):
    import csv
    sheets = _tabular_sheets(rep, status_key)

    def safe(row):
        return [_csv_safe(c) for c in row]

    # Prefer per-host rows; otherwise emit the aggregate tables stacked with blank separators.
    with open(path, "w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        if "Hosts" in sheets:
            for row in sheets["Hosts"]:
                w.writerow(safe(row))
        else:
            for i, (name, rows) in enumerate(sheets.items()):
                if i:
                    w.writerow([])
                w.writerow(["# " + name])
                for row in rows:
                    w.writerow(safe(row))


def _xlsx_colref(ci):
    s = ""
    ci += 1
    while ci:
        ci, r = divmod(ci - 1, 26)
        s = chr(65 + r) + s
    return s


def write_xlsx(path, rep, status_key):
    """Minimal but valid .xlsx (OOXML) written with only the stdlib (zipfile + XML,
    inline strings). Readable by Excel and LibreOffice; no third-party dependency."""
    import zipfile
    from xml.sax.saxutils import escape
    sheets = _tabular_sheets(rep, status_key)

    def _xml_clean(s):
        # Strip control chars illegal in XML 1.0 (keep tab/newline/CR), which would
        # otherwise corrupt the workbook; latin-1-decoded banners can contain them.
        return "".join(c for c in s if c in "\t\n\r" or ord(c) >= 0x20)

    def cell(ci, ri, val):
        ref = _xlsx_colref(ci) + str(ri)
        if isinstance(val, bool):
            val = str(val)
        if isinstance(val, (int, float)):
            return '<c r="%s"><v>%s</v></c>' % (ref, val)
        txt = escape(_xml_clean("" if val is None else str(val)))
        return '<c r="%s" t="inlineStr"><is><t xml:space="preserve">%s</t></is></c>' % (ref, txt)

    sheet_parts = []
    for name, rows in sheets.items():
        body = []
        for ri, row in enumerate(rows, start=1):
            cells = "".join(cell(ci, ri, v) for ci, v in enumerate(row))
            body.append('<row r="%d">%s</row>' % (ri, cells))
        xml = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
               '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
               '<sheetData>%s</sheetData></worksheet>' % "".join(body))
        sheet_parts.append((name[:31], xml))

    sheets_tags = "".join(
        '<sheet name="%s" sheetId="%d" r:id="rId%d"/>' % (escape(n), i + 1, i + 1)
        for i, (n, _) in enumerate(sheet_parts))
    workbook = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
                'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
                '<sheets>%s</sheets></workbook>' % sheets_tags)
    wb_rels = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
               '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
               + "".join('<Relationship Id="rId%d" Type="http://schemas.openxmlformats.org/'
                         'officeDocument/2006/relationships/worksheet" Target="worksheets/sheet%d.xml"/>'
                         % (i + 1, i + 1) for i in range(len(sheet_parts)))
               + "</Relationships>")
    root_rels = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                 '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                 '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/'
                 '2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>')
    overrides = "".join('<Override PartName="/xl/worksheets/sheet%d.xml" ContentType='
                        '"application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
                        % (i + 1) for i in range(len(sheet_parts)))
    content_types = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                     '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                     '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.'
                     'relationships+xml"/><Default Extension="xml" ContentType="application/xml"/>'
                     '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-'
                     'officedocument.spreadsheetml.sheet.main+xml"/>%s</Types>' % overrides)
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", content_types)
        z.writestr("_rels/.rels", root_rels)
        z.writestr("xl/workbook.xml", workbook)
        z.writestr("xl/_rels/workbook.xml.rels", wb_rels)
        for i, (_n, xml) in enumerate(sheet_parts):
            z.writestr("xl/worksheets/sheet%d.xml" % (i + 1), xml)


def write_reports(args, thresholds, meta, status_key, agg, rows):
    if not (args.html or args.md or args.csv or args.xlsx):
        return
    rep = build_report_model(thresholds, meta, status_key, agg, rows)
    if args.md:
        with open(args.md, "w", encoding="utf-8") as fh:
            fh.write(render_markdown(rep))
        if not args.jsonl:
            print("Wrote Markdown report to %s" % args.md)
    if args.html:
        with open(args.html, "w", encoding="utf-8") as fh:
            fh.write(render_html(rep))
        if not args.jsonl:
            print("Wrote HTML report to %s" % args.html)
    if args.csv:
        write_csv(args.csv, rep, status_key)
        if not args.jsonl:
            print("Wrote CSV report to %s" % args.csv)
    if args.xlsx:
        write_xlsx(args.xlsx, rep, status_key)
        if not args.jsonl:
            print("Wrote XLSX report to %s" % args.xlsx)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        sys.exit(130)
