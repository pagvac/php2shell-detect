# php2shell-detect

Multi-method remote **PHP version detector** with a headline **PHP2Shell triage mode**.
It infers the PHP version of web hosts using many signals — not just HTTP version
banners (which are frequently stripped) — and flags hosts exposed to **PHP2Shell**
(`CVE-2026-109618` / `CVE-2026-109619`).

> It's built to help engineers and security teams **quickly audit their estate** for
> PHP versions vulnerable to PHP2Shell — but it works as a general PHP version detector
> for any version, too.

**PHP2Shell** = two critical flaws (CVSS v4 **9.2**, unauthenticated RCE) fixed on
**2026-10-21** in **PHP 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35**. Exploitation has been
observed in the wild, and all older/EOL branches (8.1, 8.0, 7.x, 5.x …) are also
affected. **This tool performs detection only — it never sends the exploit.**

| Branch | Fixed (safe) version | Flagged `affected` when |
|--------|----------------------|-------------------------|
| PHP 8.5 | 8.5.12 | < 8.5.12 |
| PHP 8.4 | 8.4.27 | < 8.4.27 |
| PHP 8.3 | 8.3.36 | < 8.3.36 |
| PHP 8.2 | 8.2.35 | < 8.2.35 |
| ≤ 8.1 | — | EOL branch → always affected |

Thresholds live in [`thresholds.json`](thresholds.json); keep them current from
<https://www.php.net/supported-versions.php>.

## Requirements & install

Python **3.8+**, **standard library only** (`http.client`, `ssl`, `socket`, `ipaddress`,
`concurrent.futures`, `zipfile`/`csv` for reports). `packaging` is used for version
comparison if present, otherwise a built-in comparison is used.

The recommended way to run it is **no install at all** — copy the single file and run:

```bash
python3 php2shell_detect.py --help
```

Optional convenience installs (additive; the zero-dependency single-file stays primary):

```bash
# pipx / uv — gives you a `php2shell-detect` command
pipx install .          # or: uvx --from . php2shell-detect --help

# Docker — if you'd rather not manage a Python install
docker build -t php2shell-detect .
docker run --rm php2shell-detect example.com --php2shell --yes
# write reports to the host via a mount:
docker run --rm -v "$PWD/out:/out" php2shell-detect 10.0.0.0/24 \
    --php2shell --html /out/report.html --csv /out/report.csv --yes
```

## Quick start — find PHP2Shell-susceptible hosts

```bash
# A single host
python3 php2shell_detect.py example.com --php2shell --yes

# Your whole estate (CIDRs + a host list), 20 workers, only show the vulnerable ones,
# and write shareable HTML + Markdown + JSON reports
python3 php2shell_detect.py 10.0.0.0/24 192.0.2.0/27 -f estate.txt \
    --php2shell -w 20 --only-vuln \
    --html php2shell_report.html --md php2shell_report.md --json results.json --yes
```

`--php2shell` switches the verdict column to **affected / patched / suspect / n-a** and
makes the process exit **3** if any affected (or version-undisclosed "suspect") PHP host
is found — handy for CI gating.

Example output:

```
TARGET              IP               PHP        PHP2SHELL    SRC       DETAIL
--------------------------------------------------------------------------------
web1.corp.example   203.0.113.11     8.3.35     affected     headers   8.3.35 < 8.3.36 — vulnerable to CVE-2026-109618/…
api.corp.example    203.0.113.12     8.3.36     patched      headers   8.3.36 >= 8.3.36 — fixed
legacy.corp.example 203.0.113.40     7.4.33     affected     headers   7.4.33 is an EOL/unpatched branch — affected
cdn.corp.example    203.0.113.9      -          suspect      presence  PHP confirmed but version undisclosed — verify

Summary: 4 host(s) | affected=2, suspect=1, patched=1
```

## Targets

Any mix, as positionals, `-f FILE`, or (streaming) `--targets-from FILE`:

- single IP — `203.0.113.10`
- single domain — `example.com` (or `example.com:8443`)
- CIDR — `203.0.113.0/24`
- start-end IP range — `203.0.113.10-203.0.113.40` (or shorthand `203.0.113.10-40`)

**Ports:** with the default `--scheme auto` the tool probes **443 (https) then 80 (http)**.
Non-standard ports are used only when given on the target (`host:8443`). There is no
alt-port sweep.

## Detection methods

The scanner gathers independent *evidence* and picks the highest-confidence version,
keeping **"is this PHP?"** separate from **"what version?"**, and the **banner version**
separate from the **real patched level** (distro backporting).

| Method | Signal | Precision |
|--------|--------|-----------|
| `headers` | `X-Powered-By: PHP/x.y.z`, `Server: … PHP/x.y.z` on `GET /` | patch (authoritative) |
| `dummyphp` | request a random non-existent `*.php` and inspect the response — catches PHP (and version) when `/` is a static page but a `.php` request is routed through PHP (front-controller / nginx+PHP-FPM / custom PHP `ErrorDocument`) | patch / presence |
| `phpinfo` | `/phpinfo.php`, `/info.php`, … → version, Build Date, Zend, configure line | exact patch |
| `zend` | `Zend Engine v4.N.x` → PHP `8.N.x` (inside phpinfo) | patch (corroboration) |
| `exposed` | `composer.json`/`composer.lock`, Apache `server-status`/`server-info`, PHP-FPM `status`/`ping` | patch / floor |
| `easteregg` | `?=PHPE9568F34-…` logo GUID returns a PNG | proves PHP ≤ 5.4 (`--deep`) |
| `errorpage` | native `Fatal error`/`TypeError`/`ValueError` wording | major / minor floor |
| `presence` | `PHPSESSID`, `Expires: …1981…`, `X-Pingback`, `X-Redirect-By`, `wp-json` Link | PHP presence only |
| `distro` | `Server` OS token (Debian/Ubuntu/RHEL…) | branch guess + backport caveat |
| `cms` | WordPress/Laravel/Drupal/Joomla fingerprints | PHP minimum floor |
| `favicon` | `/favicon.ico` MurmurHash3 (Shodan `http.favicon.hash` compatible) | clustering only |
| `shodan` | optional passive host lookup (needs `--shodan-key`) | patch (third-party data) |

By default the active probes check a few common paths (`/phpinfo.php`, `/info.php`,
`/composer.json`) plus the random dummy `.php`; `--deep` adds the full path list and the
legacy easter-egg GUID, and `--no-active` disables all extra probing (baseline `GET /`
only).

**Invalid TLS certificates are trusted on purpose** (verification disabled for target
scanning) so broken, expired or self-signed certs never interfere with version
identification. Redirects are followed only within the same host / registrable domain —
off-target redirects (e.g. to cloud-metadata or third-party hosts) are not followed.

### Accuracy caveats

- **Distro backporting:** Debian/Ubuntu/RHEL freeze the upstream version string and
  backport fixes. A banner of `8.3.11` on Debian may already be patched. Such findings
  are annotated; treat major.minor as reliable and the patch digit as base-only there.
- **Patch precision** is only firm from phpinfo / banners / Sury-Remi builds.
- **Reverse proxies / CDNs** often strip PHP headers; the tool flags them.
- **Raw IPs:** reverse DNS is used to set the `Host` header for name-based vhosts.

## Internet-wide survey mode

For contributing an anonymized picture of PHP2Shell exposure to the community. It
streams (flat memory for any range size, incl. huge CIDRs), randomizes order, excludes
special-use ranges by default, shards, and rate-limits.

```bash
# Scan one /16, 100 conns/sec, shard 0 of 16, PHP2Shell focus,
# writing an anonymized aggregate report (no IPs) you can publish:
python3 php2shell_detect.py 198.51.100.0/16 \
    --survey --php2shell \
    --contact "security@yourorg.example" \
    --rate 100 --shard 0/16 \
    --exclude company-optout.txt \
    --survey-report php2shell_survey_shard0.json \
    --html php2shell_survey.html --yes
```

Survey mode **requires** `--contact` (advertised in the `User-Agent` so admins can reach
you and opt out) and an output sink. Built-in exclusions cover RFC 1918/5735/6598/5737/
3927 and multicast/reserved space; add your own opt-out list with `--exclude`.

**IP masking (census privacy):** in survey mode the last two octets of every IP are
masked (`203.0.113.45` → `203.0.x.x`) everywhere they could appear — `target`,
`resolved_ip`, `final_url`, error strings and evidence text — in both the streamed
output (`--jsonl`/`--json`) and the reports, and reverse-DNS names are dropped. So an
individual host can't be identified from a shared census (only the owning `/16` is
visible, which maps to an org via WHOIS — keep that in mind before publishing). The
`--survey-report` JSON holds aggregate counts (status tally, branch distribution, top
versions) **plus a list of masked IPs where PHP was found** (`hosts_with_php_masked`,
with version and PHP2Shell status). Pass `--no-mask-ips` only for your own private data
to keep full IPs.

> **Scan responsibly.** Keep `--rate` polite, spread work with `--shard`, honor opt-out
> requests promptly, and only survey space you are authorized to probe.

## Reports

Multiple formats can be written in one run; all are produced with the standard library
only (no third-party dependency):

- `--html FILE` — standalone styled HTML report (light/dark), summary + per-host table
  (or aggregate in survey mode).
- `--md FILE` — Markdown report.
- `--csv FILE` — CSV (per-host rows; aggregate tables in survey mode).
- `--xlsx FILE` — Excel workbook with `Summary`, `Status`, `Branches`, `Versions` and
  (per-host) `Hosts` sheets. Written directly as OOXML — opens in Excel/LibreOffice.
- `--json FILE` — full JSON (array), all evidence per host.
- `--jsonl` — stream one JSON object per host to stdout (pipeable to `jq`).

```bash
python3 php2shell_detect.py 10.0.0.0/24 --php2shell --yes \
    --html report.html --md report.md --csv report.csv --xlsx report.xlsx --json report.json
```

## Key options

| Option | Meaning |
|--------|---------|
| `--php2shell` | PHP2Shell triage view + exit 3 on any affected host |
| `-w, --workers N` | worker threads (**default 5**) |
| `-t, --timeout S` | per-request timeout (default 7s) |
| `--scheme auto\|http\|https` | scheme/port policy (default auto = 443 then 80) |
| `--deep` | probe full phpinfo/exposed-file paths + legacy easter-egg GUID |
| `--no-active` | baseline `GET /` only, no extra path probing |
| `--no-favicon` | skip favicon hashing |
| `--shodan-key KEY` | passive Shodan enrichment (or `SHODAN_API_KEY` env) |
| `--targets-from FILE` | stream targets (memory-light, for big lists) |
| `--survey` + `--contact` | internet-survey mode (see above) |
| `--shard i/n`, `--rate N`, `--exclude FILE`, `--seed N`, `--limit N` | survey controls |
| `--no-mask-ips` | keep full IPs in survey output (default masks last 2 octets) |
| `--html/--md/--csv/--xlsx/--json FILE` | report outputs (see Reports) |
| `--only-vuln` | show only vulnerable/affected hosts |
| `--yes` | acknowledge authorization (required non-interactively) |

Exit codes: **0** clean, **3** at least one vulnerable/affected host, **1/2** aborted/usage.

## Responsible & legal use

Only scan hosts you **own** or have **explicit written authorization** to test.
Unauthorized scanning may violate the US CFAA, the UK Computer Misuse Act, and
equivalents. The tool prints an authorization notice and requires confirmation (or
`--yes`). It is **detection only** and never attempts exploitation. See
[`AGENTS.md`](AGENTS.md) for contributor security rules (no hardcoded secrets; Semgrep
must be clean).

## Files

- `php2shell_detect.py` — the tool (single file, stdlib only).
- `thresholds.json` — editable safe-version table (with the PHP2Shell CVE metadata).
- `AGENTS.md` — contributor/agent security requirements.
- `Dockerfile` — optional container image.
- `pyproject.toml` — optional pipx/uv packaging.
- `LICENSE` — MIT.

## License

MIT © 2026 Adrian Pastor. See [`LICENSE`](LICENSE).
