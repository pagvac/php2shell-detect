# php2shell-detect benchmark

A reproducible, Docker-based benchmark that proves `php2shell_detect.py` still detects
PHP versions and reaches the correct **PHP2Shell** verdicts **across multiple detection
methods** — not just the `X-Powered-By` banner. It is the pre-push regression gate for
this repo (see [`../AGENTS.md`](../AGENTS.md)).

## Why it exists

The detector gathers independent evidence (headers, phpinfo, exposed files, dummy-`.php`
routing, CMS fingerprints, presence signals, …) and picks the highest-confidence
version. A benchmark that only set a version banner would exercise exactly one of those
paths. This harness therefore stands up a **separate fixture per detection method**, so a
regression in any single method is caught.

## Requirements

- Docker + the `docker compose` plugin.
- Ports `127.0.0.1:18131`–`18139` free (bound to loopback only).
- No network access to third parties: every target is a local container. The fixtures
  are **detection-only** scaffolding — they serve trivial pages and never run any exploit.

## How to run

```bash
python3 benchmark/run_benchmark.py        # build, scan, assert, tear down
./benchmark/run.sh                        # same thing
python3 benchmark/run_benchmark.py --keep # leave containers up for debugging
```

Exit code **0 = PASS**, non-zero = FAIL (each failed assertion is printed). Fixtures are
always torn down (`docker compose down -v`) unless `--keep` is given.

## Methodology

Each service in [`docker-compose.yml`](docker-compose.yml) is the *same* image
(`Dockerfile`: PHP's built-in server running as non-root) parameterised by
`BENCH_PROFILE`, which [`router.php`](router.php) reads to plant exactly one method's
signal. `expose_php` is disabled, so nothing leaks a version unless a profile sets one
deliberately — the method under test is the *only* version signal.

| Port  | Profile    | Signal planted                                   | Method asserted | Expected verdict |
|-------|------------|--------------------------------------------------|-----------------|------------------|
| 18131 | `banner`   | `X-Powered-By: PHP/8.3.35`                       | `headers`       | affected / vulnerable |
| 18132 | `banner`   | `X-Powered-By: PHP/8.3.36`                       | `headers`       | patched / ok |
| 18133 | `banner`   | `X-Powered-By: PHP/7.4.33`                       | `headers`       | affected / eol |
| 18134 | `banner`   | `X-Powered-By: PHP/8.4.27`                       | `headers`       | patched / ok |
| 18135 | `suspect`  | `PHPSESSID` cookie, no version                   | presence (none) | suspect / unknown |
| 18136 | `phpinfo`  | real `phpinfo()` page                            | `phpinfo`       | branch 8.3 (verdict follows image) |
| 18137 | `dummyphp` | static `/`, missing `*.php` routed to PHP        | `dummyphp`      | branch 8.3 (verdict follows image) |
| 18138 | `composer` | `/composer.json` `require.php = 8.3.35`          | `exposed`       | affected / vulnerable |
| 18139 | `cms`      | WordPress `generator` tag → PHP ≥ 7.2 floor      | `cms`           | affected / eol |

### What the runner asserts (`run_benchmark.py`)

1. **Per-host detection method** — `php_version_source` equals the method the fixture is
   designed to exercise (e.g. port 18138 must be found via `exposed`, not a banner). This
   is what guarantees coverage beyond header parsing.
2. **Verdicts** — the default-mode `status` (vulnerable/ok/eol/unknown) and the
   `--php2shell` triage status (affected/patched/suspect) match the table above.
3. **Version precision** — exact version for banner/composer cases; `major.minor` for the
   `phpinfo`/`dummyphp` cases, which read the base image's **real** patch level (so the
   benchmark survives base-image bumps). No vulnerable host is ever reported "patched".
4. **Default-mode PHP2Shell reporting** — every host the tool marks `affected` is flagged
   as `PHP2Shell-vulnerable` in its detail **without** `--php2shell`, and the default-mode
   summary reports the correct affected count.
5. **Exit codes** — both default and `--php2shell` runs exit **3** when affected/vulnerable
   hosts are present (CI gating).
6. **Survey-report masking (in-process, no Docker)** — `check_survey_report_masking()`
   drives the census report path the way `main()` does (`mask_record` → `_slim_row` →
   render) and asserts the HTML/MD/CSV survey report lists PHP-positive/flagged hosts as a
   per-host table, that their IPs are shown only as a `/16` prefix (`203.0.x.x`), that **no
   full four-octet host IP** appears in any report, and that `--no-mask-ips` labels the
   report as *not* anonymized. Survey mode excludes loopback/reserved space so it cannot
   reach the Docker fixtures, which is why this path is covered in-process.

## Extending the benchmark

- **New PHP release / threshold change:** update `thresholds.json`, then adjust the
  boundary fixtures/expectations here so a just-patched and a just-vulnerable version are
  both represented.
- **New detection method** in `php2shell_detect.py`: add a `BENCH_PROFILE` case in
  `router.php` that plants only that method's signal, a service + free loopback port in
  `docker-compose.yml`, and an `EXPECTED` entry asserting `source` is the new method.
- Keep assertions **robust to base-image updates**: assert the method and branch, and pin
  an exact patch only where the fixture itself sets it (banner/composer).
- **Report/masking change** (new survey report format, new masked field, changed row
  filter): update `check_survey_report_masking()` so it still proves no full IP can reach
  a shareable report.

> Run this benchmark and confirm **PASS** before pushing any commit (alongside the Semgrep
> and gitleaks gates in [`../AGENTS.md`](../AGENTS.md)).
