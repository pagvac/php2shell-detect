# AGENTS.md

Guidance for AI coding agents (and humans) working in this repository.

## Security requirements (MUST)

1. **No hardcoded secrets.** Never commit or inline secrets of any kind: API keys,
   tokens, passwords, private keys, session cookies, connection strings, or
   credentials. This explicitly includes the Shodan API key — it is only ever read
   at runtime from the `--shodan-key` flag or the `SHODAN_API_KEY` environment
   variable, never stored in source, config, or tests. Do not add example keys that
   look real; use obvious placeholders like `YOUR_API_KEY` or `x@y.z`.
   - Load secrets from environment variables or CLI flags only.
   - Do not write secrets to logs, reports, committed JSON output, or the README.
   - The anonymized aggregate survey report (`--survey-report`) must never contain IP
     addresses or credentials. Other survey outputs (`--jsonl`, `--json`, `--html`,
     `--md`, `--csv`, `--xlsx`) may include host IPs **only as a /16 prefix** — the last
     two octets redacted (e.g. `203.0.x.x`) — which is the default census masking. A full
     four-octet IP must never appear in any report by default; it is emitted only when the
     operator explicitly passes `--no-mask-ips`, which produces a non-anonymized report
     that must not be shared (the report labels itself as such).

2. **Static analysis must be clean.** Before considering a change complete, run
   Semgrep and ensure there are **no findings at MEDIUM, HIGH, or CRITICAL severity**:

   ```bash
   semgrep --config=auto --error --severity ERROR --severity WARNING .
   ```

   (Semgrep maps CRITICAL/HIGH/MEDIUM to `ERROR`/`WARNING`; `--error` makes the run
   exit non-zero if any are found.) Low/INFO findings should be reviewed but do not
   block. Keep the repo at zero MEDIUM+ findings.

3. **Detection only — never weaponize.** This project fingerprints PHP versions and
   flags hosts exposed to CVE-2026-109618 / CVE-2026-109619 ("PHP2Shell"). It must
   **never** send the exploit or any payload that could execute code on a target.
   PHP2Shell exposure is determined purely by comparing the detected version against
   the fixed releases. Do not add exploitation, brute-forcing, or DoS behavior.

4. **Scan only with authorization.** Keep the authorization gate and the survey-mode
   opt-out/`--contact` requirements intact. Do not weaken or bypass them.

## Pre-push review (MUST)

6. **Every change must be reviewed by TWO independent agents before it is pushed to any
   remote.** This is in addition to — not a replacement for — the Semgrep gate
   (requirement #2: zero MEDIUM/HIGH/CRITICAL findings). Run both as separate agents,
   give each the diff and the project context, and resolve everything they raise before
   pushing:
   - **Agent A — QA reviewer:** verifies correctness and behavior — version/verdict logic
     (no false "patched"/"ok" on a vulnerable host), target expansion, report formats,
     exit codes, and that behavior matches the README. Confirms tests/benchmarks pass and
     no regressions.
   - **Agent B — Product Security (ProdSec) engineer:** reviews specifically for *newly
     introduced vulnerabilities* — injection (incl. CSV/formula and XML/XLSX), SSRF and
     redirect handling, secret leakage (esp. the Shodan key and the census IP masking),
     TLS/verification choices, path traversal, unsafe parsing/deserialization, and
     DoS/resource-exhaustion. Must confirm the tool stays detection-only.

   Both agents must sign off with no unresolved CRITICAL/HIGH/MEDIUM issues. Record what
   was reviewed. Do not push until both have passed.

## Pre-push verification (MUST)

7. **Run the Docker benchmark and confirm it PASSES before every push.** The benchmark
   (`python3 benchmark/run_benchmark.py`, or `./benchmark/run.sh`) stands up local PHP
   fixtures and asserts the detector's version/verdict logic **across multiple detection
   methods** — not just the version banner. Its methodology (one fixture per detection
   method, the port/profile/verdict matrix, and what each run asserts) is documented in
   [`benchmark/README.md`](benchmark/README.md) and MUST be followed and kept current:
   - A change to detection, verdict/threshold, version-parsing, report, or exit-code
     behavior is not complete until the benchmark passes **and** its fixtures/expectations
     cover the change (e.g. a new detection method gets a new `BENCH_PROFILE` + assertion;
     a threshold bump gets refreshed boundary fixtures).
   - Requires Docker + the compose plugin. Record a PASS before pushing. Exit code 0 = PASS.

8. **Run a CLEAN gitleaks scan before every push.** Run `gitleaks` and confirm it reports
   **no leaks** before pushing:

   ```bash
   gitleaks detect --no-banner --redact            # scans committed history
   gitleaks protect --no-banner --redact --staged  # scans staged changes pre-commit
   ```

   This is in addition to — not a replacement for — the Semgrep gate (#2) and the manual
   "no secrets in the diff" check. Any finding blocks the push until resolved (remove the
   secret and rotate it; never commit a real key — see requirement #1). A false positive
   must be allowlisted explicitly in a committed `.gitleaks.toml`, not ignored silently.

## Project conventions

- **Standard library only** for the core tool (`php2shell_detect.py`). `packaging`
  is an optional enhancement with a built-in fallback. Do not add hard third-party
  dependencies without discussion.
- Keep the vulnerability thresholds in `thresholds.json` (data, not code) so they can
  be updated as PHP ships new patch releases.
- Preserve the separation between "is this PHP?" and "what version?", and between a
  banner version and the real patched level (distro backporting).

## Documentation (MUST)

5. **Always update `README.md` after making code changes** (when applicable). New or
   changed flags, output formats, detection methods, defaults, or behavior must be
   reflected in the README in the same change. A code change that alters how the tool
   is used is not complete until the README matches.

## Checklist before done

- [ ] No secrets in the diff (`git diff` reviewed; no keys/tokens/passwords).
- [ ] `python3 -m py_compile php2shell_detect.py` passes.
- [ ] `semgrep --config=auto` reports **0** MEDIUM/HIGH/CRITICAL findings.
- [ ] Tool still runs detection-only; authorization gate intact.
- [ ] `README.md` updated to match any user-visible change.
- [ ] **Before push:** `benchmark/run_benchmark.py` PASSES, and its fixtures/expectations
      cover the change (see `benchmark/README.md`).
- [ ] **Before push:** gitleaks scan is CLEAN (`gitleaks detect` and, pre-commit,
      `gitleaks protect --staged`).
- [ ] **Before push:** two-agent review complete — QA reviewer (correctness) **and**
      ProdSec engineer (no introduced vulns) both signed off with no CRIT/HIGH/MED issues.
