<!-- php2shell-detect PR checklist. CI runs compile+import, ruff, Semgrep, gitleaks,
     and the Docker benchmark automatically. The two-agent review is manual (see AGENTS.md). -->

## What & why



## Pre-merge checklist (see [AGENTS.md](../AGENTS.md))

- [ ] No secrets in the diff (keys/tokens/passwords); Shodan key stays env/flag only.
- [ ] Tool remains **detection-only**; authorization gate and survey IP-masking intact.
- [ ] `README.md` updated to match any user-visible change.
- [ ] CI green: compile/import (3.8–3.13), ruff, **Semgrep 0 MEDIUM+**, gitleaks, **benchmark PASS**.
- [ ] Benchmark fixtures/expectations cover the change (new detection method → new `BENCH_PROFILE` + assertion; threshold bump → refreshed boundary fixtures). See `benchmark/README.md`.
- [ ] **Two-agent review** complete — QA (correctness) **and** ProdSec (no introduced vulns) signed off with no CRITICAL/HIGH/MEDIUM (not covered by CI).
