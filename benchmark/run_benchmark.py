#!/usr/bin/env python3
"""End-to-end benchmark for php2shell-detect.

Spins up the Docker fixtures in docker-compose.yml (PHP hosts advertising known
versions), runs the real CLI against them, and asserts the detector's verdicts in
both the default (version) view and --php2shell triage view:

  * every version's PHP2Shell status (affected / patched / suspect),
  * the default-mode status taxonomy (vulnerable / ok / eol / unknown),
  * that PHP2Shell-vulnerable hosts are surfaced even WITHOUT --php2shell,
  * and the CI gating exit code (3 when any affected host is found).

Standard library only. Requires Docker + the compose plugin. Exit 0 = PASS, 1 = FAIL.

Usage:
    python3 benchmark/run_benchmark.py [--keep]
"""
import http.client
import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(os.path.dirname(HERE), "php2shell_detect.py")

# target -> expected outcome. Keys are checked only when present:
#   status   : default-mode status taxonomy (vulnerable/ok/eol/unknown)
#   php2shell: PHP2Shell triage verdict (affected/patched/suspect)
#   source   : php_version_source — the detection METHOD that won (proves that method
#              works, not just header parsing); None means "no version disclosed"
#   version  : exact detected version (banner/composer cases)
#   branch   : major.minor only (phpinfo/dummyphp read the image's real patch level)
EXPECTED = {
    # method: headers — exact version boundary cases
    "127.0.0.1:18131": {"status": "vulnerable", "php2shell": "affected",
                        "source": "headers", "version": "8.3.35"},
    "127.0.0.1:18132": {"status": "ok", "php2shell": "patched",
                        "source": "headers", "version": "8.3.36"},
    "127.0.0.1:18133": {"status": "eol", "php2shell": "affected",
                        "source": "headers", "version": "7.4.33"},
    "127.0.0.1:18134": {"status": "ok", "php2shell": "patched",
                        "source": "headers", "version": "8.4.27"},
    # other detection methods
    "127.0.0.1:18135": {"status": "unknown", "php2shell": "suspect", "source": None},
    # phpinfo/dummyphp read the image's REAL patch level, so we assert the method and
    # branch (robust to base-image bumps), not a fixed verdict.
    "127.0.0.1:18136": {"source": "phpinfo", "branch": "8.3"},
    "127.0.0.1:18137": {"source": "dummyphp", "branch": "8.3"},
    "127.0.0.1:18138": {"status": "vulnerable", "php2shell": "affected",
                        "source": "exposed", "version": "8.3.35"},
    "127.0.0.1:18139": {"status": "eol", "php2shell": "affected",
                        "source": "cms", "version": "7.2"},
}
TARGETS = list(EXPECTED)


def run(cmd, **kw):
    return subprocess.run(cmd, cwd=HERE, text=True, capture_output=True, **kw)


def compose(*args):
    return run(["docker", "compose", *args])


def _http_ok(target):
    """True if the local fixture answers HTTP. Uses http.client against a fixed
    127.0.0.1 host:port (no dynamic URL)."""
    host, _, port = target.partition(":")
    conn = http.client.HTTPConnection(host, int(port or 80), timeout=2)
    try:
        conn.request("GET", "/")
        conn.getresponse().read(1)
        return True
    except Exception:
        return False
    finally:
        conn.close()


def wait_ready(timeout=120):
    deadline = time.time() + timeout
    pending = set(TARGETS)
    while pending and time.time() < deadline:
        for tgt in list(pending):
            if _http_ok(tgt):
                pending.discard(tgt)
        if pending:
            time.sleep(1.5)
    return pending


def scan(php2shell):
    """Run the CLI, return (exit_code, stdout, records-by-target)."""
    out = os.path.join(HERE, "_bench_out.json")
    cmd = [sys.executable, TOOL, *TARGETS,
           "--scheme", "http", "--no-progress", "--no-color",
           "--json", out, "--yes"]
    if php2shell:
        cmd.append("--php2shell")
    proc = run(cmd)
    recs = {}
    try:
        with open(out, encoding="utf-8") as fh:
            for rec in json.load(fh):
                recs[rec.get("target")] = rec
    finally:
        if os.path.exists(out):
            os.remove(out)
    return proc.returncode, (proc.stdout or ""), recs


def main():
    keep = "--keep" in sys.argv[1:]
    failures = []
    try:
        print("[*] Building and starting benchmark fixtures ...")
        up = compose("up", "-d", "--build")
        if up.returncode != 0:
            print(up.stdout)
            print(up.stderr, file=sys.stderr)
            print("FAIL: docker compose up failed")
            return 1

        print("[*] Waiting for fixtures to answer HTTP ...")
        pending = wait_ready()
        if pending:
            print("FAIL: fixtures never became ready: %s" % ", ".join(sorted(pending)))
            return 1

        # --- default (version) mode: JSON verdicts + methods + Change-1 reporting ---
        print("[*] Scan 1/2: default mode")
        rc0, out0, recs0 = scan(php2shell=False)
        for tgt, exp in EXPECTED.items():
            rec = recs0.get(tgt)
            if not rec:
                failures.append("%s: missing from results" % tgt)
                continue
            if "status" in exp and rec.get("status") != exp["status"]:
                failures.append("%s: status %r, expected %r" % (tgt, rec.get("status"), exp["status"]))
            if "php2shell" in exp and rec.get("php2shell") != exp["php2shell"]:
                failures.append("%s: php2shell %r, expected %r" % (tgt, rec.get("php2shell"), exp["php2shell"]))
            if "source" in exp and rec.get("php_version_source") != exp["source"]:
                failures.append("%s: detection method %r, expected %r"
                                % (tgt, rec.get("php_version_source"), exp["source"]))
            if "version" in exp and rec.get("php_version") != exp["version"]:
                failures.append("%s: version %r, expected %r" % (tgt, rec.get("php_version"), exp["version"]))
            if "branch" in exp:
                got = ".".join((rec.get("php_version") or "").split(".")[:2])
                if got != exp["branch"]:
                    failures.append("%s: branch %r, expected %r (version %r)"
                                    % (tgt, got, exp["branch"], rec.get("php_version")))
        # Change 1: EVERY affected host must be surfaced in default-mode output (no flag),
        # regardless of which detection method found it.
        for tgt, rec in recs0.items():
            if rec.get("php2shell") == "affected" and "PHP2Shell-vulnerable" not in (rec.get("detail") or ""):
                failures.append("%s: default-mode detail does not flag PHP2Shell: %r"
                                % (tgt, rec.get("detail")))
        n_aff = sum(1 for r in recs0.values() if r.get("php2shell") == "affected")
        if n_aff == 0:
            failures.append("expected at least one affected host in default mode, found none")
        elif ("PHP2Shell" not in out0) or ("%d affected" % n_aff not in out0):
            failures.append("default-mode summary did not report %d PHP2Shell-affected host(s)" % n_aff)
        # Default mode also gates: exit 3 when any vulnerable/eol host is present.
        if rc0 != 3:
            failures.append("default-mode exit code %d, expected 3 (vulnerable/eol hosts present)" % rc0)

        # --- triage (--php2shell) mode: verdicts + exit 3 gating ---
        print("[*] Scan 2/2: --php2shell mode")
        rc1, _out1, recs1 = scan(php2shell=True)
        for tgt, exp in EXPECTED.items():
            rec = recs1.get(tgt)
            if rec and "php2shell" in exp and rec.get("php2shell") != exp["php2shell"]:
                failures.append("[--php2shell] %s: php2shell %r, expected %r"
                                % (tgt, rec.get("php2shell"), exp["php2shell"]))
        if rc1 != 3:
            failures.append("--php2shell exit code %d, expected 3 (affected hosts present)" % rc1)
    finally:
        if keep:
            print("[*] --keep set; leaving fixtures running (docker compose down to stop).")
        else:
            print("[*] Tearing down fixtures ...")
            compose("down", "-v")

    print("-" * 60)
    if failures:
        print("BENCHMARK FAILED (%d issue(s)):" % len(failures))
        for f in failures:
            print("  - %s" % f)
        return 1
    print("BENCHMARK PASSED: %d hosts, verdicts and exit codes correct." % len(EXPECTED))
    return 0


if __name__ == "__main__":
    sys.exit(main())
