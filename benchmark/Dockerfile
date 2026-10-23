# Benchmark host for php2shell-detect.
#
# A real PHP process (the built-in web server) driven by a single router.php. The
# BENCH_PROFILE env var selects which *detection method* the fixture exercises — a
# version banner, phpinfo, an exposed composer.json, a dummy-.php route, a CMS
# fingerprint, or a presence-only host — so the benchmark covers more than header
# parsing. Runs as the unprivileged www-data user on a non-privileged port. Test
# scaffolding only: it never runs the exploit and serves trivial pages.
FROM php:8.3-cli

COPY router.php /app/router.php

USER www-data
WORKDIR /app
EXPOSE 8080

# expose_php=0 so the only version signal is the one each profile plants (see router.php).
ENTRYPOINT ["php", "-d", "expose_php=0", "-S", "0.0.0.0:8080", "router.php"]
