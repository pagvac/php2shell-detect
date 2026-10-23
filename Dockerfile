# Optional container image for php2shell-detect.
# The tool is a single stdlib-only Python file and needs NO container to run
# (`python3 php2shell_detect.py ...`). This image is a convenience for users who
# prefer not to manage a Python install.
#
#   docker build -t php2shell-detect .
#   docker run --rm php2shell-detect example.com --php2shell --yes
#
# To write reports to the host, mount a directory and point --html/--csv/... at it:
#   docker run --rm -v "$PWD/out:/out" php2shell-detect 10.0.0.0/24 \
#       --php2shell --html /out/report.html --csv /out/report.csv --yes
FROM python:3.12-slim

# No third-party dependencies are required. `packaging` is an optional enhancement
# (the tool has a stdlib fallback); install it so PEP 440 comparison is used.
RUN pip install --no-cache-dir "packaging>=21.0"

WORKDIR /app
COPY php2shell_detect.py thresholds.json ./

# Run as a non-root user.
RUN useradd --create-home --uid 10001 scanner
USER scanner

ENTRYPOINT ["python3", "/app/php2shell_detect.py"]
CMD ["--help"]
