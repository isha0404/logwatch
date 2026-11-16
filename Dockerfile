FROM python:3.12-slim

# Run as an unprivileged user: a log reader never needs root inside the container
RUN useradd --create-home --uid 10001 logwatch
WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir . && mkdir -p /data && chown logwatch /data

USER logwatch
ENTRYPOINT ["logwatch"]
CMD ["--help"]

# Example (log mounted read-only, state kept in a volume):
#   docker build -t logwatch .
#   docker run --rm -v /var/log/auth.log:/logs/auth.log:ro -v logwatch-state:/data \
#       logwatch scan /logs/auth.log --state /data/state.json
