# syntax=docker/dockerfile:1
FROM python:3.12-slim-bookworm AS build
WORKDIR /src
COPY pyproject.toml requirements.txt README.md LICENSE ./
COPY blackarch2kali ./blackarch2kali
RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-cache-dir -r requirements.txt \
 && /opt/venv/bin/pip install --no-cache-dir --no-deps .

FROM python:3.12-slim-bookworm
ENV PATH="/opt/venv/bin:$PATH" PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
RUN useradd --system --uid 10001 --create-home --home-dir /home/ba2k ba2k \
 && mkdir -p /data /app && chown ba2k:ba2k /data
COPY --from=build /opt/venv /opt/venv
COPY --chown=root:root config /app/config
WORKDIR /data
USER 10001:10001
VOLUME ["/data"]
HEALTHCHECK --interval=60s --timeout=15s --start-period=10s --retries=3 CMD ["blackarch2kali", "--config-dir", "/app/config", "health"]
# Metadata analysis only. The container never installs or runs security tools.
ENTRYPOINT ["blackarch2kali", "--config-dir", "/app/config"]
CMD ["--help"]
