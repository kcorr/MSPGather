# syntax=docker/dockerfile:1
# Base image pinned by digest; Dependabot keeps it current.
FROM python:3.12-slim@sha256:a0f57064cbdcd6285fa45f51237ab0b35ea8ebaed06a1f5973e89e19dfb86704

ARG VERSION=dev
ARG REVISION=unknown
LABEL org.opencontainers.image.title="MSPGather" \
      org.opencontainers.image.description="Self-hosted troubleshooting and discovery toolkit for MSP engineers" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    MSPGATHER_REVISION=${REVISION} \
    MSPGATHER_DATA_DIR=/data

WORKDIR /srv
COPY requirements.txt .
RUN pip install --upgrade pip \
 && pip install --no-compile -r requirements.txt \
 && useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin mspgather \
 && mkdir -p /data && chown 10001:10001 /data && chmod 700 /data

# Application code is root-owned and read-only to the app user.
COPY app ./app

USER 10001:10001
VOLUME ["/data"]
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/api/health', timeout=4).status == 200 else 1)"
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080", \
     "--proxy-headers", "--no-server-header", "--timeout-graceful-shutdown", "10"]
