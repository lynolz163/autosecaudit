FROM python:3.11-slim

ARG INSTALL_NUCLEI=0
ARG NUCLEI_VERSION=3.3.10
ARG INSTALL_PLAYWRIGHT=0
ARG INSTALL_PLAYWRIGHT_BROWSER=0

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    DEBIAN_FRONTEND=noninteractive \
    PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        git \
        nmap \
        unzip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy source with local package metadata first for better layer caching.
COPY pyproject.toml README.md /app/
COPY autosecaudit /app/autosecaudit

RUN python -m pip install --upgrade pip setuptools wheel \
    && python -m pip install /app \
    && python -m pip install requests aiohttp openai

# Optional Playwright Python package (lightweight compared to browser payload).
RUN if [ "${INSTALL_PLAYWRIGHT}" = "1" ]; then \
      python -m pip install playwright; \
    fi

# Optional Playwright browser payload (memory heavy). Keep disabled by default.
RUN if [ "${INSTALL_PLAYWRIGHT_BROWSER}" = "1" ]; then \
      python -m pip install playwright && python -m playwright install chromium; \
    fi

# Install dirsearch from official repository (tool wrapper also supports /opt/dirsearch fallback path).
RUN git clone --depth=1 https://github.com/maurosoria/dirsearch.git /opt/dirsearch \
    && python -m pip install -r /opt/dirsearch/requirements.txt

# Optional nuclei installation for the existing nuclei_exploit_check tool.
RUN if [ "${INSTALL_NUCLEI}" = "1" ]; then \
      set -eux; \
      arch="$(dpkg --print-architecture)"; \
      case "${arch}" in \
        amd64) nuclei_arch="amd64" ;; \
        arm64) nuclei_arch="arm64" ;; \
        *) echo "Unsupported architecture for nuclei: ${arch}" >&2; exit 1 ;; \
      esac; \
      curl -fsSL -o /tmp/nuclei.zip "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${nuclei_arch}.zip"; \
      unzip -q /tmp/nuclei.zip -d /usr/local/bin; \
      chmod +x /usr/local/bin/nuclei; \
      rm -f /tmp/nuclei.zip; \
    fi

RUN useradd --create-home --shell /bin/bash autosec \
    && mkdir -p /workspace/output /workspace/config /workspace/wordlists \
    && chown -R autosec:autosec /workspace /opt/dirsearch

USER autosec
WORKDIR /workspace

VOLUME ["/workspace/output", "/workspace/config"]

# `python -m autosecaudit` supports both:
# - `init` subcommand
# - legacy CLI args (delegated to autosecaudit.cli)
ENTRYPOINT ["python", "-m", "autosecaudit"]
CMD ["--help"]
