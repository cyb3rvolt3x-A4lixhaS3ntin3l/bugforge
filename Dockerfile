# ── build stage: compile Go-based security tools ──────────────────────────
FROM golang:1.22-bookworm AS tool-builder

# Pre-install all Go-based security tools that BugForge orchestrates.
# This is the "zero-install" magic — users never run `go install` themselves.
RUN mkdir -p /tools/bin

ENV GOPATH=/go
ENV GOBIN=/tools/bin

RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -v github.com/owasp-amass/amass/v4/...@master && \
    go install github.com/tomnomnom/assetfinder@latest && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install github.com/ffuf/ffuf/v2@latest && \
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install github.com/hahwul/dalfox/v2@latest && \
    go install github.com/gitleaks/gitleaks/v8@latest && \
    go install github.com/trufflesecurity/trufflehog/v3@latest && \
    go install github.com/saeedddqbd/corsy@latest && \
    echo "All Go tools installed successfully"

# Download SecLists for ffuf wordlists (the 200K+ entries)
RUN apt-get update && apt-get install -y git && \
    git clone --depth 1 https://github.com/danielmiessler/SecLists.git /tools/seclists && \
    rm -rf /tools/seclists/.git

# ── runtime stage: Python + tools ──────────────────────────────────────────
FROM python:3.12-slim-bookworm

LABEL maintainer="BugForge Contributors"
LABEL description="BugForge v2.0 — Bug bounty orchestration platform with pre-installed tools"
LABEL version="2.0.0"

# Install system dependencies
# nmap: system package for port scanning
# nmap: used by the orchestrator's nmap tool definition
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    git \
    curl \
    dnsutils \
    && rm -rf /var/lib/apt/lists/*

# Copy pre-compiled Go tools from builder stage
COPY --from=tool-builder /tools/bin/ /usr/local/bin/

# Copy SecLists wordlists
COPY --from=tool-builder /tools/seclists/ /usr/share/seclists/

# Create symlink so the default ffuf wordlist path in registry.py works
RUN ln -sf /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
           /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt 2>/dev/null || true

# Install Python dependencies
WORKDIR /app
COPY requirements.txt setup.py ./
RUN pip install --no-cache-dir -r requirements.txt

# Install BugForge itself
COPY bugforge/ ./bugforge/
RUN pip install --no-cache-dir -e .

# Verify tools are available
RUN echo "=== Verifying installed tools ===" && \
    subfinder -version 2>&1 | head -1 && \
    httpx -version 2>&1 | head -1 && \
    ffuf -V 2>&1 | head -1 && \
    nuclei -version 2>&1 | head -1 && \
    dalfox version 2>&1 | head -1 && \
    gitleaks version 2>&1 | head -1 && \
    nmap --version 2>&1 | head -1 && \
    python3 -m bugforge --version && \
    echo "=== All tools verified ==="

# Nuclei templates download (run at build time for offline use)
RUN nuclei -update-templates 2>/dev/null || echo "Nuclei templates will download on first run"

# Expose the web UI port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -f http://localhost:8000/api/health || exit 1

# Run the BugForge web server
CMD ["python3", "-m", "bugforge", "serve", "--host", "0.0.0.0", "--port", "8000", "--no-browser"]
