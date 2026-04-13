# QuantumShield API — Debian + Python + scanner toolchain (GCE / Cloud Run).
# Build: docker build -t quantumshield-api -f Backend/Dockerfile Backend

FROM golang:1.23-bookworm AS go-tools
ENV CGO_ENABLED=0
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
 && go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest \
 && go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest \
 && go install -v github.com/owasp-amass/amass/v4/cmd/amass@latest \
 && go install -v github.com/zmap/zgrab2/cmd/zgrab2@latest

FROM python:3.12-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl git dnsutils \
    nmap openssl sslscan \
    && rm -rf /var/lib/apt/lists/*

# testssl.sh (optional but improves TLS consensus)
RUN git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl.sh \
    && ln -sf /opt/testssl.sh/testssl.sh /usr/local/bin/testssl

COPY --from=go-tools /go/bin/subfinder /go/bin/dnsx /go/bin/httpx /go/bin/amass /go/bin/zgrab2 /usr/local/bin/

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

ENV PYTHONUNBUFFERED=1
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
  CMD curl -fsS http://127.0.0.1:8000/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
