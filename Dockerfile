# ─────────────────────────────────────────────────────────────
#  Network Packet Sniffer — Dockerfile
#  Uses Python slim on Linux, so AF_PACKET raw sockets work.
#
#  Build:
#    docker build -t sniffer .
#
#  Run (requires NET_RAW + NET_ADMIN capabilities + host network):
#    docker run --rm --cap-add=NET_RAW --cap-add=NET_ADMIN \
#               --network=host sniffer
#
#  Or use docker compose:
#    docker compose run --rm sniffer
#    docker compose run --rm sniffer python ethernet.py
# ─────────────────────────────────────────────────────────────

FROM python:3.11-slim

# Install ping and curl so we can generate traffic from inside the container
RUN apt-get update && apt-get install -y --no-install-recommends \
    iputils-ping \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Set working directory inside the container
WORKDIR /app

# Copy all sniffer scripts into the container
COPY capture.py    .
COPY ethernet.py   .
COPY ip_parser.py  .
COPY transport.py  .
COPY sniffer.py    .

# No pip installs needed — pure stdlib only!

# Default command: run the full combined sniffer
# Override via: docker compose run sniffer python transport.py
CMD ["python", "sniffer.py", "--count", "50"]
