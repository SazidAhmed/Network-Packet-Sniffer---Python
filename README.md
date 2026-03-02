# Network Packet Sniffer — Python

A raw-socket packet sniffer built entirely with the Python standard library (`socket`, `struct`). No Scapy, no Wireshark bindings — just pure Python.

## Project Structure

```
Sniffer/
├── capture.py          # Raw socket, single packet capture
├── ethernet.py         # Ethernet frame parsing (MAC, EtherType)
├── ip_parser.py        # IPv4 header parsing (TTL, Proto, IPs)
├── transport.py        # TCP/UDP header parsing (Ports, Seq, ACK)
├── sniffer.py          # Full combined sniffer with color + stats
├── Dockerfile          # Python 3.11-slim image, no pip installs
├── docker-compose.yml  # 5 named services, one per script
└── README.md           # This file
```

## Prerequisites

**Python 3.7+** — no pip installs required, all stdlib.

> **⚠️ Administrator/Root Required**
> Raw sockets bypass the OS networking stack and require elevated privileges.
>
> - **Windows**: Run PowerShell or CMD as **Administrator**
> - **Linux / macOS**: Use `sudo`
> - **Docker**: Use the compose services below — no admin needed on the host

---

## Running with Docker (Recommended)

Docker solves the privilege problem cleanly. The container runs on Linux (via WSL2 on Windows) and uses `AF_PACKET` raw sockets with Linux capabilities — no Windows Administrator required.

### How it works

| Setting              | Value            | Why                                                          |
| -------------------- | ---------------- | ------------------------------------------------------------ |
| `cap_add: NET_RAW`   | Linux capability | Allows creating `AF_PACKET` / `SOCK_RAW` sockets             |
| `cap_add: NET_ADMIN` | Linux capability | Allows enabling promiscuous mode                             |
| `network_mode: host` | Share host NIC   | Container sees real network traffic, not just bridge traffic |

> ⚠️ **Windows + Docker Desktop**: `network_mode: host` maps to the WSL2 VM's network, not the Windows NIC. To capture traffic, generate it from inside WSL2 (e.g. `ping 8.8.8.8` from a WSL2 terminal).

### Build

```bash
docker build -t packet-sniffer .
# or let compose build it automatically on first run
```

### Run each layer

```bash
docker compose run --rm capture      # Hex dump of one raw packet
docker compose run --rm ethernet     # MAC addresses + EtherType
docker compose run --rm ip           # IPv4 TTL, Protocol, IPs
docker compose run --rm transport    # TCP/UDP ports, Seq, ACK, Flags
docker compose run --rm sniffer      # Full sniffer (50 packets, all protocols)
```

### Custom sniffer args

```bash
docker compose run --rm sniffer python sniffer.py --proto tcp --count 20
docker compose run --rm sniffer python sniffer.py --proto icmp
docker compose run --rm sniffer python sniffer.py --proto udp --no-color
```

### Generate traffic while sniffing

Open a second terminal and run traffic inside the container's network:

```bash
# In terminal 1 — start the sniffer
docker compose run --rm sniffer

# In terminal 2 — generate traffic
docker compose run --rm sniffer ping -c 5 8.8.8.8
```

---

## Running Directly (Native Python)

### Windows (PowerShell as Administrator)

```powershell
cd H:\Python\Sniffer

python capture.py
python ethernet.py
python ip_parser.py
python transport.py
python sniffer.py
python sniffer.py --count 50
python sniffer.py --proto tcp
python sniffer.py --proto udp
python sniffer.py --proto icmp
python sniffer.py --no-color
```

### Linux / macOS

```bash
sudo python3 capture.py
sudo python3 transport.py
sudo python3 sniffer.py --proto tcp
```

> 💡 **Tip**: While a script is running, open another terminal and run `ping google.com` or browse the web to generate traffic.

---

## Architecture Concepts

### Why Admin/Root Privileges?

| Socket Type         | Privilege Needed | What You Can See              |
| ------------------- | ---------------- | ----------------------------- |
| `SOCK_STREAM` (TCP) | None             | Your app's data only          |
| `SOCK_DGRAM` (UDP)  | None             | Your app's data only          |
| `SOCK_RAW`          | **Root/Admin**   | Raw IP packets, all traffic   |
| `AF_PACKET` (Linux) | **Root/Admin**   | Raw Ethernet frames (layer 2) |

### The "Russian Doll" Encapsulation Model

```
Ethernet Frame [14 bytes header]
└── IPv4 Packet [20+ bytes header]
    └── TCP/UDP Segment [20/8 bytes header]
        └── Application Data (HTTP, DNS, etc.)
```

Each layer wraps the one above it. Parsing requires peeling each layer off in order.

### Endianness & Network Byte Order

Network protocols use **Big Endian** (Most Significant Byte first). x86 CPUs use **Little Endian**. The `!` prefix in Python's `struct` format strings handles this conversion automatically:

```python
struct.unpack('!H', b'\x08\x00')  # → (2048,) = 0x0800 = IPv4
struct.unpack('<H', b'\x08\x00')  # → (8,)    = wrong! (little-endian interpretation)
```

### Bitwise Nibble Extraction

The IP version and header length are packed into a **single byte**:

```
Byte 0x45 = 0100 0101
             ^^^^      Version = 0x4 = 4 (IPv4)   → byte >> 4
                  ^^^^ IHL     = 0x5 = 5 × 4 = 20 bytes → byte & 0x0F
```

Same trick applies to the TCP Data Offset field.

### TCP Flags

```
Bit: 7    6    5    4    3    2    1    0
     CWR  ECE  URG  ACK  PSH  RST  SYN  FIN
```

Extract with bitwise AND: `flags & 0x02` is nonzero if SYN is set.

### Common IP Protocol Numbers

| Number | Name | Use                    |
| ------ | ---- | ---------------------- |
| 1      | ICMP | `ping`, error messages |
| 6      | TCP  | HTTP, HTTPS, SSH, etc. |
| 17     | UDP  | DNS, DHCP, streaming   |
| 89     | OSPF | Routing protocols      |

### Common Port Numbers

| Port | Service |
| ---- | ------- |
| 22   | SSH     |
| 53   | DNS     |
| 80   | HTTP    |
| 443  | HTTPS   |
| 3306 | MySQL   |

---

## Platform Notes

| Feature                 | Windows            | Linux                      |
| ----------------------- | ------------------ | -------------------------- |
| Ethernet header visible | ❌ No              | ✅ Yes (`AF_PACKET`)       |
| Promiscuous mode        | `SIO_RCVALL` ioctl | Automatic with `AF_PACKET` |
| Socket family           | `AF_INET`          | `AF_PACKET`                |
| Captured from layer     | Layer 3 (IP)       | Layer 2 (Ethernet)         |

On Windows, raw sockets deliver packets starting at the IP layer — the Ethernet header is not exposed. The step scripts simulate a placeholder Ethernet layer on Windows for consistent output.
