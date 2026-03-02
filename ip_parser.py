"""
=============================================================
  ip_parser.py — Unpacking the IP Header
  Network Packet Sniffer - Python Raw Sockets
=============================================================

ARCHITECTURE OVERVIEW: PACKET ENCAPSULATION ("RUSSIAN DOLL" MODEL)
--------------------------------------------------------------------
Network protocols are layered — each layer wraps the layer above it:

  ┌─── Ethernet Frame ───────────────────────────────────────────┐
  │ Ethernet Header (14B) │                                      │
  │                       │  ┌─── IP Packet ──────────────────┐  │
  │                       │  │ IP Header (20-60B) │           │  │
  │                       │  │                    │ TCP/UDP   │  │
  │                       │  │                    │ Payload   │  │
  │                       │  └────────────────────────────────┘  │
  └──────────────────────────────────────────────────────────────┘

Like Russian dolls, each outer layer has no knowledge of what's inside.
IP doesn't know if the payload is TCP, UDP, or a custom protocol.
It just delivers the "doll" to the next layer.

IPv4 HEADER STRUCTURE (minimum 20 bytes):
------------------------------------------
 Offset  Size  Field
    0     1B   Version (4-bit) + IHL (4-bit)  ← packed into one byte!
    1     1B   DSCP/ECN (Type of Service)
    2     2B   Total Length
    4     2B   Identification
    6     2B   Flags + Fragment Offset
    8     1B   Time To Live (TTL)
    9     1B   Protocol  (6=TCP, 17=UDP, 1=ICMP)
   10     2B   Header Checksum
   12     4B   Source IP Address
   16     4B   Destination IP Address
  [20+]       Options (if IHL > 5)

BITWISE OPERATIONS — EXTRACTING NIBBLES:
-----------------------------------------
The first byte of the IP header packs TWO 4-bit values (nibbles):
  Byte value example: 0x45
    In binary:         0100 0101
    Upper nibble:      0100      = 4 → IP Version 4
    Lower nibble:           0101 = 5 → IHL = 5 (meaning 5 × 4 = 20 bytes header)

To extract upper nibble (version): byte >> 4
  0x45 >> 4 = 0x04 = 4 ✓

To extract lower nibble (IHL): byte & 0x0F
  0x45 & 0x0F = 0x05 = 5 ✓
  (0x0F in binary = 0000 1111 — masks out the upper nibble)

IHL (Internet Header Length) is in units of 32-bit words (4 bytes), so:
  actual_header_bytes = IHL × 4
  IHL=5 → 20 bytes (the minimum, no IP options)
  IHL=6 → 24 bytes (4 bytes of IP options present)

IP PROTOCOL NUMBERS (common):
  1   = ICMP (Internet Control Message Protocol — ping!)
  6   = TCP  (Transmission Control Protocol)
  17  = UDP  (User Datagram Protocol)
  89  = OSPF (Open Shortest Path First routing)
"""

import socket
import struct
import sys
import os


# ────────────────────────── IP Protocol Registry ──────────────────────────

IP_PROTOCOLS = {
    1:   "ICMP",
    2:   "IGMP",
    6:   "TCP",
    17:  "UDP",
    41:  "IPv6 Encapsulation",
    47:  "GRE",
    50:  "ESP (IPSec)",
    51:  "AH (IPSec)",
    89:  "OSPF",
    132: "SCTP",
}

ETHERTYPE_NAMES = {
    0x0800: "IPv4",
    0x0806: "ARP",
    0x86DD: "IPv6",
    0x8100: "802.1Q VLAN",
}


# ────────────────────────── Socket Helpers ──────────────────────────

def create_raw_socket():
    try:
        if os.name == 'nt':
            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            host = socket.gethostbyname(socket.gethostname())
            raw_sock.bind((host, 0))
            raw_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            raw_sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            return raw_sock, True
        else:
            raw_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                     socket.htons(0x0003))
            return raw_sock, False
    except PermissionError:
        print("\n[ERROR] Permission denied! Run as Administrator (Windows) or root (Linux).")
        sys.exit(1)


def cleanup(raw_sock, is_windows):
    if is_windows:
        raw_sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
    raw_sock.close()


# ────────────────────────── Ethernet Parsing ──────────────────────────

def format_mac(raw_bytes):
    return ':'.join(f'{b:02X}' for b in raw_bytes)


def parse_ethernet_frame(raw_data, is_windows):
    """Returns (ethertype, payload) tuple."""
    if is_windows:
        return 0x0800, raw_data  # Windows: no ethernet header, payload is IP packet
    if len(raw_data) < 14:
        return None, None
    _, _, ethertype = struct.unpack('!6s6sH', raw_data[:14])
    return ethertype, raw_data[14:]


# ────────────────────────── IPv4 Header Parsing ──────────────────────────

def parse_ipv4_header(ip_data):
    """
    Parse the IPv4 header from the given bytes.

    The minimum IP header is 20 bytes. We use struct.unpack with format:
      '!BBHHHBBH4s4s'
        B  = 1 unsigned byte  → ver_ihl   (version + IHL packed)
        B  = 1 unsigned byte  → dscp_ecn  (type of service, ignored here)
        H  = 2 unsigned bytes → total_len (total packet length)
        H  = 2 unsigned bytes → ident     (fragmentation ID)
        H  = 2 unsigned bytes → frag_off  (flags + fragment offset)
        B  = 1 unsigned byte  → ttl       (Time To Live — hops remaining)
        B  = 1 unsigned byte  → protocol  (next layer: TCP=6, UDP=17, ICMP=1)
        H  = 2 unsigned bytes → checksum  (header integrity check)
        4s = 4 raw bytes      → src_ip    (source IP address)
        4s = 4 raw bytes      → dst_ip    (destination IP address)
      Total: 1+1+2+2+2+1+1+2+4+4 = 20 bytes ✓

    Returns a dict with all extracted fields, or None if data is too short.
    """
    if len(ip_data) < 20:
        return None

    # Unpack the fixed 20-byte IP header
    (ver_ihl, dscp_ecn, total_len, ident, frag_off,
     ttl, protocol, checksum, src_raw, dst_raw) = struct.unpack(
        '!BBHHHBBH4s4s', ip_data[:20]
    )

    # ── Bitwise extraction ──
    # ver_ihl is one byte with two nibbles:
    version = ver_ihl >> 4          # Shift right 4 bits → upper nibble = IP version
    ihl     = ver_ihl & 0x0F        # Bitwise AND with 00001111 → lower nibble = IHL
    header_length = ihl * 4         # IHL is in 32-bit words; multiply by 4 for bytes

    # ── IP address formatting ──
    # socket.inet_ntoa() converts a 4-byte big-endian binary to dotted-decimal string
    # e.g. b'\xc0\xa8\x01\x01' → '192.168.1.1'
    src_ip = socket.inet_ntoa(src_raw)
    dst_ip = socket.inet_ntoa(dst_raw)

    # The IP payload (TCP/UDP/ICMP data) starts after the IP header
    payload = ip_data[header_length:]

    return {
        'version':       version,
        'ihl':           ihl,
        'header_length': header_length,
        'total_length':  total_len,
        'ttl':           ttl,
        'protocol':      protocol,
        'proto_name':    IP_PROTOCOLS.get(protocol, f'Unknown ({protocol})'),
        'checksum':      checksum,
        'src_ip':        src_ip,
        'dst_ip':        dst_ip,
        'payload':       payload,
    }


# ────────────────────────── Display ──────────────────────────

def display_packet(eth_type, ip, packet_num):
    """Print a formatted multi-layer packet summary."""
    print(f"\n{'═' * 60}")
    print(f"  PACKET #{packet_num}")
    print(f"{'═' * 60}")
    print(f"  ┌─ ETHERNET LAYER")
    print(f"  │  EtherType : 0x{eth_type:04X}  ({ETHERTYPE_NAMES.get(eth_type, 'Unknown')})")
    print(f"  │")

    if ip:
        print(f"  ├─ NETWORK LAYER (IPv4)")
        print(f"  │  Version       : IPv{ip['version']}")
        print(f"  │  Header Length : {ip['header_length']} bytes  (IHL={ip['ihl']})")
        print(f"  │  Total Length  : {ip['total_length']} bytes")
        print(f"  │  TTL           : {ip['ttl']} hops")
        print(f"  │  Protocol      : {ip['protocol']}  →  {ip['proto_name']}")
        print(f"  │  Source IP     : {ip['src_ip']}")
        print(f"  │  Destination IP: {ip['dst_ip']}")
        print(f"  │  Payload size  : {len(ip['payload'])} bytes")
        print(f"  └{'─' * 50}")
    else:
        print(f"  └─ [Not an IPv4 packet or header too short]")


# ────────────────────────── Main Loop ──────────────────────────

def main():
    print("=" * 60)
    print("  IPv4 Header Parser")
    print("  Press Ctrl+C to stop.")
    print("=" * 60)

    raw_sock, is_windows = create_raw_socket()
    print(f"[*] Raw socket created. Platform: {'Windows' if is_windows else 'Linux/macOS'}\n")

    packet_count = 0

    try:
        while True:
            raw_data, _ = raw_sock.recvfrom(65535)
            ethertype, payload = parse_ethernet_frame(raw_data, is_windows)

            if payload is None:
                continue  # Malformed frame

            ip_header = None
            if ethertype == 0x0800:  # IPv4
                ip_header = parse_ipv4_header(payload)

            if ip_header is None and ethertype != 0x0800:
                continue  # Skip non-IPv4 for cleaner output

            packet_count += 1
            display_packet(ethertype, ip_header, packet_count)

            if packet_count >= 10:
                print(f"\n[*] Captured {packet_count} packets. Stopping.")
                break

    except KeyboardInterrupt:
        print(f"\n[*] Interrupted. Captured {packet_count} packets.")
    finally:
        cleanup(raw_sock, is_windows)
        print("[*] Socket closed.")

    print("\n[*] See transport.py to parse the TCP/UDP transport layer headers.")


if __name__ == "__main__":
    main()
