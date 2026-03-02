"""
=============================================================
  STEP 4: Unpacking the Transport Layer (TCP & UDP)
  Network Packet Sniffer - Python Raw Sockets
=============================================================

ARCHITECTURE OVERVIEW: ROUTING vs. APPLICATION COMMUNICATION
--------------------------------------------------------------
IP addresses (layer 3) answer: "Which MACHINE on the internet?"
Port numbers  (layer 4) answer: "Which APPLICATION on that machine?"

A TCP/UDP port is a 16-bit number (0–65535) that acts like an
apartment number in a building. The IP is the street address;
the port is the apartment.

Well-known ports (assigned by IANA):
  20/21  = FTP    (File Transfer Protocol)
   22    = SSH    (Secure Shell)
   23    = Telnet
   25    = SMTP   (email sending)
   53    = DNS    (Domain Name System)
   80    = HTTP
  443    = HTTPS
 3306    = MySQL
 5432    = PostgreSQL

TCP HEADER STRUCTURE (minimum 20 bytes):
-----------------------------------------
 Offset  Size  Field
    0     2B   Source Port
    2     2B   Destination Port
    4     4B   Sequence Number     ← tracks byte ordering in stream
    8     4B   Acknowledgment Num  ← confirms received bytes
   12     1B   Data Offset (4-bit) + Reserved (3-bit) + NS flag (1-bit)
   13     1B   Control Flags (CWR|ECE|URG|ACK|PSH|RST|SYN|FIN)
   14     2B   Window Size         ← flow control
   16     2B   Checksum
   18     2B   Urgent Pointer
  [20+]       Options + Data

DATA OFFSET (like IHL in IP): upper nibble of byte 12
  data_offset = (byte12 >> 4)      # shift right 4 bits
  header_bytes = data_offset * 4   # TCP header length in bytes

TCP FLAGS (bitfield in one byte):
  Bit 7 (0x80): CWR — Congestion Window Reduced
  Bit 6 (0x40): ECE — ECN-Echo
  Bit 5 (0x20): URG — Urgent pointer valid
  Bit 4 (0x10): ACK — Acknowledgment field valid
  Bit 3 (0x08): PSH — Push: deliver data immediately to application
  Bit 2 (0x04): RST — Reset connection (abort)
  Bit 1 (0x02): SYN — Synchronize sequence numbers (connection start)
  Bit 0 (0x01): FIN — Finish: no more data to send (connection end)

UDP HEADER STRUCTURE (fixed 8 bytes — much simpler than TCP):
--------------------------------------------------------------
 Offset  Size  Field
    0     2B   Source Port
    2     2B   Destination Port
    4     2B   Length (header + data)
    6     2B   Checksum
    8+        Data

UDP is connectionless — no handshake, no ordering, no acknowledgment.
Great for DNS lookups, video streaming, gaming (speed > reliability).
"""

import socket
import struct
import sys
import os


# ────────────────────────── Constants ──────────────────────────

IP_PROTOCOLS = {1: "ICMP", 6: "TCP", 17: "UDP", 41: "IPv6", 47: "GRE", 89: "OSPF"}
ETHERTYPE_NAMES = {0x0800: "IPv4", 0x0806: "ARP", 0x86DD: "IPv6", 0x8100: "VLAN"}

COMMON_PORTS = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET",
    25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    465: "SMTPS", 587: "SMTP", 993: "IMAPS", 995: "POP3S",
    3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt",
}


def port_label(port):
    """Return 'PORT (SERVICE)' or just 'PORT' if unknown."""
    name = COMMON_PORTS.get(port, "")
    return f"{port} ({name})" if name else str(port)


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


# ────────────────────────── Layer Parsers ──────────────────────────

def parse_ethernet(raw_data, is_windows):
    if is_windows:
        return 0x0800, raw_data
    if len(raw_data) < 14:
        return None, None
    _, _, ethertype = struct.unpack('!6s6sH', raw_data[:14])
    return ethertype, raw_data[14:]


def parse_ipv4(data):
    if len(data) < 20:
        return None
    (ver_ihl, _, total_len, _, _, ttl, proto, chk, src, dst) = struct.unpack(
        '!BBHHHBBH4s4s', data[:20])
    ihl = (ver_ihl & 0x0F) * 4
    return {
        'ttl': ttl, 'protocol': proto,
        'proto_name': IP_PROTOCOLS.get(proto, f'?({proto})'),
        'src_ip': socket.inet_ntoa(src),
        'dst_ip': socket.inet_ntoa(dst),
        'payload': data[ihl:],
        'header_len': ihl,
    }


def parse_tcp(data):
    """
    Parse the TCP header from raw bytes.

    struct format: '!HHLLBBHHH'
      H = Source Port          (2 bytes)
      H = Destination Port     (2 bytes)
      L = Sequence Number      (4 bytes, unsigned long)
      L = Acknowledgment Num   (4 bytes, unsigned long)
      B = Data Offset + flags  (1 byte: upper nibble = offset)
      B = Control Flags        (1 byte: CWR|ECE|URG|ACK|PSH|RST|SYN|FIN)
      H = Window Size          (2 bytes)
      H = Checksum             (2 bytes)
      H = Urgent Pointer       (2 bytes)
    Total: 2+2+4+4+1+1+2+2+2 = 20 bytes

    Data Offset (byte 12): indicates where data begins.
      offset = (byte >> 4) * 4   ← same bitwise trick as IP IHL
    """
    if len(data) < 20:
        return None

    src_port, dst_port, seq, ack, offset_reserved, flags, window, chk, urg = \
        struct.unpack('!HHLLBBHHH', data[:20])

    # Extract data offset from upper nibble of the offset_reserved byte
    tcp_header_len = (offset_reserved >> 4) * 4  # in bytes

    # Parse individual flags by bitwise AND with each bitmask
    flag_bits = {
        'FIN': bool(flags & 0x01),  # 0000 0001
        'SYN': bool(flags & 0x02),  # 0000 0010
        'RST': bool(flags & 0x04),  # 0000 0100
        'PSH': bool(flags & 0x08),  # 0000 1000
        'ACK': bool(flags & 0x10),  # 0001 0000
        'URG': bool(flags & 0x20),  # 0010 0000
    }
    active_flags = [name for name, val in flag_bits.items() if val]

    return {
        'src_port':   src_port,
        'dst_port':   dst_port,
        'seq':        seq,
        'ack':        ack,
        'header_len': tcp_header_len,
        'flags':      flag_bits,
        'flag_str':   ' | '.join(active_flags) if active_flags else 'none',
        'window':     window,
        'payload':    data[tcp_header_len:],
    }


def parse_udp(data):
    """
    Parse the UDP header (always exactly 8 bytes).
    struct format: '!HHHH'
      H = Source Port      (2 bytes)
      H = Destination Port (2 bytes)
      H = Length           (2 bytes, includes 8-byte header)
      H = Checksum         (2 bytes)
    """
    if len(data) < 8:
        return None

    src_port, dst_port, length, checksum = struct.unpack('!HHHH', data[:8])
    return {
        'src_port': src_port,
        'dst_port': dst_port,
        'length':   length,
        'payload':  data[8:],
    }


# ────────────────────────── Display ──────────────────────────

SEP_THICK = '═' * 62
SEP_THIN  = '─' * 62

def display_packet(eth_type, ip, tcp=None, udp=None, pkt_num=0):
    """Formatted multi-layer packet display."""
    print(f"\n{SEP_THICK}")
    print(f"  ▶  PACKET #{pkt_num}")
    print(SEP_THICK)

    # ── Ethernet ──
    eth_name = ETHERTYPE_NAMES.get(eth_type, f"0x{eth_type:04X}")
    print(f"  [ETH]  EtherType: {eth_name}")

    if not ip:
        return

    # ── IP ──
    print(f"{SEP_THIN}")
    print(f"  [IP]   {ip['src_ip']}  →  {ip['dst_ip']}")
    print(f"         TTL: {ip['ttl']}    Protocol: {ip['proto_name']} ({ip['protocol']})")

    # ── TCP ──
    if tcp:
        data_size = len(tcp['payload'])
        print(f"{SEP_THIN}")
        print(f"  [TCP]  {ip['src_ip']}:{port_label(tcp['src_port'])}")
        print(f"         →  {ip['dst_ip']}:{port_label(tcp['dst_port'])}")
        print(f"         Seq:    {tcp['seq']:>12,}")
        print(f"         Ack:    {tcp['ack']:>12,}")
        print(f"         Flags:  {tcp['flag_str']}")
        print(f"         Window: {tcp['window']} bytes")
        print(f"         Data:   {data_size} bytes{'  (empty — control packet)' if data_size == 0 else ''}")

    # ── UDP ──
    elif udp:
        print(f"{SEP_THIN}")
        print(f"  [UDP]  {ip['src_ip']}:{port_label(udp['src_port'])}")
        print(f"         →  {ip['dst_ip']}:{port_label(udp['dst_port'])}")
        print(f"         Length: {udp['length']} bytes")
        print(f"         Data:   {len(udp['payload'])} bytes")

    # ── ICMP / Other ──
    elif ip['protocol'] == 1:
        print(f"{SEP_THIN}")
        print(f"  [ICMP] {ip['src_ip']}  →  {ip['dst_ip']}")
        print(f"         Payload: {len(ip['payload'])} bytes")

    print(SEP_THICK)


# ────────────────────────── Main Loop ──────────────────────────

def main():
    print("=" * 62)
    print("  STEP 4: TCP/UDP Transport Layer Parser")
    print("  Press Ctrl+C to stop.")
    print("=" * 62)

    raw_sock, is_windows = create_raw_socket()
    print(f"[*] Raw socket ready. Platform: {'Windows' if is_windows else 'Linux/macOS'}\n")
    print("  Showing: TCP, UDP, and ICMP packets. Filtering out others.\n")

    pkt_count = 0

    try:
        while True:
            raw_data, _ = raw_sock.recvfrom(65535)
            ethertype, payload = parse_ethernet(raw_data, is_windows)

            if payload is None or ethertype != 0x0800:
                continue  # Only process IPv4

            ip = parse_ipv4(payload)
            if not ip:
                continue

            tcp = udp = None

            if ip['protocol'] == 6:    # TCP
                tcp = parse_tcp(ip['payload'])
            elif ip['protocol'] == 17: # UDP
                udp = parse_udp(ip['payload'])
            elif ip['protocol'] != 1:  # Not ICMP either
                continue               # Skip unknown protocols for clean output

            pkt_count += 1
            display_packet(ethertype, ip, tcp, udp, pkt_num=pkt_count)

            if pkt_count >= 15:
                print(f"\n[*] Captured {pkt_count} packets. Stopping.")
                break

    except KeyboardInterrupt:
        print(f"\n[*] Interrupted. Total packets captured: {pkt_count}")
    finally:
        cleanup(raw_sock, is_windows)
        print("[*] Socket closed.")

    print("\n[*] All 4 steps complete! See sniffer.py for the full combined version.")


if __name__ == "__main__":
    main()
