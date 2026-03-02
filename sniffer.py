"""
=============================================================
  NETWORK PACKET SNIFFER — Combined Full Version
  All layers: Ethernet → IPv4/IPv6 → TCP/UDP/ICMP
  No third-party libraries — pure Python stdlib only.
=============================================================

  Run on Windows (PowerShell as Administrator):
    python sniffer.py

  Run on Linux/macOS (with root):
    sudo python3 sniffer.py

  Optional flags:
    python sniffer.py --count 50          # Stop after 50 packets
    python sniffer.py --proto tcp         # Filter: tcp | udp | icmp | ipv6 | all
    python sniffer.py --host 192.168.1.5  # Bind to a specific interface (Windows)
    python sniffer.py --no-color          # Disable ANSI colors
"""

import socket
import struct
import sys
import os
import argparse
import datetime


# ─────────────────────────── ANSI Colors ───────────────────────────

class Colors:
    """ANSI escape codes for terminal colorization. Disabled on Windows cmd."""
    RESET   = '\033[0m'
    BOLD    = '\033[1m'
    DIM     = '\033[2m'
    RED     = '\033[91m'
    GREEN   = '\033[92m'
    YELLOW  = '\033[93m'
    BLUE    = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN    = '\033[96m'
    WHITE   = '\033[97m'
    GRAY    = '\033[90m'

    @classmethod
    def disable(cls):
        """Strip all color codes (for --no-color mode or unsupported terminals)."""
        for attr in ['RESET','BOLD','DIM','RED','GREEN','YELLOW',
                     'BLUE','MAGENTA','CYAN','WHITE','GRAY']:
            setattr(cls, attr, '')

C = Colors


# ─────────────────────────── Port Registry ───────────────────────────

COMMON_PORTS = {
    20:"FTP-DATA", 21:"FTP", 22:"SSH", 23:"TELNET",
    25:"SMTP", 53:"DNS", 67:"DHCP", 68:"DHCP",
    80:"HTTP", 110:"POP3", 143:"IMAP", 443:"HTTPS",
    465:"SMTPS", 587:"SMTP", 993:"IMAPS", 995:"POP3S",
    3306:"MySQL", 5432:"PostgreSQL", 6379:"Redis",
    8080:"HTTP-Alt", 8443:"HTTPS-Alt", 27017:"MongoDB",
}

IP_PROTOCOLS = {
    1:"ICMP", 2:"IGMP", 6:"TCP", 17:"UDP",
    41:"IPv6", 47:"GRE", 50:"ESP", 51:"AH", 89:"OSPF",
}

ETHERTYPE_NAMES = {
    0x0800:"IPv4", 0x0806:"ARP", 0x86DD:"IPv6", 0x8100:"VLAN",
}


def port_label(port):
    name = COMMON_PORTS.get(port, "")
    return f"{port}/{name}" if name else str(port)


# ─────────────────────────── Raw Socket Setup ───────────────────────────

def create_raw_socket(host=None):
    """
    Create a platform-appropriate raw socket.

    host (Windows only): IP address of the interface to bind to.
      Defaults to socket.gethostbyname(socket.gethostname()).
      Use --host to specify a different interface, e.g. a VPN or Wi-Fi adapter.
    """
    try:
        if os.name == 'nt':  # Windows
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            bound_host = host or socket.gethostbyname(socket.gethostname())
            sock.bind((bound_host, 0))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            return sock, True, bound_host
        else:  # Linux / macOS
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
            return sock, False, socket.gethostname()
    except PermissionError:
        print(f"\n{C.RED}[ERROR]{C.RESET} Permission denied!")
        print("  → Windows: Run PowerShell or CMD as Administrator")
        print("  → Linux:   sudo python3 sniffer.py")
        sys.exit(1)
    except OSError as e:
        print(f"\n{C.RED}[ERROR]{C.RESET} Could not create socket: {e}")
        sys.exit(1)


def cleanup(sock, is_windows):
    if is_windows:
        sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
    sock.close()


# ─────────────────────────── Parsers ───────────────────────────

def parse_ethernet(raw_data, is_windows):
    """Returns (ethertype, payload). Windows skips the Ethernet header."""
    if is_windows:
        return 0x0800, raw_data
    if len(raw_data) < 14:
        return None, None
    dst, src, eth_type = struct.unpack('!6s6sH', raw_data[:14])
    return eth_type, raw_data[14:]


def fmt_mac(raw):
    return ':'.join(f'{b:02X}' for b in raw)


def parse_ethernet_full(raw_data, is_windows):
    """Returns full ethernet info dict (only meaningful on Linux)."""
    if is_windows:
        return {'dst': 'N/A', 'src': 'N/A', 'ethertype': 0x0800, 'payload': raw_data}
    if len(raw_data) < 14:
        return None
    dst, src, eth_type = struct.unpack('!6s6sH', raw_data[:14])
    return {
        'dst': fmt_mac(dst),
        'src': fmt_mac(src),
        'ethertype': eth_type,
        'payload': raw_data[14:],
    }


def parse_ipv4(data):
    """Unpack the 20-byte IPv4 header. Returns dict or None."""
    if len(data) < 20:
        return None
    ver_ihl, _, total, ident, frag, ttl, proto, chk, src, dst = \
        struct.unpack('!BBHHHBBH4s4s', data[:20])
    ihl = (ver_ihl & 0x0F) * 4       # lower nibble × 4 = header length in bytes
    version = ver_ihl >> 4            # upper nibble = IP version
    return {
        'version': version,
        'ihl': ihl,
        'total': total,
        'ttl': ttl,
        'protocol': proto,
        'proto_name': IP_PROTOCOLS.get(proto, f'?({proto})'),
        'src_ip': socket.inet_ntoa(src),
        'dst_ip': socket.inet_ntoa(dst),
        'payload': data[ihl:],
    }


def parse_tcp(data):
    """Unpack the TCP header. Returns dict or None."""
    if len(data) < 20:
        return None
    src_p, dst_p, seq, ack, off_res, flags, win, chk, urg = \
        struct.unpack('!HHLLBBHHH', data[:20])
    hlen = (off_res >> 4) * 4
    flag_map = {
        'FIN': flags & 0x01, 'SYN': flags & 0x02, 'RST': flags & 0x04,
        'PSH': flags & 0x08, 'ACK': flags & 0x10, 'URG': flags & 0x20,
        'ECE': flags & 0x40, 'CWR': flags & 0x80,
    }
    active = [k for k, v in flag_map.items() if v]
    return {
        'src_port': src_p,
        'dst_port': dst_p,
        'seq': seq,
        'ack': ack,
        'header_len': hlen,
        'flags': flag_map,
        'flag_str': ' '.join(active) or 'none',
        'window': win,
        'payload': data[hlen:],
    }


def parse_udp(data):
    """Unpack the 8-byte UDP header. Returns dict or None."""
    if len(data) < 8:
        return None
    src_p, dst_p, length, chk = struct.unpack('!HHHH', data[:8])
    return {
        'src_port': src_p,
        'dst_port': dst_p,
        'length': length,
        'payload': data[8:],
    }


def parse_icmp(data):
    """Unpack the ICMP header (first 4 bytes are type/code/checksum)."""
    if len(data) < 4:
        return None
    icmp_type, code, chk = struct.unpack('!BBH', data[:4])
    type_names = {0: "Echo Reply", 3: "Dest Unreachable", 8: "Echo Request",
                  11: "Time Exceeded", 12: "Param Problem"}
    return {
        'type': icmp_type,
        'code': code,
        'type_name': type_names.get(icmp_type, f'Type {icmp_type}'),
    }


def parse_ipv6(data):
    """
    Parse the fixed 40-byte IPv6 header.

    IPv6 header structure:
      4B  Version(4) + Traffic Class(8) + Flow Label(20) — packed
      2B  Payload Length
      1B  Next Header  (like IPv4 Protocol: 6=TCP, 17=UDP, 58=ICMPv6)
      1B  Hop Limit    (like IPv4 TTL)
      16B Source Address
      16B Destination Address
    Total = 40 bytes (fixed, no options field — extensions are chained via Next Header)

    socket.inet_ntop(AF_INET6, ...) formats 16 raw bytes as a proper IPv6 address
    e.g. b'\x20\x01...' → '2001:4860:4860::8888'
    """
    if len(data) < 40:
        return None
    # First 4 bytes: version/TC/flow packed — we unpack as one big-endian uint32
    vtf, payload_len, next_hdr, hop_limit = struct.unpack('!IHBB', data[:8])
    version = (vtf >> 28) & 0xF          # top 4 bits
    src_raw = data[8:24]
    dst_raw = data[24:40]
    src_ip = socket.inet_ntop(socket.AF_INET6, src_raw)
    dst_ip = socket.inet_ntop(socket.AF_INET6, dst_raw)
    next_names = {6: 'TCP', 17: 'UDP', 58: 'ICMPv6', 43: 'Routing', 44: 'Fragment'}
    return {
        'version':     version,
        'payload_len': payload_len,
        'next_hdr':    next_hdr,
        'next_name':   next_names.get(next_hdr, f'?({next_hdr})'),
        'hop_limit':   hop_limit,
        'src_ip':      src_ip,
        'dst_ip':      dst_ip,
        'payload':     data[40:],
    }


# ─────────────────────────── Display ───────────────────────────

THICK = '═' * 64
THIN  = '─' * 64


def proto_color(proto_name):
    """Return a color code based on the protocol name."""
    colors = {
        'TCP': C.GREEN, 'UDP': C.CYAN, 'ICMP': C.YELLOW,
        'ARP': C.MAGENTA, 'IPv6': C.BLUE,
    }
    return colors.get(proto_name, C.WHITE)


def flag_color(flag_str):
    """Highlight dangerous flags (SYN, RST, FIN) in red/yellow."""
    if 'RST' in flag_str:
        return C.RED
    if 'SYN' in flag_str and 'ACK' not in flag_str:
        return C.GREEN   # New connection
    if 'FIN' in flag_str:
        return C.YELLOW  # Connection closing
    return C.WHITE


def display_packet(eth, ip, tcp=None, udp=None, icmp=None, ipv6=None, pkt_num=0, is_windows=True):
    ts = datetime.datetime.now().strftime('%H:%M:%S.%f')[:-3]
    proto_label = 'IPv6' if ipv6 and not ip else (ip['proto_name'] if ip else 'N/A')
    pc = proto_color(proto_label)

    print(f"\n{C.GRAY}{THICK}{C.RESET}")
    print(f"  {C.BOLD}{C.WHITE}#{pkt_num:<5}{C.RESET}  "
          f"{C.GRAY}{ts}{C.RESET}  "
          f"{pc}{C.BOLD}{proto_label:6}{C.RESET}")
    print(f"{C.GRAY}{THIN}{C.RESET}")

    # Ethernet
    if not is_windows and eth:
        eth_name = ETHERTYPE_NAMES.get(eth['ethertype'], f"0x{eth['ethertype']:04X}")
        print(f"  {C.DIM}ETH{C.RESET}  "
              f"{C.GRAY}{eth['src']}{C.RESET} → "
              f"{C.GRAY}{eth['dst']}{C.RESET}  "
              f"[{eth_name}]")

    # IPv6
    if ipv6 and not ip:
        print(f"  {C.BLUE}IPv6{C.RESET} {C.WHITE}{ipv6['src_ip']}{C.RESET}")
        print(f"       → {C.WHITE}{ipv6['dst_ip']}{C.RESET}")
        print(f"       Hop Limit: {ipv6['hop_limit']}  Next: {ipv6['next_name']}  Payload: {ipv6['payload_len']}B")
        return

    # IPv4
    if ip:
        print(f"  {C.BLUE}IP {C.RESET}  "
              f"{C.WHITE}{ip['src_ip']:<15}{C.RESET} → "
              f"{C.WHITE}{ip['dst_ip']:<15}{C.RESET}  "
              f"TTL:{ip['ttl']}  Len:{ip['total']}B")

    # TCP
    if tcp:
        fc = flag_color(tcp['flag_str'])
        src_label = port_label(tcp['src_port'])
        dst_label = port_label(tcp['dst_port'])
        print(f"  {C.GREEN}TCP{C.RESET}  "
              f"Port {C.CYAN}{src_label}{C.RESET} → "
              f"{C.CYAN}{dst_label}{C.RESET}")
        print(f"       SEQ:{C.YELLOW}{tcp['seq']:>12,}{C.RESET}  "
              f"ACK:{C.YELLOW}{tcp['ack']:>12,}{C.RESET}")
        print(f"       Flags: {fc}{C.BOLD}{tcp['flag_str']}{C.RESET}  "
              f"Win:{tcp['window']}  "
              f"Data:{len(tcp['payload'])}B")

    # UDP
    elif udp:
        src_label = port_label(udp['src_port'])
        dst_label = port_label(udp['dst_port'])
        print(f"  {C.CYAN}UDP{C.RESET}  "
              f"Port {C.CYAN}{src_label}{C.RESET} → "
              f"{C.CYAN}{dst_label}{C.RESET}  "
              f"Len:{udp['length']}B")

    # ICMP
    elif icmp:
        print(f"  {C.YELLOW}ICMP{C.RESET} Type:{icmp['type']}  "
              f"({icmp['type_name']})  Code:{icmp['code']}")


# ─────────────────────────── Statistics ───────────────────────────

class Stats:
    def __init__(self):
        self.total = 0
        self.by_proto = {}
        self.bytes_total = 0

    def record(self, proto_name, pkt_len):
        self.total += 1
        self.bytes_total += pkt_len
        self.by_proto[proto_name] = self.by_proto.get(proto_name, 0) + 1

    def display(self):
        print(f"\n{C.BOLD}{THICK}{C.RESET}")
        print(f"  {C.BOLD}CAPTURE SUMMARY{C.RESET}")
        print(THIN)
        print(f"  Total packets : {self.total}")
        print(f"  Total bytes   : {self.bytes_total:,}")
        print(f"  Breakdown:")
        for proto, count in sorted(self.by_proto.items(), key=lambda x: -x[1]):
            pc = proto_color(proto)
            pct = (count / self.total * 100) if self.total else 0
            bar = '█' * int(pct / 5)
            print(f"    {pc}{proto:<8}{C.RESET}: {count:>5}  {C.GRAY}{bar}{C.RESET}  {pct:.1f}%")
        print(THICK)


# ─────────────────────────── Argument Parsing ───────────────────────────

def parse_args():
    p = argparse.ArgumentParser(
        description='Network Packet Sniffer — Pure Python, no third-party libs',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python sniffer.py                        # Capture 100 packets (all protocols)
  python sniffer.py --count 50             # Stop after 50 packets
  python sniffer.py --proto tcp            # TCP only
  python sniffer.py --proto udp            # UDP only
  python sniffer.py --proto icmp           # ICMP only
  python sniffer.py --proto ipv6           # IPv6 frames only
  python sniffer.py --host 192.168.1.5     # Bind to specific interface (Windows)
  python sniffer.py --no-color             # Disable ANSI colors
        """
    )
    p.add_argument('--count',    type=int,   default=100,   help='Packets to capture (default: 100)')
    p.add_argument('--proto',    type=str,   default='all',
                   choices=['all', 'tcp', 'udp', 'icmp', 'ipv6'], help='Filter by protocol')
    p.add_argument('--host',     type=str,   default=None,
                   help='(Windows) IP of the interface to bind to. Default: auto-detect.')
    p.add_argument('--no-color', action='store_true', help='Disable colored output')
    return p.parse_args()


# ─────────────────────────── Main ───────────────────────────

def main():
    args = parse_args()
    if args.no_color:
        Colors.disable()

    # Enable ANSI on Windows terminal
    if os.name == 'nt':
        os.system('')   # Triggers VT100 ANSI support in Windows 10+

    print(f"{C.BOLD}{C.CYAN}")
    print("  ╔══════════════════════════════════════════════════════════╗")
    print("  ║       NETWORK PACKET SNIFFER  —  Pure Python            ║")
    print("  ║   Layers: Ethernet → IPv4/IPv6 → TCP / UDP / ICMP       ║")
    print("  ╚══════════════════════════════════════════════════════════╝")
    print(C.RESET)

    sock, is_windows, host = create_raw_socket(host=args.host)
    print(f"  {C.GREEN}[✓]{C.RESET} Socket ready  |  Platform: "
          f"{'Windows' if is_windows else 'Linux/macOS'}  |  Interface: {host}")
    print(f"  {C.GREEN}[✓]{C.RESET} Protocol filter: {args.proto.upper()}  |  "
          f"Max packets: {args.count}")
    if args.host and is_windows:
        print(f"  {C.GREEN}[✓]{C.RESET} Bound to user-specified host: {args.host}")
    print(f"  {C.YELLOW}[!]{C.RESET} Generating traffic? Try: ping google.com")
    print(f"  {C.GRAY}Press Ctrl+C to stop early.{C.RESET}\n")

    stats = Stats()
    pkt_num = 0

    try:
        while pkt_num < args.count:
            raw_data, _ = sock.recvfrom(65535)

            # ── Ethernet ──
            eth = parse_ethernet_full(raw_data, is_windows)
            if eth is None:
                continue
            ethertype = eth['ethertype']
            ip_data = eth['payload']

            # ── IPv6 (EtherType 0x86DD) ──
            if ethertype == 0x86DD:
                if args.proto not in ('all', 'ipv6'):
                    continue
                ipv6 = parse_ipv6(ip_data)
                if not ipv6:
                    continue
                pkt_num += 1
                stats.record('IPv6', ipv6['payload_len'])
                display_packet(eth, None, ipv6=ipv6, pkt_num=pkt_num, is_windows=is_windows)
                continue

            if ethertype != 0x0800:
                continue  # Skip non-IPv4, non-IPv6

            # ── IPv4 ──
            ip = parse_ipv4(ip_data)
            if not ip:
                continue

            proto = ip['protocol']
            tcp = udp = icmp = None

            # ── Transport Layer ──
            if proto == 6:      # TCP
                tcp = parse_tcp(ip['payload'])
                if args.proto not in ('all', 'tcp'):
                    continue
            elif proto == 17:   # UDP
                udp = parse_udp(ip['payload'])
                if args.proto not in ('all', 'udp'):
                    continue
            elif proto == 1:    # ICMP
                icmp = parse_icmp(ip['payload'])
                if args.proto not in ('all', 'icmp'):
                    continue
            else:
                continue        # Skip unknown protocols

            pkt_num += 1
            stats.record(ip['proto_name'], ip['total'])
            display_packet(eth, ip, tcp, udp, icmp, pkt_num=pkt_num, is_windows=is_windows)

    except KeyboardInterrupt:
        print(f"\n\n  {C.YELLOW}[!]{C.RESET} Capture stopped by user.")
    finally:
        cleanup(sock, is_windows)
        print(f"  {C.GREEN}[✓]{C.RESET} Socket closed and promiscuous mode disabled.")

    stats.display()


if __name__ == "__main__":
    main()
