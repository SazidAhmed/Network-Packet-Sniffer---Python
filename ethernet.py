"""
=============================================================
  ethernet.py — Unpacking the Ethernet Frame
  Network Packet Sniffer - Python Raw Sockets
=============================================================

ARCHITECTURE OVERVIEW: ETHERNET FRAMES & ENDIANNESS
----------------------------------------------------
An Ethernet II frame has this layout:

  ┌──────────────────────────────────────────────────────────┐
  │  Dest MAC  │  Src MAC   │ EtherType │     Payload        │
  │  6 bytes   │  6 bytes   │  2 bytes  │  46–1500 bytes     │
  └──────────────────────────────────────────────────────────┘
  Total header = 14 bytes

ENDIANNESS — BYTE ORDER:
-------------------------
Numbers can be stored with their most significant byte first (Big Endian /
Network Byte Order) or least significant byte first (Little Endian / host order).

Example: The number 0x0800 (IPv4 EtherType)
  Big Endian    (network): 08 00  ← what we see on the wire
  Little Endian (x86 CPU): 00 08  ← what the CPU would store natively

Python's `struct.unpack` format characters:
  '!' prefix = use Network Byte Order (Big Endian) — ALWAYS use this for packets
  '6s'       = 6-byte raw bytes (MAC address)
  'H'        = unsigned short (2 bytes) = EtherType

struct.unpack('!6s6sH', data[:14])
  → reads 6 bytes (dst MAC), 6 bytes (src MAC), 2 bytes (EtherType)
  → the '!' ensures we interpret the 2-byte EtherType as Big Endian

COMMON ETHERTYPES:
  0x0800 = IPv4
  0x0806 = ARP (Address Resolution Protocol)
  0x86DD = IPv6
  0x8100 = 802.1Q VLAN tagged frame
"""

import socket
import struct
import sys
import os


# ────────────────────────── Socket Helpers ──────────────────────────

def create_raw_socket():
    """Create a raw socket (same as capture.py)."""
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
    """Disable promiscuous mode and close socket."""
    if is_windows:
        raw_sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
    raw_sock.close()


# ────────────────────────── Ethernet Parsing ──────────────────────────

# EtherType → human-readable name mapping
ETHERTYPE_NAMES = {
    0x0800: "IPv4",
    0x0806: "ARP",
    0x86DD: "IPv6",
    0x8100: "802.1Q VLAN",
    0x0842: "Wake-on-LAN",
    0x8035: "RARP",
}


def format_mac(raw_bytes):
    """
    Convert 6 raw bytes into a human-readable MAC address string.
    
    Each byte is formatted as a 2-digit uppercase hex number, joined by colons.
    Example: b'\\xac\\x23\\x1b\\x4c\\x00\\x01' → 'AC:23:1B:4C:00:01'
    
    The colon-separated format is the IEEE standard notation.
    (Windows uses hyphens: AC-23-1B-4C-00-01, but colons are more universal.)
    """
    return ':'.join(f'{b:02X}' for b in raw_bytes)


def parse_ethernet_frame(raw_data, is_windows):
    """
    Parse the Ethernet II frame header from raw packet bytes.

    On Windows, raw sockets return the IP layer (no Ethernet header).
    On Linux,   raw AF_PACKET sockets return the full frame from layer 2.
    
    Returns:
        dict with keys: dest_mac, src_mac, ethertype, ethertype_name, payload
        OR None if the data is too short.
    
    struct.unpack format: '!6s6sH'
      '!' = network byte order (big-endian)
      '6s' = 6-byte string (Destination MAC)
      '6s' = 6-byte string (Source MAC)
      'H'  = unsigned 16-bit integer (EtherType) — 2 bytes, big-endian
    """
    if is_windows:
        # Windows raw sockets skip the Ethernet header; we synthesize placeholder values.
        # The actual IP packet starts at byte 0 in this case.
        return {
            'dest_mac':       'N/A (Windows raw socket)',
            'src_mac':        'N/A (Windows raw socket)',
            'ethertype':      0x0800,  # Assume IPv4 (we requested IP-level capture)
            'ethertype_name': 'IPv4',
            'payload':        raw_data,   # Payload IS the IP packet
        }

    # Linux path: full Ethernet frame
    if len(raw_data) < 14:
        return None  # Truncated frame, skip it

    # Unpack the 14-byte Ethernet header
    # struct.unpack returns a tuple: (dest_mac_bytes, src_mac_bytes, ethertype_int)
    dest_mac_raw, src_mac_raw, ethertype = struct.unpack('!6s6sH', raw_data[:14])

    return {
        'dest_mac':       format_mac(dest_mac_raw),
        'src_mac':        format_mac(src_mac_raw),
        'ethertype':      ethertype,
        'ethertype_name': ETHERTYPE_NAMES.get(ethertype, f'Unknown (0x{ethertype:04X})'),
        'payload':        raw_data[14:],   # Everything after the 14-byte header
    }


# ────────────────────────── Display ──────────────────────────

def display_ethernet_frame(frame, packet_num):
    """Print a formatted summary of the Ethernet frame."""
    print(f"\n{'─' * 60}")
    print(f"  PACKET #{packet_num}")
    print(f"{'─' * 60}")
    print(f"  ┌─ ETHERNET FRAME ({'Simulated on Windows' if 'N/A' in frame['dest_mac'] else 'Layer 2 capture'})")
    print(f"  │  Destination MAC : {frame['dest_mac']}")
    print(f"  │  Source MAC      : {frame['src_mac']}")
    print(f"  │  EtherType       : 0x{frame['ethertype']:04X}  →  {frame['ethertype_name']}")
    print(f"  │  Payload size    : {len(frame['payload'])} bytes")
    print(f"  └{'─' * 50}")


# ────────────────────────── Main Loop ──────────────────────────

def main():
    print("=" * 60)
    print("  Ethernet Frame Parser")
    print("  Press Ctrl+C to stop.")
    print("=" * 60)

    raw_sock, is_windows = create_raw_socket()
    print(f"[*] Raw socket created. Platform: {'Windows' if is_windows else 'Linux/macOS'}\n")

    packet_count = 0

    try:
        while True:
            raw_data, _ = raw_sock.recvfrom(65535)
            frame = parse_ethernet_frame(raw_data, is_windows)

            if frame is None:
                continue  # Skip malformed frames

            packet_count += 1
            display_ethernet_frame(frame, packet_count)

            # Stop after 10 packets so output stays readable
            if packet_count >= 10:
                print(f"\n[*] Captured {packet_count} packets. Stopping.")
                break

    except KeyboardInterrupt:
        print(f"\n[*] Interrupted. Captured {packet_count} packets.")
    finally:
        cleanup(raw_sock, is_windows)
        print("[*] Socket closed.")
    
    print("\n[*] See ip_parser.py to parse the IPv4 header inside the payload.")


if __name__ == "__main__":
    main()
