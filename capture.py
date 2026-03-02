"""
=============================================================
  STEP 1: Environment & Basic Capture
  Network Packet Sniffer - Python Raw Sockets
=============================================================

ARCHITECTURE OVERVIEW: WHY DO WE NEED ADMIN/ROOT?
--------------------------------------------------
The OS networking stack has multiple layers:
  Application Layer  (your browser, curl, etc.)
       ↓
  Transport Layer    (TCP/UDP - managed by OS)
       ↓
  Network Layer      (IP - managed by OS)
       ↓
  Data Link Layer    (Ethernet frames - NIC driver)
       ↓
  Physical Layer     (actual bits on the wire - NIC hardware)

Normal sockets (SOCK_STREAM for TCP, SOCK_DGRAM for UDP) let
applications talk at the Transport Layer. The OS handles
everything below — you never see raw IP headers or Ethernet frames.

RAW SOCKETS (SOCK_RAW) bypass these OS abstractions and allow
your program to receive packets directly from the NIC, BEFORE
the OS has processed them. This means you see the raw IP header,
Ethernet frame, and all bytes as they arrive.

This is dangerous for two reasons:
  1. You could INTERCEPT traffic meant for other processes.
  2. You could CRAFT malicious packets or spoof identities.

Therefore, the OS protects raw socket creation behind privilege checks:
  - Windows: Must be in the Administrators group
  - Linux/macOS: Must be root (UID 0), or have CAP_NET_RAW capability

PROMISCUOUS MODE:
-----------------
Normally, a NIC only accepts packets addressed TO its own MAC address
(plus broadcasts). It discards everything else at the hardware level.

In PROMISCUOUS MODE, the NIC accepts ALL packets on the network segment,
even those addressed to other machines. This is how network analyzers
like Wireshark work. On Windows, we enable this via SIO_RCVALL.

NOTE: On a modern switched network, you typically only see:
  - Your own traffic (unicast to/from your machine)
  - Broadcast traffic (e.g., ARP requests)
  - Multicast traffic
  You do NOT see other machines' traffic unless you're on a hub or
  use ARP poisoning — that's a separate topic.
"""

import socket
import struct
import sys
import os


def create_raw_socket():
    """
    Create a raw socket depending on the platform.
    
    On Windows: AF_INET + SOCK_RAW + IPPROTO_IP
      - Receives IP packets (and above). Ethernet headers are NOT included.
      - We must call SIO_RCVALL to actually receive incoming packets.
    
    On Linux: AF_PACKET + SOCK_RAW + ETH_P_ALL (0x0003)
      - Receives ALL frames including the Ethernet header.
      - More powerful — gives us layer 2 (Data Link) access.
    
    Returns the socket and a boolean indicating if it's Windows.
    """
    try:
        if os.name == 'nt':  # Windows
            # AF_INET    = IPv4 address family
            # SOCK_RAW   = raw socket (bypasses transport layer)
            # IPPROTO_IP = generic IP protocol (captures IP layer and above)
            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)

            # Bind to the local machine's IP so we can enable SIO_RCVALL.
            # '' means the default network interface / all interfaces.
            host = socket.gethostbyname(socket.gethostname())
            raw_sock.bind((host, 0))

            # Enable IP_HDRINCL: tells OS to include the IP header in captured data.
            # Without this, Windows strips the IP header before giving us the packet.
            raw_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

            # SIO_RCVALL is a Windows-specific ioctl command.
            # RCVALL_ON tells the NIC driver to forward ALL incoming IP packets to us,
            # not just those destined for our IP — this is promiscuous mode for Windows.
            raw_sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

            print(f"[*] Bound to host: {host}")
            return raw_sock, True

        else:  # Linux / macOS
            # AF_PACKET  = packet socket (layer 2, includes Ethernet header)
            # SOCK_RAW   = raw socket
            # htons(0x0003) = ETH_P_ALL: capture ALL Ethernet protocol types
            #   htons() converts the protocol number to network byte order (big-endian).
            raw_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                     socket.htons(0x0003))
            return raw_sock, False

    except PermissionError:
        print("\n[ERROR] Permission denied!")
        print("  → Windows: Run this script as Administrator")
        print("  → Linux:   Run with 'sudo python3 step1_capture.py'")
        sys.exit(1)
    except OSError as e:
        print(f"\n[ERROR] Could not create raw socket: {e}")
        sys.exit(1)


def capture_one_packet(raw_sock):
    """
    Capture a single packet from the raw socket.
    
    recvfrom() blocks (waits) until a packet arrives on the NIC.
    It returns a tuple: (data_bytes, address_info)
    
    recvfrom(65535): 65535 is the maximum possible IP packet size.
    We use this buffer size to ensure we never truncate a packet.
    """
    print("[*] Waiting for a single packet... (generate some traffic!)")
    print("    Tip: Open a browser or run 'ping google.com' in another terminal.\n")

    # Block until one packet is received
    raw_data, addr = raw_sock.recvfrom(65535)

    return raw_data, addr


def display_raw_packet(raw_data, addr):
    """
    Display the raw packet bytes in a readable hex + ASCII format,
    similar to how Wireshark or xxd shows packet data.
    """
    print("=" * 60)
    print("  PACKET CAPTURED")
    print("=" * 60)
    print(f"  Total length : {len(raw_data)} bytes")
    print(f"  From address : {addr}")
    print()
    print("  RAW HEX DUMP:")
    print("  " + "-" * 56)

    # Print 16 bytes per row, with hex on the left and ASCII on the right
    for i in range(0, len(raw_data), 16):
        chunk = raw_data[i:i + 16]

        # Hex representation: each byte as 2-digit hex, space-separated
        hex_part = ' '.join(f'{b:02x}' for b in chunk)

        # ASCII representation: printable chars shown, others replaced with '.'
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)

        # Format: offset | hex bytes (padded to 48 chars) | ascii
        print(f"  {i:04x}  {hex_part:<47}  {ascii_part}")

    print("  " + "-" * 56)


def cleanup(raw_sock, is_windows):
    """Turn off promiscuous mode on Windows before closing."""
    if is_windows:
        raw_sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        print("\n[*] Promiscuous mode disabled.")
    raw_sock.close()
    print("[*] Socket closed.")


def main():
    print("=" * 60)
    print("  STEP 1: Network Packet Sniffer - Basic Capture")
    print("=" * 60)
    print()

    # 1. Create the raw socket
    raw_sock, is_windows = create_raw_socket()
    print("[*] Raw socket created successfully.")

    try:
        # 2. Capture exactly ONE packet
        raw_data, addr = capture_one_packet(raw_sock)

        # 3. Display the raw bytes
        display_raw_packet(raw_data, addr)

    finally:
        # 4. Always clean up: disable promiscuous mode and close socket
        cleanup(raw_sock, is_windows)

    print("\n[*] Done. In Step 2, we will parse the Ethernet frame headers.")


if __name__ == "__main__":
    main()
