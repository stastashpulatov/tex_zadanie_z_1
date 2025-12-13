#!/usr/bin/env python3
import socket
import sys

try:
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    print("✓ Raw socket created successfully!")
    s.close()
except PermissionError:
    print("✗ PermissionError: Root privileges required")
    sys.exit(1)
except Exception as e:
    print(f"✗ Error: {e}")
    sys.exit(1)
