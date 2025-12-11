import socket
import struct
import os
import sys

def debug_sniff():
    if os.geteuid() != 0:
        print("Error: Must run as root (sudo).")
        return

    print("Creating raw socket...")
    try:
        # ETH_P_ALL = 3
        # Use htons to convert to network byte order
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    except Exception as e:
        print(f"Failed to create socket: {e}")
        return

    print("Socket created. Listening for packets (Ctrl+C to stop)...")
    
    count = 0
    while True:
        try:
            raw_data, addr = s.recvfrom(65535)
            count += 1
            
            eth_len = 14
            eth_header = raw_data[:eth_len]
            eth = struct.unpack('!6s6sH', eth_header)
            
            # Protocol is already unpacked as BigEndian integer by '!'
            # So 0x0800 (IP) is 2048
            protocol = eth[2]
            
            print(f"\nPacket #{count}")
            print(f"  Raw Protocol value: {protocol:#06x} ({protocol})")
            
            if protocol == 0x0800:
                print("  Type: IPv4")
                
                ip_header = raw_data[eth_len:20+eth_len]
                iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
                s_addr = socket.inet_ntoa(iph[8])
                d_addr = socket.inet_ntoa(iph[9])
                print(f"  Src: {s_addr} -> Dst: {d_addr}")
            elif protocol == 0x0806:
                print("  Type: ARP")
            elif protocol == 0x86DD:
                print("  Type: IPv6")
            else:
                print("  Type: Other")
                
            if count >= 10:
                print("\nCaptured 10 packets. Sniffer is WORKING.")
                break
                
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"Error receiving: {e}")
            break
            
    s.close()

if __name__ == "__main__":
    debug_sniff()
