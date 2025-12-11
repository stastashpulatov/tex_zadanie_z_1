import os
import sys

def verify_environment():
    print("Verifying environment for Real Network Monitoring...")
    
    # 1. Check Root
    if os.geteuid() != 0:
        print("[!] WARNING: Not running as root.")
        print("    The application requires root privileges to:")
        print("    - Open Raw Sockets (Sniff traffic)")
        print("    - Modify iptables (Block IPs)")
        print("\n    Please run with: sudo python3 main.py")
        return False
        
    print("[+] Running as root. Permissions OK.")
    
    # 2. Check iptables availability
    exit_code = os.system("iptables -L -n > /dev/null 2>&1")
    if exit_code != 0:
        print("[!] WARNING: 'iptables' command not found or failed.")
        return False
        
    print("[+] iptables found.")
    print("\nVerification passed. You can run the main application.")
    return True

if __name__ == "__main__":
    verify_environment()
