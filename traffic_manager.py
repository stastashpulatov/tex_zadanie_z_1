import sys
import time
import json
import threading
from datetime import datetime
from collections import defaultdict, deque
import socket
import struct
import subprocess
import queue
import fcntl

class TrafficManager:
    def __init__(self):
        self.is_running = False
        self.blocked_ips = set()
        self.stats = {'total': 0, 'normal': 0, 'suspicious': 0, 'blocked': 0}
        self.icmp_counter = defaultdict(int)
        self.port_scan_counter = defaultdict(set)
        self.last_cleanup = time.time()
        self.settings = {
            'max_packet_size': 20,
            'check_suspicious_ports': True,
            'ddos_protection': True,
            'scan_detection': True
        }
        self.suspicious_ports = {23, 135, 139, 445, 3389, 5900, 1433, 3306} # Set for O(1) lookup
        self.packets_buffer = deque(maxlen=1000) # Deque for O(1) appends/pops
        self.packet_queue = queue.Queue()
        self.sniffer_thread = None
        
        # Buffer Deduplication for API/UI
        self.last_seen_flows = {} # Key: (src, dst), Value: timestamp
        self.flow_throttle_time = 0.8 
        self.pkt_id_counter = 0

    def start_sniffer(self):
        if self.sniffer_thread and self.sniffer_thread.is_alive():
            return
        
        self.is_running = True
        self.sniffer_thread = threading.Thread(target=self.sniff_traffic, daemon=True)
        self.sniffer_thread.start()

    def sniff_traffic(self):
        sys.stderr.write(f"[{datetime.now()}] Sniffer thread started\n")
        sys.stderr.flush()
        
        try:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            
            interface = "wlan0"
            try:
                s.bind((interface, 0))
            except Exception as e:
                sys.stderr.write(f"[{datetime.now()}] Warning: Failed to bind to {interface}: {e}. Trying default.\n")

            # Enable Promiscuous Mode
            try:
                ifreq = struct.pack('16sH14s', interface.encode('utf-8'), 0, b'\x00'*14)
                res = fcntl.ioctl(s.fileno(), 0x8913, ifreq) # SIOCGIFFLAGS
                flags = struct.unpack('16sH14s', res)[1]
                
                new_flags = flags | 0x100
                ifreq = struct.pack('16sH14s', interface.encode('utf-8'), new_flags, b'\x00'*14)
                fcntl.ioctl(s.fileno(), 0x8914, ifreq) # SIOCSIFFLAGS
            except Exception as e:
                sys.stderr.write(f"[{datetime.now()}] Warning: Promiscuous mode failed: {e}\n")

        except PermissionError:
            print("Error: Root privileges required for raw sockets.")
            self.is_running = False
            return
        except Exception as e:
            print(f"Socket error: {e}")
            self.is_running = False
            return

        sys.stderr.write(f"[{datetime.now()}] Socket created. Capturing...\n")
        
        packet_count = 0
        last_log = time.time()
        
        while self.is_running:
            try:
                raw_data, addr = s.recvfrom(65535)
                packet_count += 1
                packet = self.parse_packet(raw_data)
                
                if packet:
                    self.packet_queue.put(packet)
                    
                # Optimized Logging: Log only every 5 seconds instead of every 100 packets
                now = time.time()
                if now - last_log > 5:
                     sys.stderr.write(f"[{datetime.now()}] Captured {packet_count} packets...\n")
                     sys.stderr.flush()
                     last_log = now
                        
            except Exception as e:
                continue
        
        s.close()
        sys.stderr.write(f"[{datetime.now()}] Sniffer stopped.\n")

    def get_mac_addr(self, bytes_addr):
        bytes_str = map('{:02x}'.format, bytes_addr)
        return ':'.join(bytes_str).upper()

    def parse_packet(self, raw_data):
        eth_len = 14
        if len(raw_data) < eth_len:
            return None
            
        # Optimization: Only unpack what we need initially
        # protocol_num = struct.unpack('!H', raw_data[12:14])[0] # Slower than full unpack?
        eth_header = raw_data[:eth_len]
        eth = struct.unpack('!6s6sH', eth_header)
        protocol_num = eth[2] 

        if protocol_num == 0x0800: # IPv4
            ip_header = raw_data[eth_len:20+eth_len]
            if len(ip_header) < 20: 
                return None
                
            iph = struct.unpack('!BBHHHBBH4s4s', ip_header)

            version_ihl = iph[0]
            ihl = version_ihl & 0xF
            iph_length = ihl * 4

            protocol = iph[6]
            s_addr = socket.inet_ntoa(iph[8])
            d_addr = socket.inet_ntoa(iph[9])

            if s_addr.startswith('127.') or d_addr.startswith('127.'):
                return None
            
            protocol_name = "OTHER"
            src_port = 0
            dst_port = 0
            
            packet_size = len(raw_data)
            payload_start = eth_len + iph_length
            
            if protocol == 6: # TCP
                if len(raw_data) >= payload_start + 20:
                    protocol_name = "TCP"
                    tcp_header = raw_data[payload_start:payload_start+20]
                    tcph = struct.unpack('!HHLLBBHHH', tcp_header)
                    src_port = tcph[0]
                    dst_port = tcph[1]
            elif protocol == 17: # UDP
                 if len(raw_data) >= payload_start + 8:
                    protocol_name = "UDP"
                    udp_header = raw_data[payload_start:payload_start+8]
                    udph = struct.unpack('!HHHH', udp_header)
                    src_port = udph[0]
                    dst_port = udph[1]
            elif protocol == 1: # ICMP
                protocol_name = "ICMP"
                
            return {
                'timestamp': datetime.now().strftime('%H:%M:%S'),
                'src_ip': s_addr,
                'dst_ip': d_addr,
                'protocol': protocol_name,
                'src_port': src_port,
                'dst_port': dst_port,
                'size': packet_size,
                'id': int(time.time() * 1000) + self.pkt_id_counter
            }
        return None

    def analyze_packet(self, packet):
        threats = []
        if not packet:
            return []

        if packet['size'] > self.settings['max_packet_size']:
            threats.append(f"Размер {packet['size']} > {self.settings['max_packet_size']} байт")
        
        if self.settings['check_suspicious_ports'] and packet['dst_port'] in self.suspicious_ports:
            threats.append(f"Подозрительный порт {packet['dst_port']}")
        
        if self.settings['ddos_protection'] and packet['protocol'] == 'ICMP':
            self.icmp_counter[packet['src_ip']] += 1
            if self.icmp_counter[packet['src_ip']] > 50:
                threats.append("ICMP flood атака")
        
        if self.settings['scan_detection'] and packet['dst_port'] > 0:
            self.port_scan_counter[packet['src_ip']].add(packet['dst_port'])
            if len(self.port_scan_counter[packet['src_ip']]) > 20:
                threats.append("Сканирование портов")
        
        return threats
    
    def process_packet(self):
        current_time = time.time()
        
        # Periodic cleanup (every 60s)
        if current_time - self.last_cleanup > 60:
            self.icmp_counter.clear()
            self.port_scan_counter.clear()
            
            # Cleanup last_seen_flows to prevent memory leak
            # Remove entries older than 5 seconds (far longer than throttle time)
            self.last_seen_flows = {k: v for k, v in self.last_seen_flows.items() if current_time - v < 5}
            
            self.last_cleanup = current_time
        
        try:
            packet = self.packet_queue.get_nowait()
        except queue.Empty:
            return None, []
            
        threats = self.analyze_packet(packet)
        
        is_blocked = (packet['src_ip'] in self.blocked_ips) or (packet['dst_ip'] in self.blocked_ips)
        is_suspicious = len(threats) > 0
        
        status = 'normal'
        tag = 'normal'

        if is_blocked:
            status = 'blocked'
            tag = 'blocked'
        elif is_suspicious:
            status = 'suspicious'
            tag = 'suspicious'
        
        self.stats['total'] += 1
        self.stats[status] += 1
        
        # Buffer FLOW DEDUPLICATION
        flow_key = (packet['src_ip'], packet['dst_ip'])
        
        should_buffer = False
        
        if is_blocked or is_suspicious or packet['protocol'] == 'ICMP':
            should_buffer = True
        else:
            last_seen = self.last_seen_flows.get(flow_key, 0)
            if current_time - last_seen > self.flow_throttle_time:
                should_buffer = True
                self.last_seen_flows[flow_key] = current_time
        
        if should_buffer:
            self.pkt_id_counter += 1 
            packet['status'] = status.upper()
            packet['threats'] = threats
            packet['tag'] = tag
            
            # Deque handles maxlen automatically, O(1)
            self.packets_buffer.append(packet)

        return packet, threats

    def block_ip(self, ip):
        if ip not in self.blocked_ips:
            self.blocked_ips.add(ip)
            try:
                subprocess.run(['sudo', 'iptables', '-I', 'INPUT', '1', '-s', ip, '-j', 'DROP'], check=False)
                subprocess.run(['sudo', 'iptables', '-I', 'OUTPUT', '1', '-d', ip, '-j', 'DROP'], check=False)
            except Exception as e:
                print(f"Failed to execute iptables: {e}")
            return True
        return False

    def unblock_ip(self, ip):
        if ip in self.blocked_ips:
            self.blocked_ips.discard(ip)
            try:
                subprocess.run(['sudo', 'iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'], check=False)
                subprocess.run(['sudo', 'iptables', '-D', 'OUTPUT', '-d', ip, '-j', 'DROP'], check=False)
            except Exception as e:
                print(f"Failed to execute iptables: {e}")
            return True
        return False

traffic_manager = TrafficManager()
