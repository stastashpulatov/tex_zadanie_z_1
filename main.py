import tkinter as tk
import sys
from tkinter import ttk, scrolledtext, messagebox, filedialog
import random
import time
import json
import threading
from datetime import datetime
from collections import defaultdict
import http.server
import socketserver
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
            'max_packet_size': 1500,
            'check_suspicious_ports': True,
            'ddos_protection': True,
            'scan_detection': True
        }
        self.suspicious_ports = [23, 135, 139, 445, 3389, 5900, 1433, 3306]
        self.packets_buffer = [] 
        self.packet_queue = queue.Queue()
        self.suspicious_ports = [23, 135, 139, 445, 3389, 5900, 1433, 3306]
        self.packets_buffer = [] 
        self.packet_queue = queue.Queue()
        self.sniffer_thread = None
        
        # UI Deduplication
        self.last_seen_flows = {} # Key: (src, dst), Value: timestamp
        self.flow_throttle_time = 0.8 # Seconds between duplicate log entries
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
            # Create a raw socket to listen to all traffic
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            
            # Bind to wlan0 explicitly
            interface = "wlan0"
            try:
                s.bind((interface, 0))
                sys.stderr.write(f"[{datetime.now()}] Bound to interface: {interface}\n")
            except Exception as e:
                sys.stderr.write(f"[{datetime.now()}] Warning: Failed to bind to {interface}: {e}. Trying default.\n")

            # Enable Promiscuous Mode
            try:
                import ctypes
                # IFF_PROMISC = 0x100
                # SIOCGIFFLAGS = 0x8913
                # SIOCSIFFLAGS = 0x8914
                
                # Get current flags
                ifreq = struct.pack('16sH14s', interface.encode('utf-8'), 0, b'\x00'*14)
                res = fcntl.ioctl(s.fileno(), 0x8913, ifreq) # SIOCGIFFLAGS
                flags = struct.unpack('16sH14s', res)[1]
                
                # Add Promiscuous flag
                new_flags = flags | 0x100
                ifreq = struct.pack('16sH14s', interface.encode('utf-8'), new_flags, b'\x00'*14)
                fcntl.ioctl(s.fileno(), 0x8914, ifreq) # SIOCSIFFLAGS
                
                sys.stderr.write(f"[{datetime.now()}] Promiscuous mode ENABLED on {interface}\n")
            except Exception as e:
                sys.stderr.write(f"[{datetime.now()}] Warning: Failed to enable promiscuous mode: {e}\n")

        except PermissionError:
            sys.stderr.write(f"[{datetime.now()}] ERROR: PermissionError (Need sudo)\n")
            sys.stderr.flush()
            print("Error: Root privileges required for raw sockets.")
            self.is_running = False
            return
        except Exception as e:
            sys.stderr.write(f"[{datetime.now()}] ERROR: Socket creation failed: {e}\n")
            sys.stderr.flush()
            print(f"Socket error: {e}")
            self.is_running = False
            return

        sys.stderr.write(f"[{datetime.now()}] Socket created successfully. Loop starting.\n")
        sys.stderr.flush()

        packet_count = 0
        while self.is_running:
            try:
                raw_data, addr = s.recvfrom(65535)
                packet_count += 1
                packet = self.parse_packet(raw_data)
                
                if packet:
                    self.packet_queue.put(packet)
                    
                if packet_count % 100 == 0:
                     sys.stderr.write(f"[{datetime.now()}] Captured {packet_count} packets. Last: {packet['protocol'] if packet else 'Dropped'}\n")
                     sys.stderr.flush()
                        
            except Exception as e:
                sys.stderr.write(f"[{datetime.now()}] Loop error: {e}\n")
                sys.stderr.flush()
                continue
        
        s.close()
        sys.stderr.write(f"[{datetime.now()}] Sniffer stopped.\n")

    def get_mac_addr(self, bytes_addr):
        bytes_str = map('{:02x}'.format, bytes_addr)
        return ':'.join(bytes_str).upper()

    def parse_packet(self, raw_data):
        # Ethernet Header (14 bytes)
        eth_len = 14
        if len(raw_data) < eth_len:
            return None
            
        eth_header = raw_data[:eth_len]
        eth = struct.unpack('!6s6sH', eth_header)
        # eth[2] is the protocol in Network Byte Order (Big Endian)
        # IPv4 is 0x0800 (2048)
        # ARP is 0x0806 (2054)
        protocol_num = eth[2] 

        # Parse IP packets (Eth Protocol 0x0800)
        # Using exact hex comparison to be safe against endian confusion
        if protocol_num == 0x0800:
            # IP Header (Variable length, usually 20 bytes)
            ip_header = raw_data[eth_len:20+eth_len]
            if len(ip_header) < 20: 
                return None
                
            iph = struct.unpack('!BBHHHBBH4s4s', ip_header)

            version_ihl = iph[0]
            # version = version_ihl >> 4
            ihl = version_ihl & 0xF
            iph_length = ihl * 4

            protocol = iph[6]
            s_addr = socket.inet_ntoa(iph[8])
            d_addr = socket.inet_ntoa(iph[9])

            # Filter Loopback / Localhost noise
            if s_addr.startswith('127.') or d_addr.startswith('127.'):
                return None
            
            # Transport Layer Parsing
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
            if self.icmp_counter[packet['src_ip']] > 50: # Increased threshold for real traffic
                threats.append("ICMP flood атака")
        
        if self.settings['scan_detection'] and packet['dst_port'] > 0:
            self.port_scan_counter[packet['src_ip']].add(packet['dst_port'])
            if len(self.port_scan_counter[packet['src_ip']]) > 20: # Increased threshold
                threats.append("Сканирование портов")
        
        return threats
    
    def process_packet(self):
        if time.time() - self.last_cleanup > 60:
            self.icmp_counter.clear()
            self.port_scan_counter.clear()
            self.last_cleanup = time.time()
        
        try:
            # Non-blocking get from queue
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
        
        # UI FLOW DEDUPLICATION LOGIC
        # We process stats for EVERY packet, but only show unique flows in the UI table
        # to prevent it from scrolling too fast to read.
        
        flow_key = (packet['src_ip'], packet['dst_ip'])
        current_time = time.time()
        
        should_log_to_ui = False
        
        # Always log suspicious, blocked, OR ICMP (Ping) packets
        if is_blocked or is_suspicious or packet['protocol'] == 'ICMP':
            should_log_to_ui = True
        else:
            # For normal packets, throttle them
            last_seen = self.last_seen_flows.get(flow_key, 0)
            if current_time - last_seen > self.flow_throttle_time:
                should_log_to_ui = True
                self.last_seen_flows[flow_key] = current_time
        
        if should_log_to_ui:
            self.pkt_id_counter += 1 # Increment ID counter to ensure uniqueness
            packet['status'] = status.upper()
            packet['threats'] = threats
            packet['tag'] = tag
            self.packets_buffer.append(packet)
            
            # Keep buffer small
            if len(self.packets_buffer) > 1000:
                self.packets_buffer.pop(0)

        return packet, threats

    def block_ip(self, ip):
        # Always add to internal set for UI sync
        if ip not in self.blocked_ips:
            self.blocked_ips.add(ip)
            # Execute real blocking
            try:
                # Block INPUT and OUTPUT
                subprocess.run(['sudo', 'iptables', '-I', 'INPUT', '1', '-s', ip, '-j', 'DROP'], check=False)
                subprocess.run(['sudo', 'iptables', '-I', 'OUTPUT', '1', '-d', ip, '-j', 'DROP'], check=False)
            except Exception as e:
                print(f"Failed to execute iptables: {e}")
            return True
        return False

    def unblock_ip(self, ip):
        if ip in self.blocked_ips:
            self.blocked_ips.discard(ip)
            # Execute real unblocking
            try:
                # Allow failure if rule doesn't exist
                subprocess.run(['sudo', 'iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'], check=False)
                subprocess.run(['sudo', 'iptables', '-D', 'OUTPUT', '-d', ip, '-j', 'DROP'], check=False)
            except Exception as e:
                print(f"Failed to execute iptables: {e}")
            return True
        return False

# Global instance for API
traffic_manager = TrafficManager()

class NetworkTrafficAnalyzer:
    def __init__(self, root):
        self.root = root
        self.root.title("Анализатор сетевого трафика")
        self.root.geometry("1600x1000")
        self.root.minsize(1200, 800)
        
        self.manager = traffic_manager # Use the global manager
        
        self.colors = {
            'bg': '#0b132b',
            'header': '#0f1e3a',
            'card': '#16213e',
            'card_border': '#1f2f4a',
            'accent': '#4fd1c5',
            'text': '#e6ecf4',
            'text_muted': '#8fa1c1',
            'success': '#6ed39e',
            'info': '#5aa9fa',
            'warning': '#f0b75a',
            'danger': '#ef6b6b',
            'table_bg': '#131f33',
            'table_header': '#1c2a42',
            'primary': '#4299e1'
        }
        
        self.root.configure(bg=self.colors['bg'])
        
        self.manual_ip = tk.StringVar()
        self.selected_ip_display = tk.StringVar(value="Не выбран")
        self.block_target = tk.StringVar(value="src")
        self.selected_packet = None
        
        self.settings = {
            'max_packet_size': tk.IntVar(value=1500),
            'check_suspicious_ports': tk.BooleanVar(value=True),
            'ddos_protection': tk.BooleanVar(value=True),
            'scan_detection': tk.BooleanVar(value=True)
        }
        
        self.setup_styles()
        self.init_ui()
    
    def setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        
        style.configure('Header.TFrame', background=self.colors['header'])
        style.configure('Card.TFrame', background=self.colors['card'])
        style.configure('TLabel', background=self.colors['card'], foreground=self.colors['text'])
        style.configure('Header.TLabel', background=self.colors['header'], foreground=self.colors['text'], font=('Segoe UI', 24, 'bold'))
        style.configure('SubHeader.TLabel', background=self.colors['header'], foreground=self.colors['text_muted'], font=('Segoe UI', 12))
        style.configure('Section.TLabel', background=self.colors['card'], foreground=self.colors['text'], font=('Segoe UI', 14, 'bold'))
        
        style.configure('Success.TButton', background=self.colors['success'], foreground='white')
        style.configure('Primary.TButton', background=self.colors['info'], foreground='white')
        style.configure('Danger.TButton', background=self.colors['danger'], foreground='white')
        
        style.configure('Treeview', background=self.colors['table_bg'], foreground=self.colors['text'], fieldbackground=self.colors['table_bg'], rowheight=26)
        style.configure('Treeview.Heading', background=self.colors['table_header'], foreground=self.colors['text'], font=('Segoe UI', 10, 'bold'))
        style.map('Treeview', background=[('selected', self.colors['accent'])])
    
    def init_ui(self):
        header_frame = tk.Frame(self.root, bg=self.colors['header'], pady=20)
        header_frame.pack(fill='x')
        
        title_label = tk.Label(header_frame, text="🛡️ Анализатор сетевого трафика", font=('Segoe UI', 28, 'bold'), bg=self.colors['header'], fg=self.colors['accent'])
        title_label.pack()
        
        subtitle_label = tk.Label(header_frame, text="Обнаружение и блокировка подозрительной активности", font=('Segoe UI', 12), bg=self.colors['header'], fg=self.colors['text_muted'])
        subtitle_label.pack()
        
        main_container = tk.Frame(self.root, bg=self.colors['bg'], padx=20, pady=20)
        main_container.pack(fill='both', expand=True)
        
        self.create_stats_panel(main_container)
        self.create_control_panel(main_container)
        self.create_data_panel(main_container)
    
    def create_stats_panel(self, parent):
        stats_frame = tk.Frame(parent, bg=self.colors['bg'])
        stats_frame.pack(fill='x', pady=(0, 20))
        
        stats_data = [
            ('📊', 'Всего пакетов', 'total', self.colors['info']),
            ('✅', 'Нормальных', 'normal', self.colors['success']),
            ('⚠️', 'Подозрительных', 'suspicious', self.colors['warning']),
            ('🚫', 'Заблокировано', 'blocked', self.colors['danger'])
        ]
        
        self.stat_labels = {}
        for icon, label_text, key, color in stats_data:
            card = tk.Frame(stats_frame, bg=self.colors['card'], relief='flat', highlightbackground=self.colors['card_border'], highlightthickness=1, padx=20, pady=15)
            card.pack(side='left', fill='both', expand=True, padx=5)
            
            icon_label = tk.Label(card, text=icon, font=('Segoe UI', 32), bg=self.colors['card'], fg=color)
            icon_label.pack(side='left', padx=(0, 15))
            
            info_frame = tk.Frame(card, bg=self.colors['card'])
            info_frame.pack(side='left', fill='both', expand=True)
            
            tk.Label(info_frame, text=label_text, font=('Segoe UI', 11), bg=self.colors['card'], fg=self.colors['text_muted']).pack(anchor='w')
            
            stat_label = tk.Label(info_frame, text='0', font=('Segoe UI', 36, 'bold'), bg=self.colors['card'], fg=color)
            stat_label.pack(anchor='w')
            self.stat_labels[key] = stat_label
    
    def create_control_panel(self, parent):
        control_frame = tk.Frame(parent, bg=self.colors['bg'])
        control_frame.pack(fill='x', pady=(0, 20))
        
        left_card = tk.Frame(control_frame, bg=self.colors['card'], relief='flat', highlightbackground=self.colors['card_border'], highlightthickness=1, padx=20, pady=15)
        left_card.pack(side='left', fill='both', expand=True, padx=(0, 10))
        
        tk.Label(left_card, text="Управление мониторингом", font=('Segoe UI', 14, 'bold'), bg=self.colors['card'], fg=self.colors['text']).pack(pady=(0, 15))
        
        btn_frame = tk.Frame(left_card, bg=self.colors['card'])
        btn_frame.pack()
        
        self.start_btn = tk.Button(btn_frame, text="▶ Запустить", font=('Segoe UI', 12, 'bold'), bg=self.colors['success'], fg='white', activebackground=self.colors['success'], activeforeground='white', relief='flat', padx=20, pady=10, cursor='hand2', command=self.toggle_monitoring)
        self.start_btn.pack(side='left', padx=5)
        
        tk.Button(btn_frame, text="💾 Экспорт", font=('Segoe UI', 12, 'bold'), bg=self.colors['info'], fg='white', activebackground=self.colors['info'], activeforeground='white', relief='flat', padx=20, pady=10, cursor='hand2', command=self.export_data).pack(side='left', padx=5)
        
        right_card = tk.Frame(control_frame, bg=self.colors['card'], relief='flat', highlightbackground=self.colors['card_border'], highlightthickness=1, padx=20, pady=15)
        right_card.pack(side='left', fill='both', expand=True, padx=(10, 0))
        
        tk.Label(right_card, text="Правила обнаружения", font=('Segoe UI', 14, 'bold'), bg=self.colors['card'], fg=self.colors['text']).pack(pady=(0, 15))
        
        rules_frame = tk.Frame(right_card, bg=self.colors['card'])
        rules_frame.pack(fill='x')
        
        tk.Checkbutton(rules_frame, text="Проверка подозрительных портов", variable=self.settings['check_suspicious_ports'], font=('Segoe UI', 11), bg=self.colors['card'], fg=self.colors['text'], selectcolor=self.colors['bg'], activebackground=self.colors['card'], activeforeground=self.colors['text']).pack(anchor='w', pady=5)
        tk.Checkbutton(rules_frame, text="Защита от DDoS атак (ICMP flood)", variable=self.settings['ddos_protection'], font=('Segoe UI', 11), bg=self.colors['card'], fg=self.colors['text'], selectcolor=self.colors['bg'], activebackground=self.colors['card'], activeforeground=self.colors['text']).pack(anchor='w', pady=5)
        tk.Checkbutton(rules_frame, text="Обнаружение сканирования портов", variable=self.settings['scan_detection'], font=('Segoe UI', 11), bg=self.colors['card'], fg=self.colors['text'], selectcolor=self.colors['bg'], activebackground=self.colors['card'], activeforeground=self.colors['text']).pack(anchor='w', pady=5)
        
        size_frame = tk.Frame(rules_frame, bg=self.colors['card'])
        size_frame.pack(anchor='w', pady=10)
        
        tk.Label(size_frame, text="Макс. размер пакета (байт):", font=('Segoe UI', 11), bg=self.colors['card'], fg=self.colors['text']).pack(side='left')
        tk.Spinbox(size_frame, from_=500, to=5000, textvariable=self.settings['max_packet_size'], width=10, font=('Segoe UI', 11), bg=self.colors['table_bg'], fg=self.colors['text'], buttonbackground=self.colors['card_border']).pack(side='left', padx=10)
    
    def create_data_panel(self, parent):
        data_frame = tk.Frame(parent, bg=self.colors['bg'])
        data_frame.pack(fill='both', expand=True)
        
        left_card = tk.Frame(data_frame, bg=self.colors['card'], relief='flat', highlightbackground=self.colors['card_border'], highlightthickness=1, padx=15, pady=15)
        left_card.pack(side='left', fill='both', expand=True, padx=(0, 10))
        
        tk.Label(left_card, text="Перехваченные пакеты", font=('Segoe UI', 14, 'bold'), bg=self.colors['card'], fg=self.colors['text']).pack(pady=(0, 10))
        
        table_frame = tk.Frame(left_card, bg=self.colors['card'])
        table_frame.pack(fill='both', expand=True)
        
        scrollbar_y = ttk.Scrollbar(table_frame, orient='vertical')
        scrollbar_y.pack(side='right', fill='y')
        
        self.packets_tree = ttk.Treeview(table_frame, columns=('time', 'src', 'dst', 'protocol', 'port', 'size', 'status'), show='headings', yscrollcommand=scrollbar_y.set, height=12)
        scrollbar_y.config(command=self.packets_tree.yview)
        
        columns = [('time', 'Время', 80), ('src', 'IP источника', 130), ('dst', 'IP назначения', 130), ('protocol', 'Протокол', 90), ('port', 'Порт', 70), ('size', 'Размер', 80), ('status', 'Статус', 120)]
        for col, heading, width in columns:
            self.packets_tree.heading(col, text=heading)
            self.packets_tree.column(col, width=width)
        
        self.packets_tree.pack(fill='both', expand=True)
        self.packets_tree.tag_configure('normal', background=self.colors['table_bg'])
        self.packets_tree.tag_configure('suspicious', background='#2a2415')
        self.packets_tree.tag_configure('blocked', background='#2a1515')
        
        self.packets_tree.bind('<<TreeviewSelect>>', self.on_packet_select)
        
        controls_frame = tk.Frame(left_card, bg=self.colors['card'])
        controls_frame.pack(fill='x', pady=10)
        
        tk.Button(controls_frame, text="📋 Копировать IP", font=('Segoe UI', 11, 'bold'), bg=self.colors['primary'], fg='white', activebackground=self.colors['primary'], activeforeground='white', relief='flat', padx=15, pady=8, cursor='hand2', command=self.copy_selected_ip).pack(anchor='w', pady=(0, 10))
        tk.Button(controls_frame, text="🚫 Блокировать IP", font=('Segoe UI', 11, 'bold'), bg=self.colors['danger'], fg='white', activebackground=self.colors['danger'], activeforeground='white', relief='flat', padx=15, pady=8, cursor='hand2', command=self.block_manual_ip).pack(anchor='w', pady=(0, 10))
        
        ip_control_frame = tk.Frame(controls_frame, bg=self.colors['card'])
        ip_control_frame.pack(fill='x', pady=5)
        
        tk.Label(ip_control_frame, text="Выбранный IP:", font=('Segoe UI', 11), bg=self.colors['card'], fg=self.colors['text_muted']).pack(anchor='w')
        
        target_frame = tk.Frame(ip_control_frame, bg=self.colors['card'])
        target_frame.pack(anchor='w', pady=(2, 6))
        tk.Radiobutton(target_frame, text="IP источника", variable=self.block_target, value="src", font=('Segoe UI', 10), bg=self.colors['card'], fg=self.colors['text'], selectcolor=self.colors['bg'], activebackground=self.colors['card'], activeforeground=self.colors['text'], command=self.update_selected_ip_display).pack(side='left', padx=(0, 10))
        tk.Radiobutton(target_frame, text="IP назначения", variable=self.block_target, value="dst", font=('Segoe UI', 10), bg=self.colors['card'], fg=self.colors['text'], selectcolor=self.colors['bg'], activebackground=self.colors['card'], activeforeground=self.colors['text'], command=self.update_selected_ip_display).pack(side='left')
        
        tk.Label(ip_control_frame, textvariable=self.selected_ip_display, font=('Courier New', 12, 'bold'), bg=self.colors['card'], fg=self.colors['text']).pack(anchor='w', pady=(0, 8))
        
        manual_frame = tk.Frame(controls_frame, bg=self.colors['card'])
        manual_frame.pack(fill='x', pady=5)
        
        tk.Label(manual_frame, text="Введите IP для блокировки", font=('Segoe UI', 11), bg=self.colors['card'], fg=self.colors['text']).pack(anchor='w')
        
        entry_btn_frame = tk.Frame(manual_frame, bg=self.colors['card'])
        entry_btn_frame.pack(fill='x', pady=(5, 0))
        
        ip_entry = tk.Entry(entry_btn_frame, textvariable=self.manual_ip, font=('Courier New', 12), bg=self.colors['table_bg'], fg=self.colors['text'], relief='flat', insertbackground=self.colors['text'])
        ip_entry.pack(side='left', fill='x', expand=True, padx=(0, 8))
        
        tk.Button(entry_btn_frame, text="🚫 Блокировать IP", font=('Segoe UI', 11, 'bold'), bg=self.colors['danger'], fg='white', activebackground=self.colors['danger'], activeforeground='white', relief='flat', padx=12, pady=6, cursor='hand2', command=self.block_manual_ip).pack(side='left')
        
        right_card = tk.Frame(data_frame, bg=self.colors['card'], relief='flat', highlightbackground=self.colors['card_border'], highlightthickness=1, padx=15, pady=15)
        right_card.pack(side='left', fill='both', expand=True, padx=(10, 0))
        
        tk.Label(right_card, text="Журнал событий", font=('Segoe UI', 14, 'bold'), bg=self.colors['card'], fg=self.colors['text']).pack(pady=(0, 10))
        
        self.log_text = scrolledtext.ScrolledText(right_card, height=15, bg=self.colors['table_bg'], fg=self.colors['text'], font=('Courier New', 10), wrap=tk.WORD, insertbackground=self.colors['text'], relief='flat')
        self.log_text.pack(fill='both', expand=True, pady=(0, 15))
        
        tk.Label(right_card, text="Заблокированные IP", font=('Segoe UI', 14, 'bold'), bg=self.colors['card'], fg=self.colors['text']).pack(pady=(0, 10))
        
        blocked_frame = tk.Frame(right_card, bg=self.colors['card'])
        blocked_frame.pack(fill='both', expand=True, pady=(0, 10))
        
        scrollbar_blocked = ttk.Scrollbar(blocked_frame, orient='vertical')
        scrollbar_blocked.pack(side='right', fill='y')
        
        self.blocked_listbox = tk.Listbox(blocked_frame, bg=self.colors['table_bg'], fg=self.colors['danger'], font=('Courier New', 11), yscrollcommand=scrollbar_blocked.set, relief='flat', selectbackground=self.colors['danger'], selectforeground='white')
        scrollbar_blocked.config(command=self.blocked_listbox.yview)
        self.blocked_listbox.pack(fill='both', expand=True)
        
        tk.Button(right_card, text="✓ Разблокировать выбранный", font=('Segoe UI', 11, 'bold'), bg=self.colors['success'], fg='white', activebackground=self.colors['success'], activeforeground='white', relief='flat', padx=15, pady=8, cursor='hand2', command=self.unblock_selected_ip).pack()
    
    def on_packet_select(self, event):
        selection = self.packets_tree.selection()
        if selection:
            self.selected_packet = selection[0]
            self.update_selected_ip_display()
    
    def toggle_monitoring(self):
        self.manager.is_running = not self.manager.is_running
        if self.manager.is_running:
            self.manager.start_sniffer() # Start the raw socket sniffer
            self.start_btn.config(text="⏸ Остановить", bg=self.colors['danger'])
            self.add_log("▶️ Мониторинг запущен")
            self.monitoring_thread = threading.Thread(target=self.monitoring_loop, daemon=True)
            self.monitoring_thread.start()
        else:
            self.start_btn.config(text="▶ Запустить", bg=self.colors['success'])
            self.add_log("⏹️ Мониторинг остановлен")
    
    def monitoring_loop(self):
        while self.manager.is_running:
            packet, threats = self.manager.process_packet()
            
            if packet: # Only update if we got a packet
                # Update UI
                self.packets_tree.insert('', 0, values=(packet['timestamp'], packet['src_ip'], packet['dst_ip'], packet['protocol'], packet['dst_port'], f"{packet['size']} B", packet['status']), tags=(packet['tag'],))
                
                children = self.packets_tree.get_children()
                if len(children) > 100:
                    self.packets_tree.delete(children[-1])
                
                if packet['tag'] == 'suspicious':
                    self.add_log(f"⚠️ Подозрительный пакет от {packet['src_ip']}: {', '.join(threats)}")
                elif packet['tag'] == 'blocked':
                    self.add_log(f"🛡️ Заблокирован пакет от {packet['src_ip']}")
                
                self.update_stats_display()
            else:
                time.sleep(0.1) # Sleep briefly if no packets to avoid busy loop
            

    def update_stats_display(self):
        for key, label in self.stat_labels.items():
            label.config(text=str(self.manager.stats[key]))
    
    def copy_selected_ip(self):
        if not self.selected_packet:
            messagebox.showwarning("Внимание", "Выберите пакет для копирования IP")
            return
        item = self.packets_tree.item(self.selected_packet)
        target_ip = item['values'][1] if self.block_target.get() == "src" else item['values'][2]
        self.root.clipboard_clear()
        self.root.clipboard_append(target_ip)
        self.add_log(f"📋 IP адрес {target_ip} скопирован в буфер обмена")
    
    def block_manual_ip(self):
        ip = self.manual_ip.get().strip()
        if not ip:
            messagebox.showwarning("Внимание", "Введите IP для блокировки")
            return
        if self.manager.block_ip(ip):
            self.blocked_listbox.insert(0, ip)
            self.selected_ip_display.set(ip)
            self.add_log(f"🚫 IP адрес {ip} заблокирован")
            messagebox.showinfo("Успех", f"IP адрес {ip} заблокирован")
        else:
            messagebox.showinfo("Информация", f"IP адрес {ip} уже заблокирован")
    
    def update_selected_ip_display(self):
        selection = self.packets_tree.selection()
        if not selection:
            self.selected_ip_display.set("Не выбран")
            return
        item = self.packets_tree.item(selection[0])
        target_ip = item['values'][1] if self.block_target.get() == "src" else item['values'][2]
        self.selected_ip_display.set(target_ip)
        self.manual_ip.set(target_ip)
    
    def unblock_selected_ip(self):
        selection = self.blocked_listbox.curselection()
        if not selection:
            messagebox.showwarning("Внимание", "Выберите IP для разблокировки")
            return
        ip = self.blocked_listbox.get(selection[0])
        if self.manager.unblock_ip(ip):
            self.blocked_listbox.delete(selection[0])
            self.add_log(f"✓ IP адрес {ip} разблокирован")
            messagebox.showinfo("Успех", f"IP адрес {ip} разблокирован")
            
    def add_log(self, message):
        timestamp = datetime.now().strftime('%H:%M:%S')
        self.log_text.insert('1.0', f"[{timestamp}] {message}\n")
        lines = self.log_text.get('1.0', tk.END).split('\n')
        if len(lines) > 100:
            self.log_text.delete(f"{len(lines)-100}.0", tk.END)
            
    def export_data(self):
        filename = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json"), ("All files", "*.*")], initialfile=f"traffic_analysis_{int(time.time())}.json")
        if filename:
            data = {
                'stats': self.manager.stats,
                'blocked_ips': list(self.manager.blocked_ips),
                'timestamp': datetime.now().isoformat()
            }
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            self.add_log(f"💾 Данные экспортированы в {filename}")
            messagebox.showinfo("Успех", f"Данные сохранены в файл:\n{filename}")

def main():
    root = tk.Tk()
    app = NetworkTrafficAnalyzer(root)
    root.mainloop()

if __name__ == "__main__":
    main()
