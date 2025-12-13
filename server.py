import http.server
import sys
import socketserver
import json
from traffic_manager import traffic_manager
import threading
import time
from datetime import datetime

PORT = 5000

class TrafficRequestHandler(http.server.BaseHTTPRequestHandler):
    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

    def do_GET(self):
        if self.path == '/api/stats':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            
            # Get latest packets and stats
            response = {
                'stats': traffic_manager.stats,
                'blocked_ips': list(traffic_manager.blocked_ips),
                'packets': list(traffic_manager.packets_buffer)[-200:] # Convert deque to list before slicing
            }
            self.wfile.write(json.dumps(response).encode('utf-8'))
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path == '/api/block':
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            data = json.loads(post_data.decode('utf-8'))
            
            ip = data.get('ip')
            if ip:
                traffic_manager.block_ip(ip)
                self.send_response(200)
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(b'{"status": "blocked"}')
            else:
                self.send_response(400)
                self.end_headers()
                
        elif self.path == '/api/unblock':
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            data = json.loads(post_data.decode('utf-8'))
            
            ip = data.get('ip')
            if ip:
                traffic_manager.unblock_ip(ip)
                self.send_response(200)
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(b'{"status": "unblocked"}')
            else:
                self.send_response(400)
                self.end_headers()
        elif self.path == '/api/start':
             sys.stderr.write(f"[{datetime.now()}] Request to start monitoring received.\n")
             sys.stderr.flush()
             
             traffic_manager.is_running = True
             traffic_manager.start_sniffer() # Start the raw socket sniffer
             
             # Check if it actually started (might have failed due to permissions)
             if not traffic_manager.is_running:
                 sys.stderr.write(f"[{datetime.now()}] Failed to start sniffer (is_running=False).\n")
                 sys.stderr.flush()
                 self.send_response(500)
                 self.send_header('Access-Control-Allow-Origin', '*')
                 self.end_headers()
                 self.wfile.write(b'{"status": "error", "message": "Failed to start sniffer. Check permissions."}')
                 return

             if not hasattr(traffic_manager, 'thread') or not traffic_manager.thread.is_alive():
                 sys.stderr.write(f"[{datetime.now()}] Starting monitoring loop thread.\n")
                 sys.stderr.flush()
                 traffic_manager.thread = threading.Thread(target=self.monitoring_loop, daemon=True)
                 traffic_manager.thread.start()
             
             self.send_response(200)
             self.send_header('Access-Control-Allow-Origin', '*')
             self.end_headers()
             self.wfile.write(b'{"status": "started"}')
        elif self.path == '/api/stop':
             sys.stderr.write(f"[{datetime.now()}] Request to stop monitoring.\n")
             sys.stderr.flush()
             traffic_manager.is_running = False
             self.send_response(200)
             self.send_header('Access-Control-Allow-Origin', '*')
             self.end_headers()
             self.wfile.write(b'{"status": "stopped"}')
        else:
            self.send_response(404)
            self.end_headers()

    def monitoring_loop(self):
        while traffic_manager.is_running:
            # Process multiple packets to keep up with traffic
            processed = False
            for _ in range(200): # Process up to 200 packets per tick
                packet, _ = traffic_manager.process_packet()
                if packet:
                    processed = True
                else:
                    break
            
            if not processed:
                time.sleep(0.1) # Sleep if no traffic to save CPU
            else:
                time.sleep(0.005) # Short sleep to yield

def run_server():
    # Manual start only
    traffic_manager.is_running = False
    # monitor_thread = threading.Thread(target=TrafficRequestHandler.monitoring_loop, args=(None,), daemon=True)
    # monitor_thread.start()
    
    class ReusableTCPServer(socketserver.TCPServer):
        allow_reuse_address = True

    with ReusableTCPServer(("", PORT), TrafficRequestHandler) as httpd:
        print(f"Server running on port {PORT}")
        httpd.serve_forever()

if __name__ == "__main__":
    run_server()
