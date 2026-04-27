"""
Test ICMP/Ping Detection
Simulates ping traffic and verifies it's detected as attacks
"""
import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from src.realtime_nids_complete import nids_system

def test_command_detection():
    """Test ICMP/ping and netstat command detection"""
    
    print("=" * 80)
    print("COMMAND DETECTION TEST (Ping + Netstat)")
    print("=" * 80)
    print("\nSimulating ping traffic (ICMP packets)...\n")
    
    # Simulate various ICMP flows (pings)
    icmp_flows = [
        {
            'src_ip': '10.0.0.5',
            'dst_ip': '192.168.1.10',
            'src_port': 0,
            'dst_port': 0,
            'proto': 'icmp',
            'service': '-',
            'dur': 0.1,
            'spkts': 1,
            'dpkts': 0,
            'sbytes': 32,
            'dbytes': 0,
            'rate': 10,
        },
        {
            'src_ip': '203.0.113.88',
            'dst_ip': '192.168.1.1',
            'src_port': 0,
            'dst_port': 0,
            'proto': 'icmp',
            'service': '-',
            'dur': 0.05,
            'spkts': 2,
            'dpkts': 1,
            'sbytes': 64,
            'dbytes': 32,
            'rate': 20,
        },
        {
            'src_ip': '192.168.1.100',
            'dst_ip': '8.8.8.8',
            'src_port': 0,
            'dst_port': 0,
            'proto': 'icmp',
            'service': '-',
            'dur': 1.5,
            'spkts': 10,
            'dpkts': 10,
            'sbytes': 640,
            'dbytes': 640,
            'rate': 6.67,
        },
    ]
    
    # Process each ICMP flow
    detected_count = 0
    for flow in icmp_flows:
        nids_system._process_flow(flow)
        print(f"✓ Processed: {flow['src_ip']} -> {flow['dst_ip']} (ICMP ping)")
        time.sleep(0.1)
    
    # Check detection results
    print(f"\n{'='*80}")
    print("DETECTION RESULTS")
    print(f"{'='*80}")
    
    attacks = nids_system.get_recent_attacks(100)
    print(f"\n🚨 Total ICMP Attacks Detected: {len(attacks)}")
    
    if len(attacks) > 0:
        print("\nDetected ICMP Attacks:")
        for attack in attacks:
            print(f"  • {attack['src_ip']} -> {attack['dst_ip']}")
            print(f"    Type: ICMP/Ping | Confidence: {attack['confidence']}%")
            print(f"    Severity: {attack['severity_score']}/10\n")
        print("✅ PING DETECTION WORKING!")
    else:
        print("❌ No ICMP detected - showing all traffic:")
        for normal in nids_system.get_recent_normal(10):
            print(f"  • {normal['src_ip']} -> {normal['dst_ip']} ({normal['proto']})")
    
    # Show statistics
    stats = nids_system.get_statistics()
    print(f"\n{'='*80}")
    print("SYSTEM STATISTICS")
    print(f"{'='*80}")
    print(f"Flows Analyzed: {stats['flows_analyzed']}")
    print(f"Attacks Detected: {stats['attacks_detected']}")
    print(f"Normal Traffic: {stats['normal_count']}")
    print(f"Detection Rate: {stats['detection_rate']:.1f}%")
    
    print(f"\n{'='*80}")
    print("✅ TEST COMPLETE - Dashboard running at http://localhost:5000")
    print(f"{'='*80}\n")

def test_netstat_detection():
    """Test netstat reconnaissance detection (high port probes)"""
    
    print("\n2. Testing Netstat detection...")
    
    # Clear previous traffic
    nids_system.attack_traffic.clear()
    nids_system.normal_traffic.clear()
    nids_system.live_predictions.clear()
    
    # Simulate netstat recon flows (TCP/UDP to high ephemeral ports >1024)
    netstat_flows = []
    src_ip = '192.168.1.200'
    
    for i in range(12):  # 12 unique high ports to trigger threshold
        netstat_flows.append({
            'src_ip': src_ip,
            'dst_ip': '127.0.0.1',
            'src_port': 54321,
            'dst_port': 12340 + i,  # High ports 12340-12351
            'proto': 'tcp' if i % 2 == 0 else 'udp',
            'service': '-',
            'dur': 0.01,
            'spkts': 1,
            'dpkts': 0,
            'sbytes': 40,
            'dbytes': 0,
            'rate': 100,
        })
    
    print(f"Simulating {len(netstat_flows)} netstat flows to high ports...")
    for flow in netstat_flows:
        nids_system._process_flow(flow)
        print(f"✓ Processed: {flow['src_ip']}:{flow['src_port']} -> {flow['dst_ip']}:{flow['dst_port']} ({flow['proto'].upper()})")
        time.sleep(0.05)
    
    print("\nNetstat Detection Results:")
    attacks = nids_system.get_recent_attacks(20)
    netstat_attacks = [a for a in attacks if 'Netstat' in a.get('attack_cat', '')]
    
    if netstat_attacks:
        print(f"✅ NETSTAT DETECTION SUCCESS: {len(netstat_attacks)} detections")
        for attack in netstat_attacks:
            print(f"  • {attack['src_ip']} -> {attack['dst_ip']} | {attack['attack_cat']} | Conf: {attack['confidence']:.1f}% | Sev: {attack['severity_score']}")
    else:
        print("❌ No Netstat detections")
    
if __name__ == "__main__":
    test_command_detection()
    test_netstat_detection()
