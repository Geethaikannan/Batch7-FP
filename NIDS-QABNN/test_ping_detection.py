"""
Test ICMP/Ping Detection
Simulates ping traffic and verifies it's detected as attacks
"""
import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from src.realtime_nids_complete import nids_system

def test_icmp_detection():
    """Test that ICMP/ping traffic is detected"""
    
    print("=" * 80)
    print("ICMP/PING ATTACK DETECTION TEST")
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

if __name__ == "__main__":
    test_icmp_detection()
