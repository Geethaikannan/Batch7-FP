"""
Demo: Simulate real-time attack detection
Generates simulated network flows and processes them through the NIDS
Useful for testing the dashboard without live network traffic
"""
import sys
import os
import time
import random
import threading
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from src.realtime_nids_complete import nids_system

def generate_simulated_flows(duration=60, flow_rate=10):
    """Generate simulated network flows"""
    print(f"\n{'='*80}")
    print("NIDS DEMO - Simulated Network Traffic Generator")
    print(f"{'='*80}")
    print(f"Duration: {duration} seconds")
    print(f"Flow rate: {flow_rate} flows per second")
    print(f"{'='*80}\n")
    
    normal_ips = ['192.168.1.100', '192.168.1.101', '192.168.1.102', '10.0.0.50']
    attack_ips = ['203.0.113.45', '198.51.100.89', '192.0.2.77']
    dest_ips = ['8.8.8.8', '1.1.1.1', '208.67.222.222', '4.4.4.4']
    
    attack_types = [
        'Reconnaissance',
        'Backdoor',
        'DoS',
        'Exploits',
        'Analysis',
        'Fuzzers',
        'Worms',
        'Shellcode',
        'Generic'
    ]
    
    start_time = time.time()
    flow_count = 0
    attack_count = 0
    
    print(f"Starting simulation at {time.strftime('%H:%M:%S')}")
    print("Generating flows...\n")
    
    while time.time() - start_time < duration:
        # Generate multiple flows per iteration
        for _ in range(max(1, flow_rate // 10)):
            # Decide if this is normal or attack traffic
            is_attack = random.random() < 0.35  # 35% attacks
            
            if is_attack:
                src_ip = random.choice(attack_ips)
                flow_type = random.choice(attack_types)
                attack_count += 1
            else:
                src_ip = random.choice(normal_ips)
                flow_type = 'Normal'
            
            # Create flow features
            flow_features = {
                'src_ip': src_ip,
                'dst_ip': random.choice(dest_ips),
                'src_port': random.randint(1024, 65535),
                'dst_port': random.choice([80, 443, 22, 21, 25, 53, 3306, 5432]),
                'proto': random.choice(['tcp', 'udp', 'icmp']),
                'service': random.choice(['-', 'http', 'https', 'ssh', 'ftp']),
                'dur': random.randint(1, 3600),
                'spkts': random.randint(1, 10000),
                'dpkts': random.randint(1, 10000),
                'sbytes': random.randint(0, 10000000),
                'dbytes': random.randint(0, 10000000),
                'rate': random.uniform(0, 100),
                'attack_cat': flow_type,
            }
            
            # Process the simulated flow
            nids_system._process_flow(flow_features)
            flow_count += 1
            
            # Print progress every 50 flows
            if flow_count % 50 == 0:
                print(f"[{time.strftime('%H:%M:%S')}] Processed {flow_count} flows | "
                      f"Attacks: {attack_count} | "
                      f"Detected: {nids_system.detection_count}")
        
        time.sleep(0.1)  # Small delay to control flow rate
    
    print(f"\n{'='*80}")
    print("SIMULATION COMPLETE")
    print(f"{'='*80}")
    print(f"Total flows processed: {flow_count}")
    print(f"Simulated attacks: {attack_count}")
    print(f"Attacks detected: {nids_system.detection_count}")
    print(f"Detection rate: {(nids_system.detection_count/max(1, attack_count)*100):.1f}%")
    print(f"\nNormal traffic records: {len(nids_system.normal_traffic)}")
    print(f"Attack records: {len(nids_system.attack_traffic)}")
    print(f"\nOpen the Flask app dashboard to see results!")
    print(f"{'='*80}\n")

def start_demo():
    """Start the demo"""
    # Ensure model is loaded
    print("Loading NIDS model...")
    if nids_system.model is None:
        print("ERROR: Could not load model")
        return
    
    print("✓ Model loaded\n")
    
    # Generate flows
    generate_simulated_flows(duration=60, flow_rate=100)
    
    # Show statistics
    stats = nids_system.get_statistics()
    print("\nFinal Statistics:")
    for key, value in stats.items():
        print(f"  {key}: {value}")

if __name__ == "__main__":
    try:
        start_demo()
    except KeyboardInterrupt:
        print("\n\nDemo interrupted by user")
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
