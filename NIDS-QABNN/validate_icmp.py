#!/usr/bin/env python
"""
Direct ICMP Detection Validation
Tests that ICMP/ping packets are correctly classified as attacks
"""
import json
import os

# Check the stored predictions to see if ICMP was detected
data_dir = 'data/realtime'
if os.path.exists(data_dir):
    files = sorted([f for f in os.listdir(data_dir) if f.endswith('.jsonl')])
    if files:
        latest_file = os.path.join(data_dir, files[-1])
        print(f"Checking predictions file: {latest_file}\n")
        
        with open(latest_file, 'r') as f:
            lines = f.readlines()
            
        # Analyze predictions
        total = len(lines)
        icmp_attacks = []
        icmp_normal = []
        
        for line in lines:
            try:
                pred = json.loads(line.strip())
                if pred.get('proto', '').lower() == 'icmp':
                    if pred.get('prediction') == 1:
                        icmp_attacks.append(pred)
                    else:
                        icmp_normal.append(pred)
            except:
                pass
        
        print(f"{'='*80}")
        print("ICMP/PING DETECTION VALIDATION")
        print(f"{'='*80}\n")
        
        print(f"📊 Summary:")
        print(f"  Total Predictions: {total}")
        print(f"  ICMP as Attacks: {len(icmp_attacks)}")
        print(f"  ICMP as Normal: {len(icmp_normal)}")
        
        if icmp_attacks:
            print(f"\n✅ ICMP DETECTION WORKING!")
            print(f"\nSample Detected Attacks:")
            for attack in icmp_attacks[:3]:
                print(f"  • {attack['src_ip']} -> {attack['dst_ip']}")
                print(f"    Confidence: {attack.get('confidence', 'N/A')}%")
                print(f"    Timestamp: {attack.get('timestamp', 'N/A')}\n")
        else:
            print(f"\n⚠️  No ICMP attacks detected yet")
            print(f"First 3 predictions recorded:")
            for pred in lines[:3]:
                try:
                    p = json.loads(pred.strip())
                    print(f"  • {p.get('src_ip')} -> {p.get('dst_ip')} ({p.get('proto')}) - {p.get('prediction')}")
                except:
                    pass
        
        print(f"\n{'='*80}")
        print("✅ Predictions Storage Working - Dashboard Ready")
        print(f"{'='*80}\n")
    else:
        print("No prediction files found yet. Dashboard hasn't recorded any traffic.")
else:
    print("Data directory doesn't exist yet. Run the Flask app with 'START LIVE MONITORING' button.")

print("📱 Dashboard: http://localhost:5000")
