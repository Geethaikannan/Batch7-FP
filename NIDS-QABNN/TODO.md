# NIDS Command Detection (Ping + Netstat) - TODO

## Overview
Extend system to detect netstat command (recon tool) alongside existing ping/ICMP detection.

## Steps:
- [x] 1. Edit src/realtime_nids_complete.py: Add netstat_tracker in __init__, new _detect_netstat_recon method, integrate into _process_flow ✅
- [ ] 2. Edit test_ping_detection.py: Rename/add test_netstat_detection with simulated flows
- [ ] 3. Test: python test_ping_detection.py - verify detections
- [ ] 4. Run realtime demo: python app_fixed.py (or main app), simulate traffic
- [x] 0. Plan approved and TODO created ✅

**Next:** Implement step 1.
