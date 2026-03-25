# NIDS-QABNN Real-Time Fix Steps

## Current Issues
- Button toggle perceived reversed, colors reversed
- No live data/logs (flow_extractor bugs, possible scapy/Npcap)

## Steps
- [x
- [ ] Step 2: Update templates/index.html (swap button colors to user preference, fix SSE live table update)
- [ ] Step 3: Update requirements.txt (add scapy)
- [ ] Step 4: Update src/realtime_nids.py (better Windows iface, more debug prints, error handling)
- [ ] Step 5: Stop current server, pip install -r requirements.txt, restart python app.py
- [ ] Step 6: Test toggle + generate traffic (ping localhost), verify live logs/table
- [ ] Step 7: Update original TODO.md, attempt_completion
