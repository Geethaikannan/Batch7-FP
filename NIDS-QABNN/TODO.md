# ICMP Ping Detection Fix - TODO List

## Plan Breakdown (Approved)
- ✅ [Complete] Understand codebase: ICMP flows processed but ML predicts Normal
✅ [Complete] Edit `src/realtime_nids_complete.py`: Add ICMP tracker + heuristic detection (severity 5/10)
- ⏳ [] Test 1: Run `python test_ping_detection.py` → Verify attacks in `get_recent_attacks()`
- ⏳ [] Test 2: Live ping flood (`ping -n 20 127.0.0.1`) with capture → Check dashboard Recent Attacks
- ⏳ [] Test 3: Run `python validate_icmp.py` → Confirm ICMP as attacks in predictions
- ⏳ [] Restart Flask: Ctrl+C, `python app.py` → Full verification
- ⏳ [] [Done] attempt_completion

**Next step marked for execution.**

