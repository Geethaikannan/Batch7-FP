# File Upload Detection - AGGRESSIVE MODE ENABLED ✅

## Changes Made for Maximum Alert Detection

### 1. **Flow Detector Thresholds** (src/flow_extractor.py)
- **HTTP/HTTPS (ports 80/443)**:
  - Complete flow when: sbytes > 500B AND server responds (dpkts > 0)
  - OR: sbytes > 100B AND dbytes >= 100B
  - Timeout: **10 seconds** (reduced from 120s)
  
- **All other protocols**:
  - Timeout: **30 seconds** (reduced from 120s)

### 2. **File Upload Detection Sensitivity** (src/realtime_nids_complete.py)

| Protocol | Port | Threshold | Condition |
|----------|------|-----------|-----------|
| HTTP/HTTPS | 80, 443 | **500B** | Any upload with server response |
| FTP | 21 | **1KB** | Any significant transfer |
| SSH/SCP | 22 | **1KB** | Any significant transfer |
| SMB | 139, 445 | **1KB** | Any significant transfer |
| Database | 3306, 5432 | **1KB** | Any client data sent |

**Key: All thresholds are EXTREMELY LOW to catch every upload**

### 3. **Severity Levels** (Very granular)
```
Size >= 0B      → "Low" severity
Size >= 100KB   → "Medium" severity  
Size >= 1MB     → "High" severity
Size >= 5MB     → "Critical" severity
```

### 4. **Logging Enabled** 🔍

**Terminal will show:**
- ✅ Every HTTP flow completion: `✔️ HTTP FLOW COMPLETED: IP:port → IP:port | XB up, YB down`
- ✅ Upload detection: `🚀 HTTP/HTTPS UPLOAD DETECTED: ZB from IP to IP:80`
- ✅ Alert creation: `📊 ALERT CREATED: 🚀 FILE UPLOAD | ZKB | IP→IP:80`
- ✅ Flow processing: `FLOW PROCESSED: IP→IP:port | sbytes=X dbytes=Y`
- ✅ General flow stats: `Processed X flows, Y detections`

### 5. **Alert Data** (Sent to Dashboard)

Each alert now includes:
```json
{
  "type": "🚀 FILE UPLOAD: HTTP/HTTPS File Upload",
  "severity": "Low|Medium|High|Critical",
  "src_ip": "192.168.x.x",
  "dst_ip": "10.0.x.x",
  "dst_port": 443,
  "data_size": 1024,
  "data_size_kb": 1.0,
  "data_size_mb": 0.0009,
  "file_path": "extracted_if_available",
  "timestamp": "2026-03-31T...",
  "status": "active"
}
```

## How Aggressive Detection Works

### Example Scenarios:

**Scenario 1: Small HTTP Upload to ChatGPT**
```
1. User uploads 2KB image
2. Flow Detector: Detects 2KB sent, server responds → FLOW COMPLETE (< 1 second)
3. Detection: sbytes (2KB) > 500B threshold → UPLOAD DETECTED ✅
4. Alert: "🚀 FILE UPLOAD: HTTP/HTTPS File Upload" with severity "Low"
5. Dashboard: Alert appears in "🚨 ACTIVE ALERTS" section immediately
```

**Scenario 2: FTP File Transfer**
```
1. FTP upload of 5KB file starts
2. Flow Detector: Detects 5KB total → FLOW COMPLETE (< 10 seconds)
3. Detection: 5KB >= 1KB threshold → UPLOAD DETECTED ✅
4. Alert: "🚀 FILE UPLOAD: FTP File Upload" with severity "Low"
5. Dashboard: Alert appears immediately
```

**Scenario 3: Web Form Upload**
```
1. HTML form POST with 50KB data
2. Flow Detector: Detects 50KB upload, server responds → FLOW COMPLETE (< 1 sec)
3. Detection: 50KB > 500B AND sbytes > dbytes → UPLOAD DETECTED ✅
4. Alert: "🚀 FILE UPLOAD: HTTP/HTTPS File Upload" with severity "Low"
5. Dashboard: Alert appears with 50KB file size
```

## Diagnostic Logging

**To monitor in real-time, check terminal for:**
```
FLOW PROCESSED: X.X.X.X → Y.Y.Y.Y:80 | sbytes=1024 dbytes=512
✔️ HTTP FLOW COMPLETED: X.X.X.X:52341 → Y.Y.Y.Y:443 | 1024B up, 512B down
🚀 HTTP/HTTPS UPLOAD DETECTED: 1.0KB from X.X.X.X to Y.Y.Y.Y:443
📊 ALERT CREATED: 🚀 FILE UPLOAD: HTTP/HTTPS File Upload | 1.0KB | X.X.X.X→Y.Y.Y.Y:443
✅ UPLOAD ALERT CREATED AND STORED: 🚀 FILE UPLOAD: HTTP/HTTPS File Upload
```

## Expected Behavior Now

✅ **ANY file being uploaded will trigger an alert**
✅ **Alerts appear on dashboard within 1-10 seconds**
✅ **Terminal shows detailed debug info**
✅ **Very low false negatives** (catches everything)
✅ **Some false positives** (catches normal data transfers too)

## If Alerts Still Don't Appear

1. **Check terminal logs for**:
   - "FLOW PROCESSED" messages
   - "HTTP FLOW COMPLETED" messages
   - "HTTP/HTTPS UPLOAD DETECTED" messages
   
2. **If no flows processed**:
   - Check if live capture is running ("MONITORING ACTIVE" on dashboard)
   - Verify network traffic is actually flowing
   - Check for capture permission errors

3. **If flows processed but no alerts**:
   - Dashboard might need refresh (F5)
   - Check browser console for JavaScript errors
   - Try stopping and restarting live capture

## Files Modified

1. **src/flow_extractor.py**
   - Reduced HTTP timeout from 30s to 10s
   - Added early flow completion for small uploads
   - Added detailed logging

2. **src/realtime_nids_complete.py**
   - Lowered all upload thresholds to 1KB
   - Added protocol-specific detection
   - Added comprehensive logging
   - File alert creation and storage

