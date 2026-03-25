# NIDS Attack Detection Testing Guide

## 🚀 System Ready for Packet Sender Testing

Your NIDS system now detects these attack types:

### ✅ **Implemented Attack Detections:**

1. **Port Scanning** - Multiple ports from same IP
2. **Brute Force Attacks** - Repeated login attempts (FTP/SSH/SMTP/POP3/IMAP)
3. **HTTP Flood** - Rapid HTTP/HTTPS requests
4. **Malformed Packets** - Unusual payload sizes
5. **ICMP Reconnaissance** - Ping sweeps and probes

### 🧪 **Testing Scenarios with Packet Sender:**

#### **1. Port Scanning Test**
```
Address: [target IP, e.g. 192.168.1.10]
Port: 1234, 5678, 9999, 1111, 2222 (uncommon ports)
Method: TCP
Resend Delay: 0.1
```
**Expected Result:** "Port Scanning" category in attacks table

#### **2. Brute Force Test (FTP)**
```
Address: [target IP]
Port: 21
Method: TCP
ASCII Payload:
USER admin
PASS 123456
```
**Send repeatedly** (3+ times)
**Expected Result:** "Brute Force (FTP)" category

#### **3. HTTP Flood Test**
```
Address: [target IP]
Port: 80
Method: TCP
ASCII Payload:
GET / HTTP/1.1
Host: [target IP]
```
**Resend Delay: 0.01** (rapid requests)
**Expected Result:** "HTTP Flood" category

#### **4. Malformed Packet Test**
```
Address: [target IP]
Port: 80
Method: TCP
HEX Payload: 47 45 54 20 2f 25 30 30 25 30 30 48 54 54 50
```
**Expected Result:** "Malformed Packets" category

### 📊 **Dashboard Features:**

- **Live Status:** Shows monitoring state
- **Statistics:** Packets processed, flows analyzed, attacks detected
- **Normal Traffic Table:** Benign network flows
- **Attacks Table:** Detected attacks with categories and severity
- **Real-time Updates:** Live predictions stream

### 🔧 **System Configuration:**

- **Port Scan Threshold:** 5 different ports
- **Brute Force Threshold:** 3 attempts
- **HTTP Flood Threshold:** 10 requests/second
- **Malformed Packet Threshold:** 2 unusual packets

### 🛡️ **Safety Notes:**

- Test only on networks you own/control
- Use virtual machines for target systems
- Monitor system resources during testing
- Stop capture when done testing

### 🎯 **Ready to Test:**

1. Start your Flask app: `python app.py`
2. Open dashboard: `http://127.0.0.1:5000`
3. Click "START LIVE MONITORING"
4. Use Packet Sender to send attack patterns
5. Watch attacks appear in the tables with proper categories!

The system will now properly categorize and display all the attack types you mentioned for testing.</content>
<parameter name="filePath">PACKET_SENDER_TESTING_GUIDE.md