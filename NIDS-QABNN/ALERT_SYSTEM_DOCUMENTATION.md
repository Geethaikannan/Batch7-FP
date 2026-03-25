# NIDS Alert System Documentation

## 🚨 Data Upload Detection & Alert System

### Overview
The NIDS Alert System provides real-time monitoring and alerting for large data transfers that may indicate file uploads, data sharing, or potential data exfiltration activities on the network.

### Alert Types

#### 1. **Data Upload Alert** (Medium Severity)
- **Trigger**: Data transfers > 50KB
- **Color**: Orange 🟠
- **Purpose**: Detects moderate file uploads and data sharing

#### 2. **Large Data Transfer Alert** (High Severity)
- **Trigger**: Data transfers > 100KB
- **Color**: Red 🔴
- **Purpose**: Detects significant data transfers that may indicate bulk uploads or exfiltration

### Alert Features

#### Real-time Detection
- Monitors all network flows for data transfer sizes
- Triggers immediately when thresholds are exceeded
- Logs detailed information about the transfer

#### Visual Dashboard
- **Prominent Alert Section**: Large, colored alert boxes at the top of the dashboard
- **Severity Indicators**: Color-coded borders and badges
- **Detailed Information**: Source IP, destination, data size, protocol, timestamp
- **Action Items**: Clear guidance on what to monitor

#### Alert Management
- **Active Alerts**: Currently active alerts requiring attention
- **Dismiss Functionality**: Click "✕ Dismiss" to mark alerts as resolved
- **Alert History**: Maintains history of all alerts (active and dismissed)
- **Statistics Integration**: Active alert count shown in dashboard stats

### Technical Implementation

#### Detection Logic
```python
# Thresholds
LARGE_UPLOAD_THRESHOLD = 50000    # 50KB
DATA_TRANSFER_THRESHOLD = 100000  # 100KB

# Detection in _detect_large_data_transfer()
total_bytes = sbytes + dbytes
if total_bytes >= LARGE_UPLOAD_THRESHOLD:
    # Generate alert based on size
```

#### Alert Data Structure
```json
{
  "id": "alert_1703123456789",
  "timestamp": "2026-03-25T10:00:00.000000",
  "type": "Large Data Transfer Alert",
  "severity": "High",
  "src_ip": "192.168.1.100",
  "dst_ip": "cloud-service.com",
  "dst_port": 443,
  "protocol": "TCP",
  "data_size": 150000,
  "data_size_mb": 0.15,
  "confidence": 95.0,
  "description": "Large data transfer detected: 146.5 KB from 192.168.1.100",
  "action_required": "Monitor for unauthorized data exfiltration",
  "status": "active"
}
```

#### API Endpoints
- `GET /api/alerts` - Get active alerts
- `POST /api/alerts/{alert_id}/dismiss` - Dismiss an alert

### Use Cases

#### File Upload Detection
- **Cloud Storage**: Google Drive, Dropbox, OneDrive uploads
- **File Sharing**: Email attachments, FTP uploads
- **Backup Services**: Automatic backups to remote servers

#### Data Exfiltration Monitoring
- **Unauthorized Transfers**: Large data sent to unknown external IPs
- **Bulk Downloads**: Large incoming data transfers
- **Suspicious Activity**: Unusual data transfer patterns

#### Network Monitoring
- **Usage Tracking**: Monitor data transfer volumes
- **Policy Enforcement**: Alert on excessive data usage
- **Security Incidents**: Detect potential data breaches

### Configuration

#### Thresholds (in `realtime_nids_complete.py`)
```python
self.LARGE_UPLOAD_THRESHOLD = 50000    # 50KB for medium alerts
self.DATA_TRANSFER_THRESHOLD = 100000  # 100KB for high alerts
self.max_alerts = 50                   # Maximum alerts to keep
```

#### Customization Options
- Adjust threshold values based on network usage patterns
- Modify alert severity logic
- Add custom alert types for specific protocols/ports
- Configure alert retention policies

### Dashboard Integration

#### Statistics Display
```
📊 Packets: 1,234
🔀 Flows: 567
🚨 Attacks: 12
📈 Rate: 2.1%
🔔 Alerts: 3
```

#### Alert Section Layout
- **Header**: "🚨 ACTIVE ALERTS - IMMEDIATE ATTENTION REQUIRED"
- **Individual Alerts**: Color-coded boxes with full details
- **Action Buttons**: Dismiss functionality
- **Responsive Design**: Works on different screen sizes

### Testing the Alert System

#### Manual Testing
1. Start the NIDS: `python app.py`
2. Open dashboard: `http://127.0.0.1:5000`
3. Click "START LIVE MONITORING"
4. Generate large data transfers:
   - Upload files to cloud services
   - Transfer large files over network
   - Use file sharing applications

#### Packet Sender Testing
- Send large payloads using Packet Sender
- Configure with data sizes >50KB
- Test different protocols (TCP/UDP)

### Security Considerations

#### False Positives
- Large legitimate downloads (software updates, video streaming)
- Backup operations
- Large email attachments

#### Mitigation Strategies
- **Whitelist Known Services**: Exclude trusted IPs/domains
- **Time-based Rules**: Different thresholds for business hours
- **User Context**: Consider user roles and permissions
- **Alert Tuning**: Adjust thresholds based on network baseline

#### Privacy & Compliance
- Monitor only network metadata (sizes, IPs, ports)
- No payload inspection
- Comply with local privacy regulations
- Implement data retention policies

### Future Enhancements

#### Advanced Features
- **Geolocation Alerts**: Flag transfers to high-risk countries
- **Behavioral Analysis**: Detect unusual transfer patterns
- **Integration**: Connect with SIEM systems
- **Automated Response**: Trigger blocking rules

#### Machine Learning
- **Anomaly Detection**: Learn normal transfer patterns
- **Predictive Alerts**: Forecast potential exfiltration
- **User Profiling**: Build user behavior baselines

### Troubleshooting

#### Common Issues
- **No Alerts Showing**: Check if live monitoring is active
- **False Alerts**: Adjust threshold values
- **Performance Impact**: Monitor system resources during high traffic

#### Debug Commands
```python
# Check active alerts
nids_system.get_active_alerts()

# View alert statistics
nids_system.get_statistics()

# Test alert generation
nids_system._detect_large_data_transfer(test_flow)
```

### Conclusion

The Alert System provides comprehensive monitoring of data transfers with immediate visual notifications for security personnel. It helps detect potential data exfiltration attempts while providing detailed information for incident response and forensic analysis.</content>
<parameter name="filePath">ALERT_SYSTEM_DOCUMENTATION.md