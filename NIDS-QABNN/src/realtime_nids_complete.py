"""
Real-time Network Intrusion Detection System
Captures live network traffic, extracts features, and detects attacks in real-time
"""
import threading
import time
import pickle
import json
import logging
from datetime import datetime
from collections import defaultdict
from pathlib import Path

import numpy as np
import pandas as pd
from scapy.all import sniff, IP, TCP, UDP, ICMP
from src.flow_extractor import FlowExtractor
from src.qabnn import QABNN
from src.xai_explainer import QABNNExplainer

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class RealtimeNIDSSystem:
    """Main real-time NIDS system for live network traffic analysis"""
    
    def __init__(self, model_path="models/qabnn_model.pkl", 
                 preprocessors_path="models/preprocessors.pkl",
                 data_dir="data/realtime"):
        self.model = None
        self.preprocessors = None
        self.model_path = model_path
        self.preprocessors_path = preprocessors_path
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        # Real-time state
        self.is_capturing = False
        self.flow_extractor = FlowExtractor(timeout=120.0)
        
        # Live predictions storage
        self.live_predictions = []  # Last 100 predictions
        self.normal_traffic = []     # Recent normal flows
        self.attack_traffic = []     # Recent attack flows
        self.max_records = 100
        
        # Stats
        self.packet_count = 0
        self.flow_count = 0
        self.detection_count = 0
        
        # Attack pattern detection state
        self.port_scan_tracker = defaultdict(lambda: {'ports': set(), 'count': 0, 'last_time': 0})
        self.brute_force_tracker = defaultdict(lambda: {'attempts': 0, 'last_time': 0})
        self.http_flood_tracker = defaultdict(lambda: {'requests': 0, 'last_time': 0})
        self.malformed_tracker = defaultdict(lambda: {'count': 0, 'last_time': 0})
        
        # Alerts system for data uploads and large transfers
        self.alerts = []  # List of active alerts
        self.max_alerts = 50  # Maximum alerts to keep
        
        # Detection thresholds
        self.PORT_SCAN_THRESHOLD = 5  # Different ports from same IP
        self.BRUTE_FORCE_THRESHOLD = 3  # Failed login attempts
        self.HTTP_FLOOD_THRESHOLD = 10  # Rapid HTTP requests per second
        self.MALFORMED_THRESHOLD = 2  # Unusual packet patterns
        self.LARGE_UPLOAD_THRESHOLD = 50000  # 50KB for large data detection
        self.DATA_TRANSFER_THRESHOLD = 100000  # 100KB for significant data transfers
        
        # Load model and preprocessors
        self._load_model()
        self._load_preprocessors()
        
        # Initialize XAI explainer
        self.explainer = None
        if self.model:
            feature_names = [
                'duration', 'spkts', 'dpkts', 'sbytes', 'dbytes', 'rate', 'sttl', 'dttl',
                'sload', 'dload', 'sloss', 'dloss', 'sintpkt', 'dintpkt', 'sjit', 'djit',
                'swin', 'stcpb', 'dtcpb', 'dwin', 'tcprtt', 'synack', 'ackdat', 'smean',
                'dmean', 'trans_depth', 'response_body_len', 'ct_ftp_cmd', 'is_ftp_login',
                'ct_ftp_resp', 'ct_dns_queries', 'ct_smtp_cmd', 'ct_state_ttl', 'ct_srv_src',
                'ct_srv_dst', 'ct_dst_ltm', 'ct_src_ltm', 'ct_src_dport_ltm', 'is_sm_ips_ports',
                'ct_flw_http_mthd', 'is_ftp_login', 'ct_ftp_resp'
            ]
            self.explainer = QABNNExplainer(self.model, feature_names=feature_names)
    
    def _load_model(self):
        """Load or train QABNN model"""
        try:
            if Path(self.model_path).exists():
                logger.info(f"Loading model from {self.model_path}")
                with open(self.model_path, 'rb') as f:
                    self.model = pickle.load(f)
                logger.info("✓ Model loaded successfully")
            else:
                logger.warning(f"Model not found at {self.model_path}, training new one...")
                from src.data_loader import load_data
                from src.preprocessing import preprocess_data
                
                train_path = "data/UNSW_NB15_training-set.csv"
                test_path = "data/UNSW_NB15_testing-set.csv"
                
                train_df, _ = load_data(train_path, test_path)
                X_train, y_train = preprocess_data(train_df)
                
                self.model = QABNN()
                self.model.fit(X_train, y_train)
                logger.info("✓ Model trained successfully")
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            self.model = QABNN()
    
    def _detect_attack_patterns(self, flow_features):
        """Detect specific attack patterns and return attack info if found"""
        src_ip = flow_features.get('src_ip', 'Unknown')
        dst_port = int(flow_features.get('dst_port', 0))
        proto = str(flow_features.get('proto', ''))
        current_time = time.time()
        
        # Port Scanning Detection
        if dst_port not in [80, 443, 53, 22, 21, 25, 110, 143]:  # Skip common ports
            self.port_scan_tracker[src_ip]['ports'].add(dst_port)
            self.port_scan_tracker[src_ip]['count'] += 1
            self.port_scan_tracker[src_ip]['last_time'] = current_time
            
            # Clean old entries (older than 60 seconds)
            for ip in list(self.port_scan_tracker.keys()):
                if current_time - self.port_scan_tracker[ip]['last_time'] > 60:
                    del self.port_scan_tracker[ip]
            
            if len(self.port_scan_tracker[src_ip]['ports']) >= self.PORT_SCAN_THRESHOLD:
                return {
                    'is_attack': True,
                    'attack_type': 'Port Scanning',
                    'severity': 8,
                    'confidence': 90.0,
                    'explanation': f"🚨 Port scan detected: {len(self.port_scan_tracker[src_ip]['ports'])} ports probed from {src_ip}"
                }
        
        # Brute Force Detection (FTP, SSH, etc.)
        if dst_port in [21, 22, 23, 25, 110, 143, 993, 995]:  # Common service ports
            self.brute_force_tracker[f"{src_ip}:{dst_port}"]['attempts'] += 1
            self.brute_force_tracker[f"{src_ip}:{dst_port}"]['last_time'] = current_time
            
            # Clean old entries
            for key in list(self.brute_force_tracker.keys()):
                if current_time - self.brute_force_tracker[key]['last_time'] > 300:  # 5 minutes
                    del self.brute_force_tracker[key]
            
            if self.brute_force_tracker[f"{src_ip}:{dst_port}"]['attempts'] >= self.BRUTE_FORCE_THRESHOLD:
                service_name = {21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 110: 'POP3', 143: 'IMAP'}.get(dst_port, f'Port {dst_port}')
                return {
                    'is_attack': True,
                    'attack_type': f'Brute Force ({service_name})',
                    'severity': 9,
                    'confidence': 95.0,
                    'explanation': f"🔐 Brute force attack: {self.brute_force_tracker[f'{src_ip}:{dst_port}']['attempts']} attempts to {service_name} from {src_ip}"
                }
        
        # HTTP Flood Detection
        if dst_port == 80 or dst_port == 443:
            self.http_flood_tracker[src_ip]['requests'] += 1
            self.http_flood_tracker[src_ip]['last_time'] = current_time
            
            # Clean old entries (1 second window)
            for ip in list(self.http_flood_tracker.keys()):
                if current_time - self.http_flood_tracker[ip]['last_time'] > 1:
                    del self.http_flood_tracker[ip]
            
            if self.http_flood_tracker[src_ip]['requests'] >= self.HTTP_FLOOD_THRESHOLD:
                protocol = 'HTTPS' if dst_port == 443 else 'HTTP'
                return {
                    'is_attack': True,
                    'attack_type': f'{protocol} Flood',
                    'severity': 7,
                    'confidence': 85.0,
                    'explanation': f"🌊 {protocol} flood detected: {self.http_flood_tracker[src_ip]['requests']} requests/sec from {src_ip}"
                }
        
        # Malformed Packet Detection (basic heuristics)
        sbytes = int(flow_features.get('sbytes', 0))
        dbytes = int(flow_features.get('dbytes', 0))
        
        # Check for unusual packet sizes or patterns
        if sbytes > 10000 or dbytes > 10000:  # Very large packets
            self.malformed_tracker[src_ip]['count'] += 1
            self.malformed_tracker[src_ip]['last_time'] = current_time
            
            if self.malformed_tracker[src_ip]['count'] >= self.MALFORMED_THRESHOLD:
                return {
                    'is_attack': True,
                    'attack_type': 'Malformed Packets',
                    'severity': 6,
                    'confidence': 75.0,
                    'explanation': f"⚠️ Malformed packets detected: unusual payload sizes from {src_ip}"
                }
        
        return None  # No attack pattern detected
    
    def _detect_large_data_transfer(self, flow_features):
        """Detect large data transfers that might indicate file uploads or data exfiltration"""
        src_ip = flow_features.get('src_ip', 'Unknown')
        dst_ip = flow_features.get('dst_ip', 'Unknown')
        dst_port = int(flow_features.get('dst_port', 0))
        sbytes = int(flow_features.get('sbytes', 0))
        dbytes = int(flow_features.get('dbytes', 0))
        proto = str(flow_features.get('proto', ''))
        
        total_bytes = sbytes + dbytes
        
        # Check for large data transfers
        if total_bytes >= self.LARGE_UPLOAD_THRESHOLD:
            alert_type = "Data Upload Alert"
            severity = "Medium"
            confidence = 85.0
            
            # Determine if it's a significant data transfer
            if total_bytes >= self.DATA_TRANSFER_THRESHOLD:
                severity = "High"
                confidence = 95.0
                alert_type = "Large Data Transfer Alert"
            
            # Create alert record
            alert = {
                'id': f"alert_{int(time.time() * 1000)}",
                'timestamp': datetime.now().isoformat(),
                'type': alert_type,
                'severity': severity,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'dst_port': dst_port,
                'protocol': proto.upper(),
                'data_size': total_bytes,
                'data_size_mb': round(total_bytes / (1024 * 1024), 2),
                'confidence': confidence,
                'description': f"Large data transfer detected: {round(total_bytes / 1024, 1)} KB from {src_ip} to {dst_ip}:{dst_port}",
                'action_required': "Monitor for unauthorized data exfiltration or file uploads",
                'status': 'active'
            }
            
            # Add to alerts list
            self.alerts.append(alert)
            
            # Keep only recent alerts
            if len(self.alerts) > self.max_alerts:
                self.alerts = self.alerts[-self.max_alerts:]
            
            logger.warning(f"🚨 {alert_type}: {total_bytes} bytes from {src_ip} to {dst_ip}")
            
            return alert
        
        return None
    
    def _load_preprocessors(self):
        """Load preprocessors for feature scaling"""
        try:
            if Path(self.preprocessors_path).exists():
                logger.info(f"Loading preprocessors from {self.preprocessors_path}")
                with open(self.preprocessors_path, 'rb') as f:
                    self.preprocessors = pickle.load(f)
                logger.info("✓ Preprocessors loaded successfully")
            else:
                logger.warning("Preprocessors not found")
        except Exception as e:
            logger.error(f"Failed to load preprocessors: {e}")
    
    def _get_protocol_string(self, proto_num):
        """Convert protocol number to string"""
        protocols = {6: 'tcp', 17: 'udp', 1: 'icmp', 2: 'igmp', 47: 'gre'}
        return protocols.get(proto_num, str(proto_num))
    
    def packet_callback(self, pkt):
        """Process each captured packet"""
        try:
            self.packet_count += 1
            
            if IP not in pkt:
                return
            
            # Extract flow information
            flow_result = self.flow_extractor.process_packet(pkt)
            
            if flow_result:
                self.flow_count += 1
                self._process_flow(flow_result)
                
                # Log every 10 flows
                if self.flow_count % 10 == 0:
                    logger.info(f"Processed {self.flow_count} flows, {self.detection_count} detections")
        
        except Exception as e:
            logger.error(f"Error processing packet: {e}")
    
    def _process_flow(self, flow_features):
        """Process a complete network flow and make prediction"""
        try:
            # Check for large data transfers first (alert system)
            upload_alert = self._detect_large_data_transfer(flow_features)
            
            # First, check for known attack patterns
            attack_pattern = self._detect_attack_patterns(flow_features)
            
            if attack_pattern:
                # Attack pattern detected - use rule-based detection
                prediction = 1  # Attack
                attack_prob = attack_pattern['confidence'] / 100.0
                confidence = attack_pattern['confidence']
                severity = attack_pattern['severity']
                xai_explanation = attack_pattern['explanation']
                attack_cat = attack_pattern['attack_type']
            else:
                # ICMP/Ping Detection: Flag ICMP traffic as suspicious (reconnaissance)
                proto = str(flow_features.get('proto', ''))
                is_icmp = proto.lower() in ['icmp', '1']
                
                if is_icmp:
                    # ICMP is often used for reconnaissance/scanning
                    prediction = 1  # Attack
                    attack_prob = 0.95  # High confidence
                    confidence = 95.0
                    severity = 10
                    xai_explanation = "🎯 ICMP/Ping detected - Reconnaissance attack. ICMP is commonly used for network scanning and probe activities."
                    attack_cat = "Reconnaissance"
                else:
                    # Prepare features for model
                    feature_vector = self._convert_flow_to_features(flow_features)
                    
                    if feature_vector is None:
                        return
                    
                    # Make prediction
                    prediction = self.model.predict(np.array([feature_vector]))[0]
                    proba = self.model.predict_proba(np.array([feature_vector]))[0]
                    
                    # Get attack probability
                    attack_prob = proba[1]
                    confidence = max(proba) * 100
                    severity = self._calculate_severity(flow_features, prediction, attack_prob)
                    
                    # Generate XAI explanation for attacks
                    xai_explanation = ""
                    if prediction == 1 and self.explainer:
                        try:
                            explanation = self.explainer.explain_prediction(
                                np.array([feature_vector]),
                                sample_metadata=flow_features
                            )
                            # Extract top features contributing to attack classification
                            if 'top_features' in explanation:
                                top_features = explanation['top_features'][:3]
                                reasons = [f"{f['feature']}" for f in top_features]
                                xai_explanation = f"Key indicators: {', '.join(reasons)}"
                            if 'reason' in explanation:
                                xai_explanation = explanation['reason']
                        except Exception as e:
                            xai_explanation = f"Model detected anomalous behavior (Confidence: {confidence:.1f}%)"
                    
                    # Filter: Only flag as attack if it's a high-severity threat
                    # Normal traffic (port 443/HTTPS, 53/DNS, etc.) with low severity is OK
                    if prediction == 1 and severity <= 3:
                        # This is predicted as attack by model, but low severity
                        # Check common safe ports/patterns
                        dst_port = int(flow_features.get('dst_port', 0))
                        if dst_port in [443, 80, 53, 123, 22]:  # HTTPS, HTTP, DNS, NTP, SSH are common
                            prediction = 0  # Treat as normal (just network activity)
                            xai_explanation = ""
                            attack_cat = "Normal Traffic"
                        else:
                            attack_cat = "Suspicious Activity"
                    else:
                        attack_cat = "Anomaly" if prediction == 1 else "Normal Traffic"
            pred_record = {
                'timestamp': datetime.now().isoformat(),
                'src_ip': flow_features.get('src_ip', 'Unknown'),
                'dst_ip': flow_features.get('dst_ip', 'Unknown'),
                'src_port': flow_features.get('src_port', 0),
                'dst_port': flow_features.get('dst_port', 0),
                'proto': flow_features.get('proto', '-'),
                'service': flow_features.get('service', '-'),
                'duration': flow_features.get('dur', 0),
                'sbytes': int(flow_features.get('sbytes', 0)),
                'dbytes': int(flow_features.get('dbytes', 0)),
                'src_bytes': int(flow_features.get('sbytes', 0)),
                'dst_bytes': int(flow_features.get('dbytes', 0)),
                'prediction': 'Attack' if prediction == 1 else 'Normal',
                'confidence': round(confidence, 2),
                'attack_probability': round(float(attack_prob), 4),
                'severity_score': severity if prediction == 1 else 0,
                'attack_cat': attack_cat,
                'state': 'FIN' if prediction == 1 else 'EST',
                'xai_explanation': xai_explanation if prediction == 1 else ""
            }
            
            # Store in appropriate list
            if prediction == 1:  # Attack
                self.attack_traffic.append(pred_record)
                self.detection_count += 1
                logger.warning(f"🚨 ATTACK DETECTED: {pred_record['src_ip']} -> {pred_record['dst_ip']}")
            else:  # Normal
                self.normal_traffic.append(pred_record)
            
            # Keep only recent records
            if len(self.normal_traffic) > self.max_records:
                self.normal_traffic = self.normal_traffic[-self.max_records:]
            if len(self.attack_traffic) > self.max_records:
                self.attack_traffic = self.attack_traffic[-self.max_records:]
            
            # Add to live predictions
            self.live_predictions.append(pred_record)
            if len(self.live_predictions) > 50:
                self.live_predictions = self.live_predictions[-50:]
            
            # Save to file (append mode for persistence)
            self._save_prediction(pred_record)
        
        except Exception as e:
            logger.error(f"Error processing flow: {e}")
    
    def _convert_flow_to_features(self, flow_features):
        """Convert flow dictionary to feature vector for model"""
        try:
            # Expected feature order (43 features)
            features = [
                flow_features.get('dur', 0),
                flow_features.get('spkts', 0),
                flow_features.get('dpkts', 0),
                flow_features.get('sbytes', 0),
                flow_features.get('dbytes', 0),
                flow_features.get('rate', 0),
                flow_features.get('sttl', 254),
                flow_features.get('dttl', 0),
                flow_features.get('sload', 0),
                flow_features.get('dload', 0),
                flow_features.get('sloss', 0),
                flow_features.get('dloss', 0),
                flow_features.get('sinpkt', 0),
                flow_features.get('dinpkt', 0),
                flow_features.get('sjit', 0),
                flow_features.get('djit', 0),
                flow_features.get('swin', 255),
                flow_features.get('stcpb', 0),
                flow_features.get('dtcpb', 0),
                flow_features.get('dwin', 255),
                flow_features.get('tcprtt', 0),
                flow_features.get('synack', 0),
                flow_features.get('ackdat', 0),
                flow_features.get('smean', 0),
                flow_features.get('dmean', 0),
                flow_features.get('trans_depth', 0),
                flow_features.get('response_body_len', 0),
                flow_features.get('ct_srv_src', 1),
                flow_features.get('ct_state_ttl', 1),
                flow_features.get('ct_dst_ltm', 1),
                flow_features.get('ct_src_dport_ltm', 1),
                flow_features.get('ct_dst_sport_ltm', 1),
                flow_features.get('ct_dst_src_ltm', 1),
                flow_features.get('is_ftp_login', 0),
                flow_features.get('ct_ftp_cmd', 0),
                flow_features.get('ct_flw_http_mthd', 0),
                flow_features.get('ct_srv_dst', 1),
                flow_features.get('is_sm_ips_ports', 0),
                1.0,  # Placeholder for remaining features
                0.0,
                0.0,
                0.0,
                0.0
            ]
            
            return np.array(features, dtype=float)
        
        except Exception as e:
            logger.error(f"Error converting flow to features: {e}")
            return None
    
    def _calculate_severity(self, flow_features, prediction, attack_prob):
        """Calculate severity score (1-10)"""
        score = 1
        
        if prediction == 1:  # Attack
            score = min(10, int(attack_prob * 10) + 1)
        else:
            # For normal traffic, base severity on data volume
            total_bytes = flow_features.get('sbytes', 0) + flow_features.get('dbytes', 0)
            score = min(10, int(total_bytes / 1000000))
        
        return score
    
    def _save_prediction(self, pred_record):
        """Save prediction to persistent storage"""
        try:
            filename = self.data_dir / f"predictions_{datetime.now().strftime('%Y%m%d')}.jsonl"
            with open(filename, 'a') as f:
                f.write(json.dumps(pred_record) + '\n')
        except Exception as e:
            logger.error(f"Error saving prediction: {e}")
    
    def start_capture(self, interface=None):
        """Start live packet capture"""
        if self.is_capturing:
            logger.warning("Capture already running")
            return "Already capturing"
        
        self.is_capturing = True
        logger.info(f"Starting packet capture on interface: {interface or 'default'}")
        
        # Start capture in background thread
        def capture_thread():
            try:
                sniff(
                    iface=interface,
                    prn=self.packet_callback,
                    store=False,
                    stop_filter=lambda x: not self.is_capturing
                )
            except PermissionError:
                logger.error("Permission denied! Run with administrator/sudo privileges")
            except Exception as e:
                logger.error(f"Capture error: {e}")
            finally:
                self.is_capturing = False
        
        thread = threading.Thread(target=capture_thread, daemon=True)
        thread.start()
        logger.info("✓ Packet capture started")
        return "Started"
    
    def stop_capture(self):
        """Stop live packet capture"""
        self.is_capturing = False
        # Reset attack pattern trackers
        self.port_scan_tracker.clear()
        self.brute_force_tracker.clear()
        self.http_flood_tracker.clear()
        self.malformed_tracker.clear()
        # Note: Keep alerts for historical reference
        logger.info("✓ Packet capture stopped and attack trackers reset")
        return "Stopped"
    
    def get_statistics(self):
        """Get current NIDS statistics"""
        active_alerts = len([a for a in self.alerts if a.get('status') == 'active'])
        return {
            'is_capturing': self.is_capturing,
            'packets_processed': self.packet_count,
            'flows_analyzed': self.flow_count,
            'attacks_detected': self.detection_count,
            'normal_count': len(self.normal_traffic),
            'attack_count': len(self.attack_traffic),
            'active_alerts': active_alerts,
            'total_alerts': len(self.alerts),
            'detection_rate': (self.detection_count / max(1, self.flow_count)) * 100
        }
    
    def get_recent_normal(self, limit=50):
        """Get recent normal traffic records"""
        records = self.normal_traffic[-limit:]
        return [self._serialize_record(r) for r in records]
    
    def get_recent_attacks(self, limit=50):
        """Get recent attack traffic records"""
        records = self.attack_traffic[-limit:]
        return [self._serialize_record(r) for r in records]
    
    def get_active_alerts(self, limit=20):
        """Get active alerts (most recent first)"""
        active_alerts = [alert for alert in self.alerts if alert.get('status') == 'active']
        return active_alerts[-limit:][::-1]  # Most recent first
    
    def dismiss_alert(self, alert_id):
        """Dismiss an alert by marking it as resolved"""
        for alert in self.alerts:
            if alert.get('id') == alert_id:
                alert['status'] = 'dismissed'
                alert['dismissed_at'] = datetime.now().isoformat()
                break
    
    def _serialize_record(self, record):
        """Convert record to JSON-serializable format"""
        return {
            'timestamp': str(record.get('timestamp', '')),
            'src_ip': str(record.get('src_ip', 'Unknown')),
            'dst_ip': str(record.get('dst_ip', 'Unknown')),
            'src_port': int(record.get('src_port', 0)),
            'dst_port': int(record.get('dst_port', 0)),
            'proto': str(record.get('proto', '-')),
            'service': str(record.get('service', '-')),
            'duration': int(record.get('duration', 0)),
            'sbytes': int(record.get('sbytes', 0)),
            'dbytes': int(record.get('dbytes', 0)),
            'src_bytes': int(record.get('src_bytes', 0)),
            'dst_bytes': int(record.get('dst_bytes', 0)),
            'prediction': str(record.get('prediction', 'Unknown')),
            'confidence': float(record.get('confidence', 0)),
            'attack_probability': float(record.get('attack_probability', 0)),
            'severity_score': int(record.get('severity_score', 0)),
            'attack_cat': str(record.get('attack_cat', 'Unknown')),
            'state': str(record.get('state', 'EST')),
            'xai_explanation': str(record.get('xai_explanation', ''))
        }


# Global instance
nids_system = RealtimeNIDSSystem()
