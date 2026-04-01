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
        self.label_encoders = {}  # For categorical feature encoding
        self.scaler = None         # For feature scaling
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
        
        # File upload detection state
        self.file_upload_tracker = defaultdict(lambda: {'count': 0, 'total_bytes': 0, 'last_time': 0})
        self.FILE_UPLOAD_THRESHOLD = 1024 * 800  # 800KB (0.8MB) threshold for file uploads
        self.FILE_UPLOAD_PORTS = [80, 443, 21, 22, 139, 445, 3306, 5432]  # Common file transfer ports
        
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
        
        logger.info("✓ NIDS System initialized - ready to capture LIVE network traffic")
    
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
    
    def _extract_file_path(self, flow_features):
        """Extract file path from network flow features if available"""
        try:
            # Try to extract from HTTP headers or payload
            http_method = flow_features.get('http_method', '')
            http_url = flow_features.get('http_url', '')
            
            if http_url:
                # Extract filename from URL
                if '/' in http_url:
                    file_path = http_url.split('/')[-1]
                    if file_path and len(file_path) > 0:
                        return file_path
                return http_url
            
            # Try to extract from FTP commands (if available in service field)
            service = flow_features.get('service', '')
            if 'ftp' in service.lower():
                return "[FTP Transfer - filename not captured at flow level]"
            
            # Try to extract from SCP/SSH
            if 'ssh' in service.lower() or 'scp' in service.lower():
                return "[SSH/SCP Transfer - filename not captured at flow level]"
            
            return None
        except Exception as e:
            logger.debug(f"Error extracting file path: {e}")
            return None
    
    def _detect_file_upload(self, flow_features):
        """Detect REAL file uploads - only alert on significant files (>= 1MB)"""
        src_ip = flow_features.get('src_ip', 'Unknown')
        dst_ip = flow_features.get('dst_ip', 'Unknown')
        dst_port = int(flow_features.get('dst_port', 0))
        sbytes = int(flow_features.get('sbytes', 0))
        dbytes = int(flow_features.get('dbytes', 0))
        proto = str(flow_features.get('proto', 'tcp')).lower()
        current_time = time.time()
        
        total_bytes = sbytes + dbytes
        
        # Check for file uploads based on port only
        is_file_transfer_port = dst_port in self.FILE_UPLOAD_PORTS
        
        if not is_file_transfer_port:
            return None
        
        # ONLY REAL UPLOADS: Minimum 1MB threshold
        MIN_UPLOAD_SIZE = 1024 * 1024  # 1MB minimum
        
        # Different detection logic for different protocols
        upload_detected = False
        upload_size = 0
        
        if dst_port == 80 or dst_port == 443:
            # HTTP/HTTPS: Check client upload data only (sbytes = client->server)
            # Web uploads usually: client sends file, server sends small response
            if sbytes >= MIN_UPLOAD_SIZE:
                upload_detected = True
                upload_size = sbytes
                logger.warning(f"🚀 HTTP/HTTPS UPLOAD DETECTED: {sbytes/(1024*1024):.2f}MB from {src_ip} to {dst_ip}:{dst_port}")
        
        elif dst_port == 21:
            # FTP: Any significant file transfer
            if total_bytes >= MIN_UPLOAD_SIZE:
                upload_detected = True
                upload_size = total_bytes
                logger.warning(f"🚀 FTP UPLOAD DETECTED: {total_bytes/(1024*1024):.2f}MB from {src_ip} to {dst_ip}:{dst_port}")
        
        elif dst_port == 22:
            # SSH/SCP: Encrypted file transfer
            if total_bytes >= MIN_UPLOAD_SIZE:
                upload_detected = True
                upload_size = total_bytes
                logger.warning(f"🚀 SSH/SCP UPLOAD DETECTED: {total_bytes/(1024*1024):.2f}MB from {src_ip} to {dst_ip}:{dst_port}")
        
        elif dst_port in [139, 445]:
            # SMB: File share access
            if total_bytes >= MIN_UPLOAD_SIZE:
                upload_detected = True
                upload_size = total_bytes
                logger.warning(f"🚀 SMB UPLOAD DETECTED: {total_bytes/(1024*1024):.2f}MB from {src_ip} to {dst_ip}:{dst_port}")
        
        elif dst_port in [3306, 5432]:
            # Database: Data load
            if sbytes >= MIN_UPLOAD_SIZE:
                upload_detected = True
                upload_size = sbytes
                logger.warning(f"🚀 DB UPLOAD DETECTED: {sbytes/(1024*1024):.2f}MB from {src_ip} to {dst_ip}:{dst_port}")
        
        if not upload_detected:
            return None
        
        # Track upload
        tracker_key = f"{src_ip}:{dst_ip}:{dst_port}"
        self.file_upload_tracker[tracker_key]['count'] += 1
        self.file_upload_tracker[tracker_key]['total_bytes'] += upload_size
        self.file_upload_tracker[tracker_key]['last_time'] = current_time
        
        # Clean old entries (older than 5 minutes)
        for key in list(self.file_upload_tracker.keys()):
            if current_time - self.file_upload_tracker[key]['last_time'] > 300:
                del self.file_upload_tracker[key]
        
        # Determine transfer type and extract file path
        transfer_type = "Unknown"
        file_path = self._extract_file_path(flow_features)
        
        if dst_port == 80 or dst_port == 443:
            transfer_type = "HTTP/HTTPS"
        elif dst_port == 21:
            transfer_type = "FTP"
        elif dst_port == 22:
            transfer_type = "SSH/SCP"
        elif dst_port in [139, 445]:
            transfer_type = "SMB"
        elif dst_port in [3306, 5432]:
            transfer_type = "Database"
        
        # Calculate file size properly
        file_size_mb = round(upload_size / (1024 * 1024), 2)
        file_size_kb = round(upload_size / 1024, 2)
        
        # Determine severity based on actual file size
        severity = "Medium"
        if upload_size >= 10 * 1024 * 1024:  # >= 10MB
            severity = "High"
        elif upload_size >= 50 * 1024 * 1024:  # >= 50MB
            severity = "Critical"
        
        file_info = f" ({file_path})" if file_path else ""
        
        # Create alert with correct file size
        alert = {
            'id': f"upload_{int(time.time() * 1000)}",
            'timestamp': datetime.now().isoformat(),
            'type': f"🚀 FILE UPLOAD DETECTED",
            'severity': severity,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'dst_port': dst_port,
            'protocol': proto.upper(),
            'transfer_type': transfer_type,
            'data_size': upload_size,
            'data_size_kb': file_size_kb,
            'data_size_mb': file_size_mb,
            'confidence': 100.0,
            'file_path': file_path,
            'description': f"{transfer_type} file upload: {file_size_mb}MB from {src_ip} to {dst_ip}:{dst_port}{file_info}",
            'action_required': "Review file upload for security",
            'status': 'active'
        }
        
        self.alerts.append(alert)
        if len(self.alerts) > self.max_alerts:
            self.alerts = self.alerts[-self.max_alerts:]
        
        logger.warning(f"📊 ALERT CREATED: {file_size_mb}MB file uploaded from {src_ip} to {dst_ip}:{dst_port} via {transfer_type}")
        return alert
    
    def _load_preprocessors(self):
        """Load preprocessors for feature scaling"""
        try:
            if Path(self.preprocessors_path).exists():
                logger.info(f"Loading preprocessors from {self.preprocessors_path}")
                with open(self.preprocessors_path, 'rb') as f:
                    preprocessor_data = pickle.load(f)
                logger.info("✓ Preprocessors loaded successfully")
                
                # Extract encoders and scaler
                self.label_encoders = preprocessor_data.get('encoders', {})
                self.scaler = preprocessor_data.get('scaler', None)
                
                if self.label_encoders:
                    logger.info(f"Loaded {len(self.label_encoders)} label encoders")
                if self.scaler:
                    logger.info("Scaler loaded successfully")
            else:
                logger.warning("Preprocessors not found")
                self.label_encoders = {}
                self.scaler = None
        except Exception as e:
            logger.error(f"Failed to load preprocessors: {e}")
            self.label_encoders = {}
            self.scaler = None
    
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
        """Process flows - Make predictions and populate dashboard data"""
        try:
            # Check for file uploads first
            file_upload_alert = self._detect_file_upload(flow_features)
            if file_upload_alert:
                logger.warning(f"✅ UPLOAD ALERT: {file_upload_alert['data_size_mb']}MB file detected")
            
            # Make prediction using model if available
            if self.model:
                try:
                    # Transform features properly using encoders and scaler
                    features_array = self._transform_flow_features(flow_features)
                    
                    if features_array is not None:
                        # Get prediction
                        prediction = self.model.predict(features_array)
                        prediction_proba = self.model.predict_proba(features_array) if hasattr(self.model, 'predict_proba') else None
                        
                        # Determine if attack
                        is_attack = prediction[0] == 1
                        
                        # Calculate confidence: use probability of predicted class
                        if prediction_proba is not None:
                            # Get probability of predicted class
                            if is_attack:
                                confidence = float(prediction_proba[0][1] * 100)  # Attack probability
                            else:
                                confidence = float(prediction_proba[0][0] * 100)  # Normal probability
                        else:
                            confidence = 100.0 if is_attack else 50.0
                        
                        confidence = max(50, min(100, confidence))  # Ensure between 50-100
                        
                        # Create record
                        record = {
                            'timestamp': datetime.now().isoformat(),
                        'src_ip': flow_features.get('src_ip', 'Unknown'),
                        'dst_ip': flow_features.get('dst_ip', 'Unknown'),
                        'src_port': int(flow_features.get('src_port', 0)),
                        'dst_port': int(flow_features.get('dst_port', 0)),
                        'proto': flow_features.get('proto', 'tcp'),
                        'service': flow_features.get('service', '-'),
                        'duration': int(flow_features.get('dur', 0)),
                        'sbytes': int(flow_features.get('sbytes', 0)),
                        'dbytes': int(flow_features.get('dbytes', 0)),
                        'src_bytes': int(flow_features.get('sbytes', 0)),
                        'dst_bytes': int(flow_features.get('dbytes', 0)),
                        'prediction': 'Attack' if is_attack else 'Normal',
                        'confidence': confidence,
                        'attack_probability': confidence if is_attack else (100 - confidence),
                        'severity_score': int((confidence / 10)) if is_attack else 0,
                        'attack_cat': flow_features.get('attack_cat', 'Unknown'),
                        'state': flow_features.get('state', 'EST'),
                        'xai_explanation': ''
                    }
                    
                    # Add to appropriate list
                    if is_attack:
                        self.attack_traffic.append(record)
                        self.detection_count += 1
                        if len(self.attack_traffic) > self.max_records:
                            self.attack_traffic = self.attack_traffic[-self.max_records:]
                    else:
                        self.normal_traffic.append(record)
                        if len(self.normal_traffic) > self.max_records:
                            self.normal_traffic = self.normal_traffic[-self.max_records:]
                    
                    # Add to live predictions
                    self.live_predictions.append(record)
                    if len(self.live_predictions) > self.max_records:
                        self.live_predictions = self.live_predictions[-self.max_records:]
                    
                except Exception as e:
                    logger.debug(f"Error making prediction: {e}")
            else:
                # No model available, just store as normal traffic for dashboard display
                record = {
                    'timestamp': datetime.now().isoformat(),
                    'src_ip': flow_features.get('src_ip', 'Unknown'),
                    'dst_ip': flow_features.get('dst_ip', 'Unknown'),
                    'src_port': int(flow_features.get('src_port', 0)),
                    'dst_port': int(flow_features.get('dst_port', 0)),
                    'proto': flow_features.get('proto', 'tcp'),
                    'service': flow_features.get('service', '-'),
                    'duration': int(flow_features.get('dur', 0)),
                    'sbytes': int(flow_features.get('sbytes', 0)),
                    'dbytes': int(flow_features.get('dbytes', 0)),
                    'src_bytes': int(flow_features.get('sbytes', 0)),
                    'dst_bytes': int(flow_features.get('dbytes', 0)),
                    'prediction': 'Normal',
                    'confidence': 50.0,
                    'attack_probability': 0,
                    'severity_score': 0,
                    'attack_cat': 'Unknown',
                    'state': flow_features.get('state', 'EST'),
                    'xai_explanation': ''
                }
                self.normal_traffic.append(record)
                self.live_predictions.append(record)
                if len(self.normal_traffic) > self.max_records:
                    self.normal_traffic = self.normal_traffic[-self.max_records:]
                if len(self.live_predictions) > self.max_records:
                    self.live_predictions = self.live_predictions[-self.max_records:]
        
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
    
    def _transform_flow_features(self, flow_features):
        """Transform raw flow features to properly encoded and scaled format"""
        try:
            # Build feature dictionary with all columns
            feature_dict = {
                'dur': flow_features.get('dur', 0),
                'proto': flow_features.get('proto', 'tcp'),  # Categorical
                'service': flow_features.get('service', '-'),  # Categorical
                'state': flow_features.get('state', 'CON'),  # Categorical
                'spkts': flow_features.get('spkts', 0),
                'dpkts': flow_features.get('dpkts', 0),
                'sbytes': flow_features.get('sbytes', 0),
                'dbytes': flow_features.get('dbytes', 0),
                'rate': flow_features.get('rate', 0),
                'sttl': flow_features.get('sttl', 254),
                'dttl': flow_features.get('dttl', 0),
                'sload': flow_features.get('sload', 0),
                'dload': flow_features.get('dload', 0),
                'sloss': flow_features.get('sloss', 0),
                'dloss': flow_features.get('dloss', 0),
                'sinpkt': flow_features.get('sinpkt', 0),
                'dinpkt': flow_features.get('dinpkt', 0),
                'sjit': flow_features.get('sjit', 0),
                'djit': flow_features.get('djit', 0),
                'swin': flow_features.get('swin', 255),
                'stcpb': flow_features.get('stcpb', 0),
                'dtcpb': flow_features.get('dtcpb', 0),
                'dwin': flow_features.get('dwin', 255),
                'tcprtt': flow_features.get('tcprtt', 0),
                'synack': flow_features.get('synack', 0),
                'ackdat': flow_features.get('ackdat', 0),
                'smean': flow_features.get('smean', 0),
                'dmean': flow_features.get('dmean', 0),
                'trans_depth': flow_features.get('trans_depth', 0),
                'response_body_len': flow_features.get('response_body_len', 0),
                'ct_srv_src': flow_features.get('ct_srv_src', 1),
                'ct_state_ttl': flow_features.get('ct_state_ttl', 1),
                'ct_dst_ltm': flow_features.get('ct_dst_ltm', 1),
                'ct_src_dport_ltm': flow_features.get('ct_src_dport_ltm', 1),
                'ct_dst_sport_ltm': flow_features.get('ct_dst_sport_ltm', 1),
                'ct_dst_src_ltm': flow_features.get('ct_dst_src_ltm', 1),
                'is_ftp_login': flow_features.get('is_ftp_login', 0),
                'ct_ftp_cmd': flow_features.get('ct_ftp_cmd', 0),
                'ct_flw_http_mthd': flow_features.get('ct_flw_http_mthd', 0),
                'ct_srv_dst': flow_features.get('ct_srv_dst', 1),
                'is_sm_ips_ports': flow_features.get('is_sm_ips_ports', 0),
            }
            
            # Create a DataFrame for proper encoding
            df = pd.DataFrame([feature_dict])
            
            # Encode categorical features if encoders are available
            for col in ['proto', 'service', 'state']:
                if col in self.label_encoders:
                    try:
                        # Handle unknown values by using the first class
                        df[col] = self.label_encoders[col].transform(df[col])
                    except ValueError:
                        # Unknown category - use default encoding
                        df[col] = 0
                else:
                    # No encoder available, use numeric encoding
                    if col == 'proto':
                        proto_map = {'tcp': 6, 'udp': 17, 'icmp': 1}
                        df[col] = proto_map.get(df[col].values[0], 6)
                    else:
                        df[col] = 0
            
            # Get feature array
            X = df.values
            
            # Apply scaler if available
            if self.scaler is not None:
                X = self.scaler.transform(X)
            
            return X
        
        except Exception as e:
            logger.error(f"Error transforming flow features: {e}")
            logger.debug(f"Flow features: {flow_features}")
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
