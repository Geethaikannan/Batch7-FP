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
            
            # Create prediction record
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
                'severity_score': severity if is_icmp else 0 if prediction == 0 else severity,
                'attack_cat': 'Reconnaissance' if is_icmp else ('Probe' if prediction == 1 else 'Normal Traffic'),
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
        logger.info("✓ Packet capture stopped")
        return "Stopped"
    
    def get_statistics(self):
        """Get current NIDS statistics"""
        return {
            'is_capturing': self.is_capturing,
            'packets_processed': self.packet_count,
            'flows_analyzed': self.flow_count,
            'attacks_detected': self.detection_count,
            'normal_count': len(self.normal_traffic),
            'attack_count': len(self.attack_traffic),
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
