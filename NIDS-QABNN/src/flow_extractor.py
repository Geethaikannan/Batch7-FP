import time
from collections import defaultdict
from scapy.all import IP, TCP, UDP, ICMP
from typing import Dict, Tuple, Optional

class FlowKey:
    def __init__(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, proto: int):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.proto = proto
    
    def __hash__(self):
        return hash((self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.proto))
    
    def __eq__(self, other):
        return (self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.proto) == \
               (other.src_ip, other.dst_ip, other.src_port, other.dst_port, other.proto)

class FlowExtractor:
    def __init__(self, timeout: float = 120.0):
        self.flows: Dict[FlowKey, dict] = {}
        self.timeout = timeout
    
    def _get_ports(self, pkt):
        if pkt.haslayer(TCP):
            return pkt[TCP].sport, pkt[TCP].dport
        elif pkt.haslayer(UDP):
            return pkt[UDP].sport, pkt[UDP].dport
        elif pkt.haslayer(ICMP):
            # For ICMP, use type and code as ports
            return pkt[ICMP].type, pkt[ICMP].code
        return 0, 0
    
    def process_packet(self, pkt):
        """Process a single packet and extract flows"""
        if IP not in pkt:
            return None
        
        # Create flow key
        src_port, dst_port = self._get_ports(pkt)
        key = FlowKey(
            src_ip=pkt[IP].src,
            dst_ip=pkt[IP].dst,
            src_port=src_port,
            dst_port=dst_port,
            proto=pkt[IP].proto
        )
        
        now = time.time()
        
        # Initialize or retrieve flow
        if key not in self.flows:
            self.flows[key] = {
                'start': now,
                'last': now,
                'spkts': 0, 'dpkts': 0,
                'sbytes': 0, 'dbytes': 0,
                'proto': self._proto_name(pkt[IP].proto),
                'service': '-', 'state': 'INT',
            }
        
        flow = self.flows[key]
        pkt_len = len(pkt)
        
        # Update flow stats based on direction
        if pkt[IP].src == key.src_ip:
            flow['spkts'] += 1
            flow['sbytes'] += pkt_len
        else:
            flow['dpkts'] += 1
            flow['dbytes'] += pkt_len
        
        flow['last'] = now
        
        # Check if flow should be extracted (completed)
        is_complete = False
        
        # ICMP flows complete immediately (single packet)
        if pkt[IP].proto == 1:  # ICMP
            is_complete = True
        # TCP flow completion indicators
        elif TCP in pkt:
            flags = pkt[TCP].flags
            # FIN (0x01) or RST (0x04)
            if flags & 0x01 or flags & 0x04:
                is_complete = True
        
        # HTTP/HTTPS upload detection: Complete flow early for ANY upload activity
        # This allows VERY fast detection of uploads on ports 80/443
        if (key.dst_port == 80 or key.dst_port == 443):
            # Complete flow if we see bidirectional traffic with ANY significant client data
            if flow['sbytes'] > 500 and flow['dpkts'] > 0:
                # Client sent 500B+, server responded at least once = likely upload complete
                is_complete = True
            elif flow['sbytes'] > 100 and flow['dbytes'] >= 100:
                # Even smaller upload with any response
                is_complete = True
        
        # Timeout-based completion (very short timeout for web traffic to catch small uploads)
        flow_duration = now - flow['start']
        timeout_threshold = 10 if (key.dst_port == 80 or key.dst_port == 443) else 30  # Reduced from 30/120 to 10/30
        if flow_duration > timeout_threshold:
            is_complete = True
        
        # Extract and return features if flow is complete
        if is_complete:
            features = self._extract_features(key, flow, now)
            # Log flow completion
            import logging
            logger = logging.getLogger(__name__)
            sbytes = flow.get('sbytes', 0)
            dbytes = flow.get('dbytes', 0)
            total = sbytes + dbytes
            if dst_port in [80, 443] and total > 0:
                logger.debug(f"✔️ HTTP FLOW COMPLETED: {key.src_ip}:{key.src_port} → {key.dst_ip}:{key.dst_port} | {sbytes}B up, {dbytes}B down")
            elif total > 1000:
                logger.debug(f"✔️ FLOW COMPLETED: {key.src_ip}:{key.src_port} → {key.dst_ip}:{key.dst_port} | {total}B total")
            del self.flows[key]
            return features
        
        return None
    
    def _proto_name(self, proto_num):
        """Convert protocol number to string"""
        names = {1: 'icmp', 6: 'tcp', 17: 'udp', 2: 'igmp', 47: 'gre'}
        return names.get(proto_num, str(proto_num))
    
    def _extract_features(self, key: FlowKey, flow: dict, now: float) -> dict:
        """Extract UNSW-NB15 compatible features from a flow"""
        
        spkts = flow.get('spkts', 0)
        dpkts = flow.get('dpkts', 0)
        sbytes = flow.get('sbytes', 0)
        dbytes = flow.get('dbytes', 0)
        
        dur = max(now - flow.get('start', now), 0.001)
        rate = (spkts + dpkts) / dur if dur > 0 else 0
        
        features = {
            'src_ip': key.src_ip,
            'dst_ip': key.dst_ip,
            'src_port': key.src_port,
            'dst_port': key.dst_port,
            'proto': flow.get('proto', 'tcp'),
            'service': flow.get('service', '-'),
            'dur': dur,
            'spkts': spkts,
            'dpkts': dpkts,
            'sbytes': sbytes,
            'dbytes': dbytes,
            'rate': rate,
            'sttl': 254,
            'dttl': 0,
            'sload': sbytes / dur if dur > 0 else 0,
            'dload': dbytes / dur if dur > 0 else 0,
            'sloss': max(0, spkts - dpkts) * 0.1,
            'dloss': max(0, dpkts - spkts) * 0.1,
            'sinpkt': sbytes / spkts if spkts > 0 else 0,
            'dinpkt': dbytes / dpkts if dpkts > 0 else 0,
            'sjit': 0,
            'djit': 0,
            'swin': 255,
            'stcpb': 0,
            'dtcpb': 0,
            'dwin': 255,
            'tcprtt': 0,
            'synack': 0,
            'ackdat': 0,
            'smean': sbytes / spkts if spkts > 0 else 0,
            'dmean': dbytes / dpkts if dpkts > 0 else 0,
            'trans_depth': 0,
            'response_body_len': 0,
            'ct_srv_src': 1,
            'ct_state_ttl': 1,
            'ct_dst_ltm': 1,
            'ct_src_dport_ltm': 1,
            'ct_dst_sport_ltm': 1,
            'ct_dst_src_ltm': 1,
            'ct_dst_sport_ltm': 1,
            'is_ftp_login': 0,
            'ct_ftp_cmd': 0,
            'ct_flw_http_mthd': 0,
            'ct_src_ltm': 1,
            'ct_srv_dst': 1,
            'is_sm_ips_ports': 0,
        }
        
        return features

