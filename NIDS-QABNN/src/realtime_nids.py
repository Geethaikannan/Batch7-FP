import threading
import time
from src.qabnn import QABNN
from src.preprocessing import preprocess_data
import numpy as np

realtime_nids = type('RealtimeNIDS', (), {})()

realtime_nids.model = None
realtime_nids.scaler = None
realtime_nids.label_encoders = None
realtime_nids.is_capturing = False
realtime_nids.live_predictions = []

def start_capture():
    global realtime_nids
    realtime_nids.is_capturing = True
    print("Live capture started (stub - implement scapy sniffing)")
    # TODO: Add scapy packet capture + flow_extractor
    threading.Thread(target=_capture_loop, daemon=True).start()
    return "Started"

def stop_capture():
    global realtime_nids
    realtime_nids.is_capturing = False
    print("Live capture stopped")
    return "Stopped"

def _capture_loop():
    while realtime_nids.is_capturing:
        # Simulate prediction every 2s
        pred_data = {
            'time': time.strftime('%H:%M:%S'),
            'src_ip': '192.168.1.10',
            'dst_ip': '8.8.8.8',
            'proto': 'tcp',
            'pred': 'Normal' if np.random.rand() > 0.3 else 'Attack',
            'severity_score': np.random.randint(1, 10)
        }
        if realtime_nids.model:
            # Dummy X
            X_dummy = np.random.rand(1, 43)
            pred = realtime_nids.model.predict(X_dummy)[0]
            pred_data['pred'] = 'Attack' if pred == 1 else 'Normal'
        realtime_nids.live_predictions.append(pred_data)
        if len(realtime_nids.live_predictions) > 50:
            realtime_nids.live_predictions = realtime_nids.live_predictions[-20:]
        time.sleep(2)

realtime_nids.start_capture = start_capture
realtime_nids.stop_capture = stop_capture
