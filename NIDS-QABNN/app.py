import os
import numpy as np
import pickle
import json
import logging
import traceback

from flask import Flask, render_template, request, session, Response, stream_with_context, jsonify
from src.data_loader import load_data
from src.preprocessing import preprocess_data
from src.qabnn import QABNN
from src.xai_explainer import QABNNExplainer, FeatureImportanceCalculator
from src.realtime_nids_complete import nids_system

import math
import pandas as pd
import time

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = 'nids_qabnn_secret_key'

# Dataset configurations
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_PATH = os.path.join(BASE_DIR, "data", "UNSW_NB15_testing-set.csv")

# Global caches
model_cache = {}
test_df_cache = None
X_test_cache = None
y_test_cache = None

# Error handler for unhandled exceptions
@app.errorhandler(Exception)
def handle_error(error):
    logger.error(f"Unhandled error: {error}\n{traceback.format_exc()}")
    return jsonify({'error': 'An internal server error occurred', 'message': str(error)}), 500


@app.route("/", methods=["GET", "POST"])
def index():
    try:
        prediction = None
        recent_normals = []
        recent_attacks = []
        
        live_status = ("ON" if nids_system.is_capturing else "OFF")
        
        if request.method == "GET" and not nids_system.is_capturing and not session.get('auto_started'):
            result = nids_system.start_capture()
            session['auto_started'] = True
            if result == "Started":
                prediction = "✓ Live traffic capture auto-started - monitoring network traffic for attacks..."
            else:
                prediction = "⚠️ Failed to auto-start live capture. Check the capture error below."

        if request.method == "POST":
            if request.form.get('toggle_live'):
                try:
                    print("TOGGLE LIVE CAPTURE CLICKED!")
                    if nids_system.is_capturing:
                        result = nids_system.stop_capture()
                        print(f"STOP result: {result}")
                        prediction = "✓ Live traffic capture stopped"
                    else:
                        result = nids_system.start_capture()
                        print(f"START result: {result}")
                        prediction = "✓ Live traffic capture started - monitoring network traffic for attacks..."
                except Exception as e:
                    logger.error(f"Error toggling capture: {e}")
                    prediction = f"⚠️ Error: {str(e)}"

        
        session.modified = True
        
        try:
            live_data = nids_system.live_predictions[-20:] if nids_system.live_predictions else []
            recent_normals = nids_system.get_recent_normal(100)
            recent_attacks = nids_system.get_recent_attacks(100)
            active_alerts = nids_system.get_active_alerts(20)
        except Exception as e:
            logger.error(f"Error retrieving data: {e}")
            live_data = []
            recent_normals = []
            recent_attacks = []
            active_alerts = []
        
        session['recent_normals'] = recent_normals
        session['recent_attacks'] = recent_attacks
        session.modified = True
        
        stats = nids_system.get_statistics()
        available_interfaces = nids_system.get_available_interfaces()
        return render_template(
            "index.html", 
            prediction=prediction,
            live_status=live_status,
            live_data=live_data,
            realtime_nids=nids_system.is_capturing,
            nids_stats=stats,
            capture_error=stats.get('capture_error'),
            capture_interface=stats.get('capture_interface'),
            available_interfaces=available_interfaces,
            recent_normals=recent_normals,
            recent_attacks=recent_attacks,
            active_alerts=active_alerts
        )
    except Exception as e:
        logger.error(f"Error in index route: {e}\n{traceback.format_exc()}")
        return jsonify({'error': 'Failed to load dashboard', 'message': str(e)}), 500

@app.route('/live-data')
def live_data():
    try:
        def generate():
            try:
                while nids_system.is_capturing:
                    if nids_system.live_predictions:
                        data = nids_system.live_predictions[-1]
                        serialized = nids_system._serialize_record(data)
                        yield f"data: {json.dumps(serialized)}\n\n"
                    time.sleep(1)
            except Exception as e:
                logger.error(f"Error in live data stream: {e}")
                yield f"data: {json.dumps({'error': str(e)})}\n\n"
        return Response(stream_with_context(generate()), mimetype='text/event-stream')
    except Exception as e:
        logger.error(f"Error setting up live data: {e}")
        return jsonify({'error': 'Failed to start live data stream', 'message': str(e)}), 500

@app.route('/api/stats')
def api_stats():
    """Get real-time statistics"""
    try:
        return jsonify(nids_system.get_statistics())
    except Exception as e:
        logger.error(f"Error getting stats: {e}")
        return jsonify({'error': 'Failed to get statistics', 'message': str(e)}), 500

@app.route('/api/recent-normal')
def api_recent_normal():
    """Get recent normal traffic"""
    try:
        limit = request.args.get('limit', 50, type=int)
        return jsonify({'data': nids_system.get_recent_normal(limit)})
    except Exception as e:
        logger.error(f"Error getting normal traffic: {e}")
        return jsonify({'error': 'Failed to get normal traffic', 'message': str(e)}), 500

@app.route('/api/recent-attacks')
def api_recent_attacks():
    """Get recent attack traffic"""
    try:
        limit = request.args.get('limit', 50, type=int)
        return jsonify({'data': nids_system.get_recent_attacks(limit)})
    except Exception as e:
        logger.error(f"Error getting attacks: {e}")
        return jsonify({'error': 'Failed to get attacks', 'message': str(e)}), 500

@app.route('/api/live-predictions')
def api_live_predictions():
    """Get recent live predictions"""
    try:
        limit = request.args.get('limit', 50, type=int)
        predictions = nids_system.live_predictions[-limit:]
        serialized = [nids_system._serialize_record(p) for p in predictions]
        return jsonify({'data': serialized})
    except Exception as e:
        logger.error(f"Error getting live predictions: {e}")
        return jsonify({'error': 'Failed to get live predictions', 'message': str(e)}), 500

@app.route('/api/raw-packets')
def api_raw_packets():
    """Get recent raw captured packet summaries"""
    try:
        limit = request.args.get('limit', 50, type=int)
        packets = nids_system.get_recent_packets(limit)
        return jsonify({'data': packets})
    except Exception as e:
        logger.error(f"Error getting raw packets: {e}")
        return jsonify({'error': 'Failed to get raw packets', 'message': str(e)}), 500

@app.route('/api/alerts')
def api_alerts():
    """Get active alerts"""
    try:
        limit = request.args.get('limit', 20, type=int)
        return jsonify({'data': nids_system.get_active_alerts(limit)})
    except Exception as e:
        logger.error(f"Error getting alerts: {e}")
        return jsonify({'error': 'Failed to get alerts', 'message': str(e)}), 500

@app.route('/api/alerts/<alert_id>/dismiss', methods=['POST'])
def dismiss_alert(alert_id):
    """Dismiss an alert"""
    try:
        nids_system.dismiss_alert(alert_id)
        return jsonify({'status': 'success', 'message': 'Alert dismissed'})
    except Exception as e:
        logger.error(f"Error dismissing alert: {e}")
        return jsonify({'error': 'Failed to dismiss alert', 'message': str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True)

