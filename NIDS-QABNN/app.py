import os
import numpy as np
import pickle
import json

from flask import Flask, render_template, request, session, Response, stream_with_context, jsonify
from src.data_loader import load_data
from src.preprocessing import preprocess_data
from src.qabnn import QABNN
from src.xai_explainer import QABNNExplainer, FeatureImportanceCalculator
from src.realtime_nids_complete import nids_system

import math
import pandas as pd
import time

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



@app.route("/", methods=["GET", "POST"])
def index():
    prediction = None
    recent_normals = []
    recent_attacks = []
    
    live_status = ("ON" if nids_system.is_capturing else "OFF")
    
    if request.method == "POST":
        if request.form.get('toggle_live'):
            print("TOGGLE LIVE CAPTURE CLICKED!")
            if nids_system.is_capturing:
                result = nids_system.stop_capture()
                print(f"STOP result: {result}")
                prediction = "✓ Live traffic capture stopped"
            else:
                result = nids_system.start_capture()
                print(f"START result: {result}")
                prediction = "✓ Live traffic capture started - monitoring network traffic for attacks..."

    
    session.modified = True
    
    live_data = nids_system.live_predictions[-20:] if nids_system.live_predictions else []
    recent_normals = nids_system.get_recent_normal(100)
    recent_attacks = nids_system.get_recent_attacks(100)
    
    session['recent_normals'] = recent_normals
    session['recent_attacks'] = recent_attacks
    session.modified = True
    
    return render_template(
        "index.html", 
        prediction=prediction,
        live_status=live_status,
        live_data=live_data,
        realtime_nids=nids_system.is_capturing,
        nids_stats=nids_system.get_statistics()
    )

@app.route('/live-data')
def live_data():
    def generate():
        while nids_system.is_capturing:
            if nids_system.live_predictions:
                data = nids_system.live_predictions[-1]
                yield f"data: {json.dumps(data)}\n\n"
            time.sleep(1)
    return Response(stream_with_context(generate()), mimetype='text/event-stream')

@app.route('/api/stats')
def api_stats():
    """Get real-time statistics"""
    return jsonify(nids_system.get_statistics())

@app.route('/api/recent-normal')
def api_recent_normal():
    """Get recent normal traffic"""
    limit = request.args.get('limit', 50, type=int)
    return jsonify(nids_system.get_recent_normal(limit))

@app.route('/api/recent-attacks')
def api_recent_attacks():
    """Get recent attack traffic"""
    limit = request.args.get('limit', 50, type=int)
    return jsonify(nids_system.get_recent_attacks(limit))

@app.route('/api/live-predictions')
def api_live_predictions():
    """Get recent live predictions"""
    limit = request.args.get('limit', 50, type=int)
    return jsonify(nids_system.live_predictions[-limit:])

if __name__ == "__main__":
    app.run(debug=True)

