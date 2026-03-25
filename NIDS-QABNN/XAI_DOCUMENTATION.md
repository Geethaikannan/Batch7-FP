# NIDS-QABNN with XAI (Explainable AI)

## Overview

This project extends the QABNN-based Network Intrusion Detection System with **Explainable AI (XAI)** capabilities. Now, when the system detects network traffic as attack or normal, it provides detailed explanations for **why** that classification was made.

## XAI Features

### 1. **Confidence Scores**
- **Confidence Level (0-100%)**: Displays how confident the model is about its prediction
- **Probability Distribution**: Shows the probability of the traffic being Normal vs Attack
- Helps you understand the certainty of each detection

### 2. **Key Discriminative Features**
- **Top 3 Features**: Shows the network flow features that were most important for the classification
- **Distance Metrics**: 
  - Distance to Normal Prototype: How different the sample is from "typical normal" traffic
  - Distance to Attack Prototype: How different the sample is from "typical attack" traffic
- Features with large differences between distances are strong indicators of the classification

### 3. **Reasoning Explanation**
- **Natural Language Explanation**: Describes in human-readable form why the traffic was classified as attack or normal
- Considers:
  - The confidence level and how certain the model is
  - Which features are most indicative
  - Service type and protocol information
  - Attack category (if applicable)

### 4. **Attack Category** (for detected attacks)
- Shows the specific type of attack detected (e.g., DoS, Exploits, Backdoor, etc.)
- Helps security teams understand the threat level

## How XAI Works in QABNN

The QABNN model uses a prototype-based approach:

1. **Training Phase**: 
   - Creates two "prototypes" (representative patterns): one for normal traffic, one for attack traffic
   - These are learned from labeled training data

2. **Prediction Phase**:
   - For new traffic, calculates how similar it is to each prototype
   - Classification is based on which prototype it's closer to
   - XAI explains this by showing:
     - **Feature-level distances**: Which specific features contribute to the distance
     - **Distance difference**: How much more similar to one prototype vs the other
     - **Key features**: Which features have the largest impact on the classification

## User Interface

### Dashboard
The web interface displays two columns:
- **✓ Recent Normals**: Safe traffic detected
- **⚠ Recent Attacks**: Suspicious traffic detected

### Expandable Details
Click on any traffic sample to expand and view:
- Confidence level visualization (progress bar)
- Top discriminative features with distance metrics
- Detailed reasoning explanation
- Attack category (for attacks only)

### Visual Indicators
- **Green badges**: Normal traffic classification
- **Red badges**: Attack traffic classification
- **Progress bars**: Confidence level visualization

## Example Output

### Normal Traffic Explanation
```
Confidence Level: 95%
Probability - Normal: 0.95, Attack: 0.05

Key Indicators Supporting NORMAL Classification:
📊 Feature_1 - Distance to Normal: 1, Distance to Attack: 8
📊 Feature_5 - Distance to Normal: 2, Distance to Attack: 9
📊 Feature_8 - Distance to Normal: 1, Distance to Attack: 7

Reasoning: This is classified as NORMAL traffic with very high confidence (95% confidence). 
Key indicators: Feature_1, Feature_5, Feature_8 show patterns consistent with normal traffic. 
Service: HTTP Pattern matches typical behavior.
```

### Attack Traffic Explanation
```
Confidence Level: 92%
Probability - Normal: 0.08, Attack: 0.92

Key Indicators Supporting ATTACK Classification:
📊 Feature_12 - Distance to Normal: 8, Distance to Attack: 1
📊 Feature_15 - Distance to Normal: 9, Distance to Attack: 2
📊 Feature_18 - Distance to Normal: 7, Distance to Attack: 1

Reasoning: This is classified as ATTACK traffic with high confidence (92% confidence). 
Key indicators: Feature_12, Feature_15, Feature_18 show patterns consistent with attack traffic.

Attack Category: DoS
```

## Technical Details

### XAI Explainer Module (`src/xai_explainer.py`)

The module provides two main classes:

#### `QABNNExplainer`
- `explain_prediction()`: Generates comprehensive explanations for predictions
- `compare_samples()`: Compares two samples to understand differences
- `_get_top_discriminative_features()`: Identifies most important features
- `_generate_reasoning()`: Creates human-readable explanations

#### `FeatureImportanceCalculator`
- `calculate_binary_importance()`: Ranks features by their discriminative power
- `calculate_sample_importance()`: Shows which features are active in a sample

### Integration with Flask App

The explanation is generated during prediction:

1. **Load Model**: Model cache includes the explainer instance
2. **Make Prediction**: QABNN makes the attack/normal classification
3. **Generate Explanation**: QABNNExplainer analyzes the prediction
4. **Store with Sample**: Explanation stored alongside prediction results
5. **Display in UI**: Template renders explanation in expandable sections

### Feature Names

The system automatically uses column names from your dataset as feature names:
- Common features in UNSW-NB15: `dur`, `sbytes`, `dbytes`, `sttl`, `dttl`, `sload`, `dload`, `spkts`, `dpkts`, etc.
- This makes explanations easily interpretable by security analysts

## Benefits for Security Operations

1. **Trust in Detections**: Understand why traffic was flagged as suspicious
2. **Faster Investigation**: XAI shows key indicators, making triage faster
3. **Tuning Alerts**: Security teams can adjust sensitivity based on reasoning
4. **Compliance**: Explains model decisions for audit and compliance requirements
5. **Learning**: Network security team learns about attack patterns from explanations

## Future Enhancements

Possible extensions:
- LIME (Local Interpretable Model-agnostic Explanations) integration
- SHAP (SHapley Additive exPlanations) values
- Interactive feature importance visualization
- Anomaly score tracking over time
- Attack pattern clustering based on explanations

## Requirements

The XAI module requires:
- NumPy: For numerical computations
- Pandas: For data manipulation (already in requirements)
- sklearn: For preprocessing (already in requirements)

No additional packages need to be installed - XAI uses existing dependencies!

## Performance Impact

- **Minimal Overhead**: XAI explanations add ~1-5ms per prediction
- **Scalable**: Suitable for real-time and batch processing
- **Memory Efficient**: No additional large data structures needed

## Running with XAI

Simply run your application normally:

```bash
python app.py
```

The XAI explanations are automatically generated and displayed in the web interface. No configuration changes needed!

---

**Questions or Issues?** Check the sample explanations in the dashboard to understand model behavior and adjust your detection thresholds accordingly.
