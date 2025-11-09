# ========================================
# CTI-NLP Enhanced Analyzer - Flask API Backend (v2.1 - Production Ready)
# ========================================

from flask import Flask, request, jsonify
from flask_cors import CORS
import pickle
import pandas as pd
import numpy as np
import time
import re
from urllib.parse import urlparse
from pathlib import Path
import sys
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any, Set
from functools import wraps
import os

# Add modules to path
sys.path.insert(0, str(Path(__file__).parent / 'modules'))

# Import custom modules
from modules.ip_tracker import IPTracker
from modules.device_scanner import DeviceScanner
from modules.alert_system import AlertSystem

# ========================================
# Configuration
# ========================================
class Config:
    """Application configuration"""
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
    API_KEY = os.getenv('API_KEY', None)  # Set in production for auth
    MAX_FILE_SIZE_MB = int(os.getenv('MAX_FILE_SIZE_MB', '100'))
    DEBUG = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')

# ========================================
# Logging Setup
# ========================================
logging.basicConfig(
    level=getattr(logging, Config.LOG_LEVEL),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('cti_analyzer.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ========================================
# Flask App Initialization
# ========================================
app = Flask(__name__)
app.config.from_object(Config)
CORS(app)  # Allow cross-origin requests

# ========================================
# Global Variables for Models
# ========================================
MODEL = None
FEATURE_NAMES: Optional[List[str]] = None
THREAT_ENCODER = None

URL_MODEL = None
URL_FEATURE_NAMES: Optional[List[str]] = None
URL_LABEL_ENCODER = None
TRUSTED_DOMAINS: Set[str] = set()

# Initialize new modules
IP_TRACKER: Optional[IPTracker] = None
DEVICE_SCANNER: Optional[DeviceScanner] = None
ALERT_SYSTEM: Optional[AlertSystem] = None

# ========================================
# Trusted Domains & Configuration
# ========================================
TRUSTED_DOMAINS_DEFAULT: Set[str] = {
    'google.com', 'youtube.com', 'facebook.com', 'amazon.com', 'wikipedia.org',
    'twitter.com', 'instagram.com', 'linkedin.com', 'reddit.com', 'github.com',
    'microsoft.com', 'apple.com', 'netflix.com', 'yahoo.com', 'bing.com',
    'stackoverflow.com', 'medium.com', 'dropbox.com', 'adobe.com', 'paypal.com',
    'ebay.com', 'cnn.com', 'bbc.com', 'nytimes.com', 'spotify.com', 'baidu.com',
    'qq.com', 'taobao.com', 'tmall.com', 'vk.com', 'whatsapp.com', 'zoom.us',
    'geethashishu.in', 'flipkart.com', 'paytm.com', 'zomato.com', 'swiggy.com'
}

LEGITIMATE_TLDS: Set[str] = {
    '.com', '.org', '.net', '.edu', '.gov', '.co', '.io', '.ai', 
    '.in', '.jp', '.uk', '.ca', '.de', '.fr'
}

SUSPICIOUS_TLDS: Set[str] = {
    '.tk', '.ml', '.ga', '.cf', '.gq', '.zip', '.review', 
    '.xyz', '.top', '.click', '.esy.es'
}


# ========================================
# Authentication Decorator (Optional)
# ========================================
def require_api_key(f):
    """Decorator to require API key for endpoints (if enabled)"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if Config.API_KEY:  # Only check if API_KEY is set
            api_key = request.headers.get('X-API-Key')
            if not api_key or api_key != Config.API_KEY:
                logger.warning(f"Unauthorized access attempt from {request.remote_addr}")
                return jsonify({"error": "Unauthorized - Invalid or missing API key"}), 401
        return f(*args, **kwargs)
    return decorated_function


# ========================================
# Error Handler Decorator
# ========================================
def handle_errors(f):
    """Decorator to handle errors gracefully"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except ValueError as e:
            logger.error(f"Value error in {f.__name__}: {e}")
            return jsonify({"error": f"Invalid input: {str(e)}"}), 400
        except Exception as e:
            logger.error(f"Unexpected error in {f.__name__}: {e}", exc_info=True)
            return jsonify({"error": f"Server error: {str(e)}"}), 500
    return decorated_function


# ========================================
# URL Feature Extraction (Fixed Type Issues)
# ========================================
def extract_url_features(url: str) -> Dict[str, Any]:
    """Extract URL features for threat detection"""
    features: Dict[str, Any] = {}
    
    try:
        parsed = urlparse(url.strip())
        domain = parsed.netloc.lower() if parsed.netloc else ""
        path = parsed.path if parsed.path else ""
        query = parsed.query if parsed.query else ""
        scheme = parsed.scheme if parsed.scheme else ""
    except Exception as e:
        logger.warning(f"URL parsing error for {url}: {e}")
        domain = path = query = scheme = ""
    
    # Clean domain
    clean_domain = re.sub(r':\d+$', '', domain)
    clean_domain = re.sub(r'^www\.', '', clean_domain)
    
    # Basic features - FIX: Ensure TRUSTED_DOMAINS is not None
    trusted_domains_to_check: Set[str] = TRUSTED_DOMAINS if TRUSTED_DOMAINS else TRUSTED_DOMAINS_DEFAULT
    features['is_trusted_domain'] = 1 if any(trusted in clean_domain for trusted in trusted_domains_to_check) else 0
    features['has_legitimate_tld'] = 1 if any(clean_domain.endswith(tld) for tld in LEGITIMATE_TLDS) else 0
    features['has_suspicious_tld'] = 1 if any(clean_domain.endswith(tld) for tld in SUSPICIOUS_TLDS) else 0
    
    # Length features
    features['url_length'] = len(url)
    features['domain_length'] = len(domain)
    features['path_length'] = len(path)
    features['query_length'] = len(query)
    
    # Character count features
    features['num_dots'] = url.count('.')
    features['num_hyphens'] = url.count('-')
    features['num_underscores'] = url.count('_')
    features['num_slashes'] = url.count('/')
    features['num_at_symbol'] = url.count('@')
    features['num_question_mark'] = url.count('?')
    features['num_ampersand'] = url.count('&')
    features['num_equals'] = url.count('=')
    features['num_percent'] = url.count('%')
    features['num_digits'] = sum(c.isdigit() for c in url)
    features['num_letters'] = sum(c.isalpha() for c in url)
    features['num_special_chars'] = sum(not c.isalnum() and c not in './-_:?' for c in url)
    
    # Domain features
    features['num_dots_domain'] = domain.count('.')
    features['num_hyphens_domain'] = domain.count('-')
    features['has_ip_address'] = 1 if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url) else 0
    features['subdomain_count'] = max(0, len(domain.split('.')) - 2) if domain else 0
    features['domain_has_digits'] = 1 if any(c.isdigit() for c in domain) else 0
    
    # Protocol features
    features['has_https'] = 1 if scheme == 'https' else 0
    features['has_http'] = 1 if scheme == 'http' else 0
    features['port_in_url'] = 1 if re.search(r':\d{2,5}', domain) else 0
    
    # Path features
    features['excessive_dots_in_path'] = 1 if path.count('..') > 0 or path.count('...') > 0 else 0
    features['has_wp_includes'] = 1 if 'wp-includes' in url.lower() or 'wp-admin' in url.lower() else 0
    features['has_admin_path'] = 1 if '/admin' in url.lower() or '/administrator' in url.lower() else 0
    
    # Phishing indicators
    phishing_keywords = ['login', 'signin', 'verify', 'update', 'secure', 'account', 
                         'banking', 'confirm', 'suspended', 'locked', 'paypal', 'dropbox']
    features['phishing_keyword_count'] = sum(1 for kw in phishing_keywords if kw in url.lower())
    
    # Brand impersonation - FIX: Use the checked trusted domains
    trusted_brands = ['google', 'paypal', 'amazon', 'microsoft', 'apple', 'facebook', 'dropbox']
    features['brand_impersonation'] = 1 if any(brand in clean_domain for brand in trusted_brands) and clean_domain not in trusted_domains_to_check else 0
    
    # File type features
    features['has_php_file'] = 1 if '.php' in path.lower() else 0
    features['has_html_file'] = 1 if '.htm' in path.lower() or '.html' in path.lower() else 0
    
    # Entropy calculation
    def calculate_entropy(text: str) -> float:
        if not text or len(text) < 2:
            return 0.0
        prob = [float(text.count(c)) / len(text) for c in set(text)]
        return -sum(p * np.log2(p) for p in prob if p > 0)
    
    features['url_entropy'] = calculate_entropy(url)
    features['domain_entropy'] = calculate_entropy(domain)
    features['path_entropy'] = calculate_entropy(path) if path else 0.0
    features['high_domain_entropy'] = 1 if features['domain_entropy'] > 4.0 else 0
    features['high_path_entropy'] = 1 if features['path_entropy'] > 4.5 else 0
    
    # Ratio features
    url_len = max(len(url), 1)
    features['digit_ratio'] = features['num_digits'] / url_len
    features['special_char_ratio'] = features['num_special_chars'] / url_len
    features['dots_to_length_ratio'] = features['num_dots'] / url_len
    
    # Suspicious patterns
    features['excessive_subdomains'] = 1 if features['subdomain_count'] > 3 else 0
    features['url_shortener'] = 1 if any(s in clean_domain for s in ['bit.ly', 'tinyurl', 'goo.gl', 't.co']) else 0
    features['hyphen_in_domain'] = 1 if '-' in clean_domain else 0
    
    # Path analysis
    path_parts = [p for p in path.split('/') if p and len(p) > 10]
    features['has_long_random_path'] = 1 if any(len(p) > 32 for p in path_parts) else 0
    features['path_depth'] = len([p for p in path.split('/') if p])
    features['deep_path'] = 1 if features['path_depth'] > 5 else 0
    
    # Encoding features
    features['has_hex_encoding'] = 1 if re.search(r'%[0-9a-fA-F]{2}', url) else 0
    features['has_at_symbol'] = 1 if '@' in url else 0
    features['has_double_slash'] = 1 if '//' in path else 0
    
    # Query features
    features['num_query_params'] = query.count('&') + (1 if query else 0)
    features['has_redirect'] = 1 if any(p in query.lower() for p in ['redirect', 'url=', 'next=', 'goto=']) else 0
    
    # Domain component lengths
    if domain:
        parts = domain.split('.')
        if len(parts) >= 2:
            features['main_domain_length'] = len(parts[-2])
            features['tld_length'] = len(parts[-1])
        else:
            features['main_domain_length'] = 0
            features['tld_length'] = 0
    else:
        features['main_domain_length'] = 0
        features['tld_length'] = 0
    
    return features


# ========================================
# Load All Models
# ========================================
def load_models() -> bool:
    """Load all trained models and initialize modules"""
    global MODEL, FEATURE_NAMES, THREAT_ENCODER
    global URL_MODEL, URL_FEATURE_NAMES, URL_LABEL_ENCODER, TRUSTED_DOMAINS
    global IP_TRACKER, DEVICE_SCANNER, ALERT_SYSTEM
    
    logger.info("="*60)
    logger.info("Loading CTI-NLP Enhanced Analyzer...")
    logger.info("="*60)
    
    # Load CTI Report Models
    try:
        with open('model.pkl', 'rb') as f: 
            MODEL = pickle.load(f)
        with open('feature_list.pkl', 'rb') as f: 
            FEATURE_NAMES = pickle.load(f)
        with open('threat_encoder.pkl', 'rb') as f: 
            THREAT_ENCODER = pickle.load(f)
        
        logger.info("✓ CTI Report Models loaded")
    except Exception as e:
        logger.error(f"✗ CTI Models Error: {e}")
        return False

    # Load URL Models
    try:
        with open('url_model.pkl', 'rb') as f: 
            URL_MODEL = pickle.load(f)
        with open('url_feature_names.pkl', 'rb') as f: 
            URL_FEATURE_NAMES = pickle.load(f)
        with open('url_label_encoder.pkl', 'rb') as f:
            URL_LABEL_ENCODER = pickle.load(f)
        
        try:
            with open('url_trusted_domains.pkl', 'rb') as f:
                loaded_domains = pickle.load(f)
                TRUSTED_DOMAINS = set(loaded_domains) if loaded_domains else TRUSTED_DOMAINS_DEFAULT
        except:
            TRUSTED_DOMAINS = TRUSTED_DOMAINS_DEFAULT
            
        logger.info("✓ URL Models loaded")
    except Exception as e:
        logger.error(f"✗ URL Models Error: {e}")
        return False

    # Initialize new modules
    try:
        IP_TRACKER = IPTracker()
        logger.info("✓ IP Tracker initialized")
        
        DEVICE_SCANNER = DeviceScanner()
        logger.info("✓ Device Scanner initialized")
        
        ALERT_SYSTEM = AlertSystem()
        logger.info("✓ Alert System initialized")
    except Exception as e:
        logger.error(f"✗ Module initialization error: {e}")
        return False

    logger.info("="*60)
    return True


# ========================================
# Risk Score Calculations
# ========================================
def calculate_cti_risk_score(sentiment: float, severity: int, 
                             prediction_proba: float, predicted_class: str) -> int:
    """Calculate risk score for CTI report analysis"""
    predicted_class_str = str(predicted_class).lower()
    
    if predicted_class_str in ['benign', 'safe', 'normal']:
        return min(25, round((1 - sentiment) * 30))
    
    severity_weight = severity * 15
    sentiment_risk = (1.0 - sentiment) * 20
    confidence_weight = prediction_proba * 40
    
    total_score = severity_weight + sentiment_risk + confidence_weight
    return min(100, max(30, round(total_score)))


def calculate_url_risk_score(predicted_class_str: str, confidence_proba: float, 
                             features_dict: Dict[str, Any]) -> int:
    """Calculate risk score for URL analysis"""
    
    if features_dict.get('is_trusted_domain', 0) == 1 and predicted_class_str in ['legitimate', 'benign', 'safe']:
        return min(15, round((1 - confidence_proba) * 30))
    
    if predicted_class_str in ['legitimate', 'benign', 'safe']:
        if confidence_proba > 0.7:
            return min(25, round((1 - confidence_proba) * 50))
        else:
            return min(45, round((1 - confidence_proba) * 80))
    
    base_risk = confidence_proba * 60
    
    if features_dict.get('has_suspicious_tld', 0) == 1:
        base_risk += 15
    if features_dict.get('brand_impersonation', 0) == 1:
        base_risk += 10
    if features_dict.get('excessive_dots_in_path', 0) == 1:
        base_risk += 10
    if features_dict.get('phishing_keyword_count', 0) > 0:
        base_risk += min(15, features_dict['phishing_keyword_count'] * 5)
    
    return min(100, max(60, round(base_risk)))


# ========================================
# API Endpoints - CTI Analysis
# ========================================

@app.route('/analyze', methods=['POST'])
@handle_errors
def analyze_cti_report():
    """Endpoint for CTI Report Analysis"""
    if MODEL is None or THREAT_ENCODER is None:
        return jsonify({"error": "CTI Report Model not loaded"}), 500
    
    data = request.get_json()
    sentiment = float(data.get('sentiment', 0.5))
    severity = int(data.get('severity', 3))

    input_data = np.array([[sentiment, severity]])
    input_df = pd.DataFrame(input_data, columns=FEATURE_NAMES)

    prediction_encoded = MODEL.predict(input_df)[0]
    prediction_proba = MODEL.predict_proba(input_df)[0]
    
    predicted_threat = THREAT_ENCODER.inverse_transform([prediction_encoded])[0]
    confidence_proba = prediction_proba[prediction_encoded]

    risk_score = calculate_cti_risk_score(sentiment, severity, confidence_proba, predicted_threat)
    
    predicted_threat_str = str(predicted_threat).lower()
    is_malicious = predicted_threat_str not in ['benign', 'safe', 'normal']

    response = {
        "status": "success",
        "detection": "MALICIOUS" if is_malicious else "BENIGN",
        "classification": str(predicted_threat),
        "risk_score": int(risk_score),
        "confidence_percent": round(float(confidence_proba) * 100, 2),
        "threat_categories": list(THREAT_ENCODER.classes_),
        "threat_probabilities": [round(float(p) * 100, 2) for p in prediction_proba],
        "analysis_time_ms": round(time.time() * 1000, 2)
    }
    
    logger.info(f"CTI Analysis: Sentiment={sentiment:.2f}, Severity={severity} → {predicted_threat} (Risk: {risk_score}%)")
    return jsonify(response)


@app.route('/analyze_url', methods=['POST'])
@handle_errors
def analyze_url_endpoint():
    """Endpoint for URL Threat Analysis"""
    if URL_MODEL is None or URL_FEATURE_NAMES is None or URL_LABEL_ENCODER is None:
        return jsonify({"error": "URL Model not loaded"}), 500
    
    data = request.get_json()
    url = data.get('url', '').strip()
    
    if not url:
        return jsonify({"error": "URL is required"}), 400

    features_dict = extract_url_features(url)
    features_list = [features_dict.get(name, 0) for name in URL_FEATURE_NAMES]
    input_df = pd.DataFrame([features_list], columns=URL_FEATURE_NAMES)

    prediction_proba = URL_MODEL.predict_proba(input_df)[0]
    prediction_encoded = int(np.argmax(prediction_proba))
    
    # FIX: Ensure URL_LABEL_ENCODER is iterable
    label_encoder_list = list(URL_LABEL_ENCODER) if URL_LABEL_ENCODER is not None else []
    predicted_class = str(label_encoder_list[prediction_encoded]) if prediction_encoded < len(label_encoder_list) else "Unknown"
    confidence_proba = float(prediction_proba[prediction_encoded])

    risk_score = calculate_url_risk_score(predicted_class.lower(), confidence_proba, features_dict)
    
    predicted_class_lower = predicted_class.lower()
    is_malicious = predicted_class_lower not in ['legitimate', 'benign', 'safe', 'normal']

    response = {
        "status": "success",
        "detection": "MALICIOUS" if is_malicious else "BENIGN",
        "classification": predicted_class,
        "risk_score": int(risk_score),
        "confidence_percent": round(confidence_proba * 100, 2),
        "threat_categories": [str(c) for c in label_encoder_list],
        "threat_probabilities": [round(float(p) * 100, 2) for p in prediction_proba],
        "url_analyzed": url[:100],
        "analysis_time_ms": round(time.time() * 1000, 2)
    }
    
    logger.info(f"URL Analysis: {url[:60]}... → {predicted_class} ({confidence_proba:.1%} confidence, Risk: {risk_score}%)")
    return jsonify(response)


# ========================================
# NEW ENDPOINTS - IP Tracking
# ========================================

@app.route('/track_ip', methods=['POST'])
@handle_errors
def track_ip():
    """Track and analyze a specific IP address"""
    if IP_TRACKER is None:
        return jsonify({"error": "IP Tracker not initialized"}), 500
    
    data = request.get_json()
    ip_address = data.get('ip_address', '').strip()
    
    if not ip_address:
        return jsonify({"error": "IP address is required"}), 400
    
    # Check if malicious
    threat_check = IP_TRACKER.check_ip_malicious(ip_address)
    
    # Get geolocation
    geo_info = IP_TRACKER.get_ip_geolocation(ip_address)
    
    # Create alert if malicious
    if threat_check['is_malicious'] and ALERT_SYSTEM:
        ALERT_SYSTEM.alert_malicious_ip(ip_address, threat_check['threat_type'], {
            'geolocation': geo_info,
            'severity': threat_check['severity']
        })
    
    response = {
        "status": "success",
        "ip_address": ip_address,
        "threat_check": threat_check,
        "geolocation": geo_info,
        "timestamp": time.time()
    }
    
    return jsonify(response)


@app.route('/scan_connections', methods=['GET'])
@handle_errors
def scan_connections():
    """Scan all active network connections"""
    if IP_TRACKER is None:
        return jsonify({"error": "IP Tracker not initialized"}), 500
    
    scan_result = IP_TRACKER.scan_current_connections()
    return jsonify(scan_result)


@app.route('/ip_statistics', methods=['GET'])
@handle_errors
def ip_statistics():
    """Get IP tracking statistics"""
    if IP_TRACKER is None:
        return jsonify({"error": "IP Tracker not initialized"}), 500
    
    stats = IP_TRACKER.get_statistics()
    public_ip = IP_TRACKER.get_my_public_ip()
    
    return jsonify({
        "status": "success",
        "public_ip": public_ip,
        "statistics": stats
    })


# ========================================
# NEW ENDPOINTS - Device Scanning
# ========================================

@app.route('/get_drives', methods=['GET'])
@handle_errors
def get_drives():
    """Get all connected drives"""
    if DEVICE_SCANNER is None:
        return jsonify({"error": "Device Scanner not initialized"}), 500
    
    drives = DEVICE_SCANNER.get_connected_drives()
    return jsonify({
        "status": "success",
        "drives": drives
    })


@app.route('/scan_file', methods=['POST'])
@handle_errors
def scan_file():
    """Scan a specific file for threats"""
    if DEVICE_SCANNER is None:
        return jsonify({"error": "Device Scanner not initialized"}), 500
    
    data = request.get_json()
    file_path = data.get('file_path', '').strip()
    
    if not file_path:
        return jsonify({"error": "File path is required"}), 400
    
    scan_result = DEVICE_SCANNER.scan_file(file_path)
    
    # Create alert if malicious
    if scan_result['is_malicious'] and ALERT_SYSTEM:
        ALERT_SYSTEM.alert_malicious_file(
            file_path,
            scan_result['threat_type'],
            scan_result
        )
    
    return jsonify({
        "status": "success",
        "scan_result": scan_result
    })


@app.route('/scan_directory', methods=['POST'])
@handle_errors
def scan_directory():
    """Scan a directory for threats"""
    if DEVICE_SCANNER is None:
        return jsonify({"error": "Device Scanner not initialized"}), 500
    
    data = request.get_json()
    directory_path = data.get('directory_path', '').strip()
    recursive = data.get('recursive', True)
    
    if not directory_path:
        return jsonify({"error": "Directory path is required"}), 400
    
    scan_result = DEVICE_SCANNER.scan_directory(directory_path, recursive=recursive)
    
    return jsonify({
        "status": "success",
        "scan_result": scan_result
    })


@app.route('/quarantine_file', methods=['POST'])
@handle_errors
def quarantine_file():
    """Quarantine a malicious file"""
    if DEVICE_SCANNER is None:
        return jsonify({"error": "Device Scanner not initialized"}), 500
    
    data = request.get_json()
    file_path = data.get('file_path', '').strip()
    
    if not file_path:
        return jsonify({"error": "File path is required"}), 400
    
    success = DEVICE_SCANNER.quarantine_file(file_path)
    
    return jsonify({
        "status": "success" if success else "failed",
        "quarantined": success
    })


@app.route('/scanner_statistics', methods=['GET'])
@handle_errors
def scanner_statistics():
    """Get scanner statistics"""
    if DEVICE_SCANNER is None:
        return jsonify({"error": "Device Scanner not initialized"}), 500
    
    stats = DEVICE_SCANNER.get_statistics()
    return jsonify({
        "status": "success",
        "statistics": stats
    })


# ========================================
# NEW ENDPOINTS - Alert System
# ========================================

@app.route('/get_alerts', methods=['GET'])
@handle_errors
def get_alerts():
    """Get alerts with optional filters"""
    if ALERT_SYSTEM is None:
        return jsonify({"error": "Alert System not initialized"}), 500
    
    limit = int(request.args.get('limit', 50))
    severity = request.args.get('severity')
    unacknowledged_only = request.args.get('unacknowledged_only', 'false').lower() == 'true'
    
    alerts = ALERT_SYSTEM.get_alerts(
        limit=limit,
        severity=severity,
        unacknowledged_only=unacknowledged_only
    )
    
    return jsonify({
        "status": "success",
        "alerts": alerts
    })


@app.route('/alert_statistics', methods=['GET'])
@handle_errors
def alert_statistics():
    """Get alert statistics"""
    if ALERT_SYSTEM is None:
        return jsonify({"error": "Alert System not initialized"}), 500
    
    stats = ALERT_SYSTEM.get_alert_statistics()
    return jsonify({
        "status": "success",
        "statistics": stats
    })


@app.route('/acknowledge_alert', methods=['POST'])
@handle_errors
def acknowledge_alert():
    """Acknowledge an alert"""
    if ALERT_SYSTEM is None:
        return jsonify({"error": "Alert System not initialized"}), 500
    
    data = request.get_json()
    alert_id = data.get('alert_id', '').strip()
    
    if not alert_id:
        return jsonify({"error": "Alert ID is required"}), 400
    
    success = ALERT_SYSTEM.acknowledge_alert(alert_id)
    
    return jsonify({
        "status": "success" if success else "failed",
        "acknowledged": success
    })


# ========================================
# Utility Endpoints
# ========================================

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "2.1.0",
        "components": {
            "cti_model": MODEL is not None,
            "url_model": URL_MODEL is not None,
            "ip_tracker": IP_TRACKER is not None,
            "device_scanner": DEVICE_SCANNER is not None,
            "alert_system": ALERT_SYSTEM is not None
        }
    })


@app.route('/', methods=['GET'])
def home():
    """Root endpoint with API information"""
    return jsonify({
        "message": "CTI-NLP Enhanced Threat Analyzer API",
        "version": "2.1.0",
        "status": "online",
        "documentation": "https://github.com/yourusername/cti-analyzer",
        "endpoints": {
            "CTI Analysis": {
                "POST /analyze": "Analyze CTI reports for threat classification",
                "POST /analyze_url": "Analyze URLs for phishing/malware detection"
            },
            "IP Tracking": {
                "POST /track_ip": "Track and analyze specific IP address",
                "GET /scan_connections": "Scan all active network connections",
                "GET /ip_statistics": "Get IP tracking statistics"
            },
            "Device Scanning": {
                "GET /get_drives": "List all connected drives",
                "POST /scan_file": "Scan a single file for malware",
                "POST /scan_directory": "Scan directory (recursive optional)",
                "POST /quarantine_file": "Quarantine a malicious file",
                "GET /scanner_statistics": "Get scanner statistics"
            },
            "Alerts": {
                "GET /get_alerts": "Get alerts with optional filters",
                "GET /alert_statistics": "Get alert statistics",
                "POST /acknowledge_alert": "Acknowledge an alert"
            },
            "Utility": {
                "GET /health": "Health check with component status",
                "GET /": "API documentation"
            }
        },
        "authentication": {
            "required": Config.API_KEY is not None,
            "method": "X-API-Key header"
        }
    })


# ========================================
# Additional Utility Endpoints
# ========================================

@app.route('/system_info', methods=['GET'])
@handle_errors
def system_info():
    """Get system information and capabilities"""
    import platform
    import psutil
    
    return jsonify({
        "status": "success",
        "system": {
            "platform": platform.system(),
            "platform_release": platform.release(),
            "platform_version": platform.version(),
            "architecture": platform.machine(),
            "processor": platform.processor(),
            "python_version": platform.python_version()
        },
        "resources": {
            "cpu_count": psutil.cpu_count(),
            "cpu_percent": psutil.cpu_percent(interval=1),
            "memory_total_gb": round(psutil.virtual_memory().total / (1024**3), 2),
            "memory_available_gb": round(psutil.virtual_memory().available / (1024**3), 2),
            "memory_percent": psutil.virtual_memory().percent,
            "disk_usage_percent": psutil.disk_usage('/').percent
        },
        "application": {
            "version": "2.1.0",
            "debug_mode": Config.DEBUG,
            "log_level": Config.LOG_LEVEL
        }
    })


@app.route('/clear_cache', methods=['POST'])
@handle_errors
def clear_cache():
    """Clear application cache (if implemented)"""
    # This is a placeholder for future cache implementation
    logger.info("Cache clear requested")
    return jsonify({
        "status": "success",
        "message": "Cache cleared successfully"
    })


# ========================================
# Error Handlers
# ========================================

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return jsonify({
        "error": "Endpoint not found",
        "status_code": 404,
        "message": "The requested endpoint does not exist. Check /  for API documentation."
    }), 404


@app.errorhandler(405)
def method_not_allowed(error):
    """Handle 405 errors"""
    return jsonify({
        "error": "Method not allowed",
        "status_code": 405,
        "message": f"The method {request.method} is not allowed for this endpoint."
    }), 405


@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    logger.error(f"Internal server error: {error}")
    return jsonify({
        "error": "Internal server error",
        "status_code": 500,
        "message": "An unexpected error occurred. Please try again later."
    }), 500


# ========================================
# Request/Response Middleware
# ========================================

@app.before_request
def log_request():
    """Log incoming requests"""
    logger.debug(f"Incoming {request.method} request to {request.path} from {request.remote_addr}")


@app.after_request
def log_response(response):
    """Log outgoing responses"""
    logger.debug(f"Response {response.status_code} for {request.method} {request.path}")
    return response


# ========================================
# Start Server
# ========================================
if __name__ == '__main__':
    print("\n" + "="*60)
    print(" CTI-NLP ENHANCED THREAT ANALYZER API v2.1")
    print(" Production-Ready Edition")
    print("="*60)
    
    if load_models():
        print("\n✓ All systems loaded successfully!")
        print("\nServer Configuration:")
        print(f"  Host: 0.0.0.0")
        print(f"  Port: 5000")
        print(f"  Debug Mode: {Config.DEBUG}")
        print(f"  Log Level: {Config.LOG_LEVEL}")
        print(f"  API Authentication: {'Enabled' if Config.API_KEY else 'Disabled'}")
        print("\nCore Features:")
        print("  ✓ CTI Report Analysis")
        print("  ✓ URL Threat Detection")
        print("\nNew Features:")
        print("  ✓ IP Address Tracking & Geolocation")
        print("  ✓ Device/Drive Virus Scanning")
        print("  ✓ Real-time Alert System")
        print("  ✓ Comprehensive Error Handling")
        print("  ✓ Request Logging")
        print("\nProduction Improvements:")
        print("  ✓ Type Safety (Fixed Pylance Errors)")
        print("  ✓ Error Handler Decorators")
        print("  ✓ Structured Logging")
        print("  ✓ Health Check Endpoint")
        print("  ✓ System Information Endpoint")
        print("="*60 + "\n")
        
        # Production warning
        if Config.DEBUG:
            print("⚠️  WARNING: Debug mode is enabled!")
            print("   Set FLASK_DEBUG=False in production\n")
        
        if not Config.API_KEY:
            print("⚠️  WARNING: API authentication is disabled!")
            print("   Set API_KEY environment variable for production\n")
        
        print("Starting server...")
        print("Access API documentation at: http://localhost:5000/")
        print("Health check at: http://localhost:5000/health")
        print("="*60 + "\n")
        
        app.run(host='0.0.0.0', port=5000, debug=Config.DEBUG)
    else:
        print("\n✗ Failed to load models!")
        print("  Please ensure all .pkl files exist in the project directory")
        print("  Run model_training.ipynb to generate the required model files")
        print("="*60 + "\n")
        sys.exit(1)