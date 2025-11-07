# 🛡️ CTI-NLP Enhanced Threat Analyzer v2.0

**Advanced Cyber Threat Intelligence Platform with IP Tracking, Device Scanning & Real-time Alerts**

## 🌟 New Features in v2.0

### 🔍 IP Address Tracking
- **Real-time Connection Monitoring** - Track all active network connections
- **Geolocation Detection** - Identify IP origin (country, city, ISP)
- **Threat Intelligence Integration** - Check IPs against malicious databases
- **Automatic Alerts** - Get notified of suspicious connections

### 💾 Device & Drive Virus Scanner
- **USB Auto-Detection** - Automatically detect connected USB drives
- **Signature-Based Scanning** - Detect malware using virus signatures
- **Hash-Based Detection** - Identify known malicious files by hash
- **Quarantine System** - Isolate threats automatically
- **Recursive Directory Scanning** - Deep scan entire drives

### 🚨 Advanced Alert System
- **Multi-Level Alerts** - LOW, MEDIUM, HIGH, CRITICAL severity levels
- **Real-time Notifications** - Instant alerts for threats
- **Alert History** - Track all security events
- **Customizable Thresholds** - Configure alert sensitivity

### 📊 Enhanced Dashboard
- **Live Statistics** - Real-time security metrics
- **4-Mode Interface** - URL, CTI Reports, IP Tracking, Device Scanning
- **Visual Analytics** - Charts and graphs for threat data
- **Responsive Design** - Works on desktop, tablet, and mobile

---

## 🏗️ Project Architecture

```
CTI_PROJECT/
├── data/                           # Data storage
│   ├── url_dataset.csv            # URL training data
│   ├── cyber-threat-intelligence-all.csv
│   ├── malicious_ips.csv          # NEW - Known malicious IPs
│   ├── virus_signatures.json      # NEW - Virus signatures
│   └── trusted_ips.txt            # NEW - Trusted IP whitelist
│
├── modules/                        # NEW - Security modules
│   ├── __init__.py
│   ├── ip_tracker.py              # IP tracking & geolocation
│   ├── device_scanner.py          # USB/drive virus scanning
│   └── alert_system.py            # Alert management
│
├── logs/                           # NEW - System logs
│   ├── ip_tracking.log
│   ├── device_scans.log
│   ├── alerts.log
│   └── system.log
│
├── quarantine/                     # NEW - Isolated malicious files
│
├── app.py                          # ENHANCED - Flask API backend
├── index.html                      # ENHANCED - Frontend dashboard
├── model_training.ipynb            # Model training notebook
├── config.py                       # NEW - Configuration settings
├── requirements.txt                # NEW - Dependencies
├── .gitignore
└── README.md
```

---

## 🚀 Quick Start Guide

### Step 1: Install Dependencies

```bash
pip install -r requirements.txt
```

**Required packages:**
- Flask 3.0.0
- Flask-CORS 4.0.0
- pandas 2.1.4
- numpy 1.26.2
- scikit-learn 1.3.2
- psutil 5.9.6 (system monitoring)
- requests 2.31.0

### Step 2: Prepare Data Files

Ensure these files exist in the `data/` folder:
- `url_dataset.csv` - URL training data (with 'url' and 'type' columns)
- `cyber-threat-intelligence-all.csv` - CTI training data
- `malicious_ips.csv` - Known malicious IPs (created automatically if missing)
- `virus_signatures.json` - Virus signatures (created automatically)
- `trusted_ips.txt` - Trusted IP whitelist (optional)

### Step 3: Train Models

Open and run `model_training.ipynb` in Jupyter:

```bash
jupyter notebook model_training.ipynb
```

**Run all cells** to generate:
- `model.pkl` - CTI report classifier
- `feature_list.pkl` - CTI features
- `threat_encoder.pkl` - Threat label encoder
- `url_model.pkl` - URL threat classifier
- `url_feature_names.pkl` - URL features
- `url_label_encoder.pkl` - URL label encoder

### Step 4: Configure Settings (Optional)

Edit `config.py` to customize:
- Enable/disable features
- Set alert thresholds
- Configure API keys for threat intelligence
- Adjust scanning parameters

### Step 5: Start Backend API

**Terminal 1:**
```bash
python app.py
```

You should see:
```
✓ CTI Report Models loaded
✓ URL Models loaded
✓ IP Tracker initialized
✓ Device Scanner initialized
✓ Alert System initialized

 * Running on http://0.0.0.0:5000
```

### Step 6: Start Frontend Server

**Terminal 2:**
```bash
python -m http.server 8000
```

### Step 7: Access Dashboard

Open your browser and navigate to:
```
http://127.0.0.1:8000/index.html
```

---

## 📖 Usage Guide

### 1️⃣ URL Threat Analysis

**Analyze suspicious URLs for phishing, malware, and other threats.**

1. Select **"🌐 URL Analysis"** tab
2. Enter URL (e.g., `http://suspicious-paypal-login.com`)
3. Click **"Analyze URL"**
4. View:
   - Risk Score (0-100)
   - Threat Classification
   - Confidence Level
   - Probability Distribution

**Example URLs to Test:**
- ✅ Safe: `https://www.google.com`
- ⚠️ Suspicious: `http://bit.ly/xyz123` (URL shortener)
- 🚨 Malicious: `http://paypal-verify-account.tk`

### 2️⃣ CTI Report Analysis

**Classify cyber threat intelligence reports.**

1. Select **"📊 CTI Reports"** tab
2. Enter:
   - **Sentiment Score** (0.0-1.0): Higher = lower risk
   - **Severity Level** (1-5): 5 = maximum severity
3. Click **"Analyze Report"**

**Example Values:**
- Low Risk: Sentiment=0.9, Severity=1
- Medium Risk: Sentiment=0.5, Severity=3
- High Risk: Sentiment=0.2, Severity=5

### 3️⃣ IP Address Tracking (NEW)

**Monitor and analyze IP connections in real-time.**

**Option A: Track Specific IP**
1. Select **"🔍 IP Tracking"** tab
2. Enter IP address (e.g., `8.8.8.8`)
3. Click **"Track IP"**
4. View:
   - Threat Status
   - Geolocation (Country, City)
   - ISP Information
   - Risk Assessment

**Option B: Scan All Connections**
1. Click **"🔍 Scan All Connections"**
2. View all active network connections
3. See malicious connections highlighted
4. Automatic alerts for threats

**Use Cases:**
- Monitor unauthorized access attempts
- Detect botnet connections
- Identify suspicious foreign IPs
- Track connection patterns

### 4️⃣ Device & Drive Scanning (NEW)

**Scan USB drives and files for malware.**

**Scan Connected Drive:**
1. Select **"💾 Device Scan"** tab
2. View list of connected drives
3. Click **"Scan Drive"** on any drive
4. Wait for scan to complete
5. View:
   - Files scanned
   - Threats detected
   - Scan duration
   - Threat details

**Scan Custom Path:**
1. Enter directory path (e.g., `C:\Users\Downloads`)
2. Click **"Scan Device"**
3. Review results

**Features:**
- ✅ Signature-based detection
- ✅ Hash-based detection
- ✅ Heuristic analysis
- ✅ Automatic quarantine
- ✅ Ransomware detection

---

## 🔔 Alert System

### Alert Severity Levels

| Level | Icon | Description | Example |
|-------|------|-------------|---------|
| **LOW** | ℹ️ | Informational | Device connected |
| **MEDIUM** | ⚠️ | Suspicious activity | Unknown IP connection |
| **HIGH** | 🔴 | Confirmed threat | Malicious IP detected |
| **CRITICAL** | 🚨 | Active attack | Malware found on drive |

### Viewing Alerts

- **Live Alerts Panel** - Bottom of dashboard, auto-refreshes every 30 seconds
- **Click "🔄 Refresh"** - Manually update alerts
- **Filter by Severity** - Use API endpoint `/get_alerts?severity=HIGH`

### Alert Types

1. **Malicious IP Detected** - Suspicious connection attempt
2. **Malicious File Found** - Virus/malware detected
3. **Device Connected** - New USB drive plugged in
4. **Suspicious Activity** - Unusual behavior detected
5. **System Resource** - High CPU/memory usage

---

## 🔧 API Endpoints

### Original Endpoints

#### `POST /analyze`
Analyze CTI report
```json
{
  "sentiment": 0.75,
  "severity": 4
}
```

#### `POST /analyze_url`
Analyze URL for threats
```json
{
  "url": "http://suspicious-site.com"
}
```

### New Endpoints - IP Tracking

#### `POST /track_ip`
Track specific IP address
```json
{
  "ip_address": "192.168.1.100"
}
```

#### `GET /scan_connections`
Scan all active connections
```bash
curl http://localhost:5000/scan_connections
```

#### `GET /ip_statistics`
Get IP tracking statistics
```bash
curl http://localhost:5000/ip_statistics
```

### New Endpoints - Device Scanning

#### `GET /get_drives`
List all connected drives
```bash
curl http://localhost:5000/get_drives
```

#### `POST /scan_file`
Scan single file
```json
{
  "file_path": "/path/to/file.exe"
}
```

#### `POST /scan_directory`
Scan entire directory
```json
{
  "directory_path": "/path/to/scan",
  "recursive": true
}
```

#### `POST /quarantine_file`
Quarantine malicious file
```json
{
  "file_path": "/path/to/malware.exe"
}
```

#### `GET /scanner_statistics`
Get scanner statistics
```bash
curl http://localhost:5000/scanner_statistics
```

### New Endpoints - Alert System

#### `GET /get_alerts`
Get alerts with filters
```bash
# Get all alerts
curl http://localhost:5000/get_alerts

# Get only HIGH severity
curl http://localhost:5000/get_alerts?severity=HIGH&limit=10

# Get unacknowledged only
curl http://localhost:5000/get_alerts?unacknowledged_only=true
```

#### `GET /alert_statistics`
Get alert statistics
```bash
curl http://localhost:5000/alert_statistics
```

#### `POST /acknowledge_alert`
Acknowledge an alert
```json
{
  "alert_id": "alert_20240115_123456_789"
}
```

### Utility Endpoints

#### `GET /health`
Health check
```bash
curl http://localhost:5000/health
```

#### `GET /`
API information
```bash
curl http://localhost:5000/
```

---

## ⚙️ Configuration

### Enable External Threat Intelligence (Optional)

Edit `config.py` and add API keys:

```python
# Get free API keys:
# - AbuseIPDB: https://www.abuseipdb.com/
# - VirusTotal: https://www.virustotal.com/

ABUSEIPDB_API_KEY = 'your_key_here'
VIRUSTOTAL_API_KEY = 'your_key_here'
USE_EXTERNAL_THREAT_INTEL = True
```

### Customize Alert Thresholds

```python
# config.py
IP_ALERT_THRESHOLD = 5  # Alerts after 5 suspicious connections
CPU_ALERT_THRESHOLD = 90  # Alert if CPU > 90%
MEMORY_ALERT_THRESHOLD = 85  # Alert if memory > 85%
```

### Auto-Quarantine Settings

```python
# config.py
AUTO_QUARANTINE = True  # Automatically quarantine threats
QUARANTINE_RETENTION_DAYS = 30  # Keep files for 30 days
```

---

## 🧪 Testing

### Test IP Tracker
```bash
cd modules
python ip_tracker.py
```

### Test Device Scanner
```bash
cd modules
python device_scanner.py
```

### Test Alert System
```bash
cd modules
python alert_system.py
```

---

## 🛠️ Troubleshooting

### Issue: "Models not loaded"
**Solution:** Run `model_training.ipynb` to generate .pkl files

### Issue: "Permission denied" when scanning
**Solution:** Run as administrator/sudo for system-level access

### Issue: "No drives detected"
**Solution:** Ensure USB drives are properly mounted

### Issue: "Connection refused" errors
**Solution:** Check if backend is running on port 5000

### Issue: "CORS errors"
**Solution:** Use `python -m http.server` to serve frontend

---

## 📊 Performance Tips

1. **Large Directories**: Limit scans to 5000 files using `max_files` parameter
2. **Slow Scans**: Skip large files by setting `MAX_FILE_SIZE_MB` in config
3. **API Rate Limits**: Enable caching for external threat intelligence APIs
4. **Memory Usage**: Clear old alerts periodically

---

## 🔐 Security Best Practices

1. **Never disable quarantine** in production environments
2. **Review alerts regularly** - Check dashboard daily
3. **Update signatures** - Keep virus database current
4. **Monitor logs** - Check `logs/` directory for anomalies
5. **Use HTTPS** - Enable SSL in production deployments
6. **Restrict API access** - Add authentication for sensitive endpoints

---

## 🤝 Contributing

Contributions are welcome! Areas for improvement:
- Additional virus signatures
- Machine learning model improvements
- Real-time WebSocket alerts
- Email notification integration
- Mobile app support

---

## 📄 License

MIT License - Free to use and modify

---

## 👨‍💻 Version History

### v2.0.0 (Current) - Enhanced Security Platform
- ✅ IP address tracking and geolocation
- ✅ USB/drive virus scanning
- ✅ Real-time alert system
- ✅ Multi-mode dashboard
- ✅ Quarantine management

### v1.0.0 - Initial Release
- URL threat analysis
- CTI report classification
- Basic risk scoring

---

## 📞 Support

For issues, questions, or feature requests:
1. Check the troubleshooting section
2. Review logs in `logs/` directory
3. Test individual modules using the test commands above

---

**🛡️ Stay Safe. Stay Secure. Stay Protected.**

*CTI-NLP Enhanced Threat Analyzer v2.0 - Advanced Cybersecurity Platform*