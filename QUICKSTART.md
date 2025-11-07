# 🚀 Quick Start Guide - CTI-NLP Enhanced Analyzer v2.0

## ⚡ 5-Minute Setup

### Step 1: Run Setup Script
```bash
python setup.py
```

This will:
- ✅ Check Python version
- ✅ Create directories
- ✅ Install dependencies
- ✅ Verify files

### Step 2: Train Models
```bash
jupyter notebook model_training.ipynb
```
- Run all cells (Shift+Enter)
- Wait for completion (~2-5 minutes)
- Close Jupyter when done

### Step 3: Start Backend
**Terminal 1:**
```bash
python app.py
```
Wait for: `✓ All systems loaded successfully!`

### Step 4: Start Frontend
**Terminal 2:**
```bash
python -m http.server 8000
```

### Step 5: Open Dashboard
```
http://127.0.0.1:8000/index.html
```

---

## 🎯 First Test

### Test URL Analysis
1. Click **"🌐 URL Analysis"** tab
2. Default URL already loaded: `http://login-verify-paypal.com/update/index.php`
3. Click **"Analyze URL"**
4. See results: Risk score, threat type, confidence

### Test IP Tracking
1. Click **"🔍 IP Tracking"** tab
2. Click **"🔍 Scan All Connections"**
3. View active network connections
4. See if any are malicious

### Test Device Scanning
1. Plug in USB drive (optional)
2. Click **"💾 Device Scan"** tab
3. See list of connected drives
4. Click **"Scan Drive"** on any drive

---

## 📁 Required Files Checklist

Before running, ensure you have:

### Training Data (in `data/` folder)
- [ ] `url_dataset.csv` - **REQUIRED** for URL model
- [ ] `cyber-threat-intelligence-all.csv` - Optional for CTI model

### After Training (generated automatically)
- [ ] `model.pkl`
- [ ] `feature_list.pkl`
- [ ] `threat_encoder.pkl`
- [ ] `url_model.pkl`
- [ ] `url_feature_names.pkl`
- [ ] `url_label_encoder.pkl`

### Auto-Generated (created on first run)
- [ ] `data/malicious_ips.csv`
- [ ] `data/virus_signatures.json`
- [ ] `data/trusted_ips.txt`

---

## 🔧 Common Issues & Fixes

### Issue: "Module not found"
```bash
pip install -r requirements.txt
```

### Issue: "Model not loaded"
```bash
# Run training notebook first
jupyter notebook model_training.ipynb
```

### Issue: "Port already in use"
```bash
# Kill process on port 5000
# Windows:
netstat -ano | findstr :5000
taskkill /PID <PID> /F

# Linux/Mac:
lsof -ti:5000 | xargs kill -9
```

### Issue: "Permission denied" when scanning
```bash
# Run as administrator
# Windows: Right-click → Run as administrator
# Linux/Mac: sudo python app.py
```

### Issue: "CORS error" in browser
```bash
# Always use http.server to serve frontend
python -m http.server 8000
# Don't open index.html directly from file system
```

---

## 📊 Test Dataset

If you don't have `url_dataset.csv`, create a sample:

```csv
url,type
https://www.google.com,legitimate
https://www.facebook.com,legitimate
http://bit.ly/phishing123,phishing
http://malware-site.tk/download.exe,phishing
https://www.github.com,legitimate
http://secure-paypal-login.ml,phishing
```

Save as `data/url_dataset.csv` and train models.

---

## 🎓 Usage Examples

### Example 1: Scan for Malicious IPs
```bash
# In Python console or script:
import requests

response = requests.get('http://localhost:5000/scan_connections')
data = response.json()

print(f"Total connections: {data['total_connections']}")
print(f"Malicious: {data['malicious_count']}")
```

### Example 2: Scan a File
```bash
curl -X POST http://localhost:5000/scan_file \
  -H "Content-Type: application/json" \
  -d '{"file_path": "/path/to/file.exe"}'
```

### Example 3: Get Alerts
```bash
curl http://localhost:5000/get_alerts?severity=HIGH&limit=5
```

---

## 🔐 Security Tips

1. **Don't expose to internet** - Run on localhost only
2. **Use strong passwords** - If enabling authentication
3. **Review alerts daily** - Check dashboard regularly
4. **Keep signatures updated** - Update virus database
5. **Monitor quarantine folder** - Review isolated files

---

## 📚 Next Steps

After setup:
1. ✅ Read full `README.md` for detailed documentation
2. ✅ Explore all 4 modes in dashboard
3. ✅ Test with sample malicious URLs
4. ✅ Configure `config.py` for your needs
5. ✅ Set up email alerts (optional)

---

## 🆘 Get Help

### Check Logs
```bash
# View system logs
tail -f logs/system.log

# View IP tracking logs
tail -f logs/ip_tracking.log

# View scan logs
tail -f logs/device_scans.log

# View alerts
tail -f logs/alerts.log
```

### Test Individual Modules
```bash
# Test IP tracker
python modules/ip_tracker.py

# Test device scanner
python modules/device_scanner.py

# Test alert system
python modules/alert_system.py
```

### Health Check
```bash
curl http://localhost:5000/health
```

---

## ✅ Verification Checklist

Before considering setup complete:

- [ ] Setup script ran successfully
- [ ] All dependencies installed
- [ ] Training completed without errors
- [ ] Backend starts without errors
- [ ] Frontend accessible in browser
- [ ] Can analyze sample URL
- [ ] Can scan connections
- [ ] Alerts panel shows data
- [ ] Quick stats show numbers

---

**🎉 Setup Complete! You're ready to start protecting your systems.**

**Dashboard:** http://127.0.0.1:8000/index.html  
**API Docs:** http://127.0.0.1:5000/

---

*Need more help? Check README.md for full documentation.*