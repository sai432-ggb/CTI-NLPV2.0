# CTI-NLP v3.0 - Complete Backend Implementation Guide

## 🚀 QUICK START WITH LOVABLE

### Step 1: Copy This Entire Prompt to Lovable
Use the `LOVABLE_MASTER_PROMPT.md` file as your system prompt for the Lovable AI tool.

### Step 2: Command to Generate Backend
```
Generate the complete FastAPI backend for CTI-NLP v3.0 threat analyzer platform 
following the LOVABLE_MASTER_PROMPT.md specification. Include all services, models, 
routes, and deployment configurations. Make it production-ready, fully type-hinted, 
with comprehensive error handling and logging.
```

### Step 3: Command to Generate Frontend
```
Generate a modern React/TypeScript frontend dashboard for CTI-NLP v3.0 using the 
specification. Include all 4 analysis modes (URL, CTI, IP Tracking, Device Scan), 
real-time alerts panel, system statistics, and threat visualization charts.
```

---

## 📋 BACKEND FILE STRUCTURE (Ready for Implementation)

### 1. Main Application File
**File: `backend/app/main.py`**

```python
# Content to generate:
- FastAPI application initialization
- CORS configuration
- Exception handlers (HTTPException, ValidationError)
- Middleware (logging, CORS, rate limiting)
- Lifespan context manager
- Startup/shutdown events
- OpenAPI/Swagger setup
- Health check route
- Root endpoint with API info
```

### 2. Configuration File
**File: `backend/app/config.py`**

```python
# Generate:
- BaseSettings (Pydantic v2)
- Development/Staging/Production configs
- Database connection strings
- Redis configuration
- JWT settings
- API keys for threat feeds
- CORS settings
- Feature flags
- Logging configuration
- Model paths
```

### 3. Database Models
**File: `backend/app/models.py`**

```python
# Generate SQLAlchemy models:
- User (id, username, email, password_hash, role, created_at)
- AnalysisResult (id, user_id, type, input, output, risk_score, created_at)
- Alert (id, severity, title, message, status, created_at, acknowledged_at)
- ThreatFeed (id, name, last_updated, threat_count, indicators)
- ScanLog (id, target, status, threats_found, duration, created_at)
- IPTrackingLog (id, ip_address, geo_location, threat_status, created_at)
- APIKey (id, user_id, key_hash, name, last_used)
```

### 4. Pydantic Schemas
**File: `backend/app/schemas.py`**

```python
# Generate request/response schemas:
- UserCreate, UserResponse
- URLAnalysisRequest, URLAnalysisResponse
- CTIReportRequest, CTIReportResponse
- IPTrackingRequest, IPTrackingResponse
- ScanRequest, ScanResponse
- AlertResponse, AlertFilter
- ThreatFeedResponse
```

### 5. Authentication & Security
**File: `backend/app/security.py`**

```python
# Generate:
- create_access_token()
- verify_token()
- get_password_hash()
- verify_password()
- get_current_user() (dependency)
- check_api_key() (dependency)
- RateLimitChecker (dependency)
```

### 6. API Routes

**File: `backend/routes/auth.py`**
```python
# Endpoints:
- POST /api/v3/auth/register
- POST /api/v3/auth/login
- POST /api/v3/auth/refresh
- GET /api/v3/auth/me
```

**File: `backend/routes/cti_analysis.py`**
```python
# Endpoints:
- POST /api/v3/analysis/cti
- GET /api/v3/analysis/cti/{id}
- GET /api/v3/analysis/cti/history
- POST /api/v3/analysis/cti/batch
```

**File: `backend/routes/url_analysis.py`**
```python
# Endpoints:
- POST /api/v3/analysis/url
- GET /api/v3/analysis/url/{id}
- POST /api/v3/analysis/url/batch
- GET /api/v3/analysis/url/stats
```

**File: `backend/routes/ip_tracking.py`**
```python
# Endpoints:
- POST /api/v3/tracking/ip
- GET /api/v3/tracking/ip/{ip}/
- POST /api/v3/tracking/connections
- GET /api/v3/tracking/ip/stats
```

**File: `backend/routes/device_scanning.py`**
```python
# Endpoints:
- POST /api/v3/scanner/start
- GET /api/v3/scanner/status/{scan_id}
- GET /api/v3/scanner/results/{scan_id}
- POST /api/v3/scanner/quarantine
- GET /api/v3/scanner/drives
```

**File: `backend/routes/alerts.py`**
```python
# Endpoints:
- GET /api/v3/alerts
- GET /api/v3/alerts/{id}
- POST /api/v3/alerts/{id}/acknowledge
- DELETE /api/v3/alerts/{id}
- GET /api/v3/alerts/stats
```

### 7. Services

**File: `backend/services/threat_analyzer.py`**
```python
# Generate:
class ThreatAnalyzerService:
    - load_models()
    - predict_threat()
    - extract_cti_features()
    - calculate_risk_score()
    - generate_threat_report()
```

**File: `backend/services/url_classifier.py`**
```python
# Generate:
class URLClassifierService:
    - extract_url_features() [70+ features]
    - classify_url()
    - get_domain_reputation()
    - check_phishing_keywords()
    - validate_ssl_certificate()
```

**File: `backend/services/ip_geolocation.py`**
```python
# Generate:
class IPGeolocationService:
    - get_geolocation()
    - check_threat_intelligence()
    - lookup_asn()
    - get_reputation_score()
    - detect_proxy_vpn()
```

**File: `backend/services/device_scanner.py`**
```python
# Generate:
class DeviceScannerService:
    - scan_file()
    - scan_directory()
    - quarantine_file()
    - get_connected_drives()
    - get_scan_status()
```

**File: `backend/services/alert_engine.py`**
```python
# Generate:
class AlertEngineService:
    - create_alert()
    - acknowledge_alert()
    - filter_alerts()
    - send_notifications()
    - get_alert_statistics()
```

**File: `backend/services/threat_feeds.py`**
```python
# Generate:
class ThreatFeedsService:
    - fetch_threat_feed()
    - update_indicators()
    - search_indicators()
    - get_cve_data()
```

### 8. ML Models Loader

**File: `backend/ml_models/model_loader.py`**
```python
# Generate:
class ModelLoader:
    - load_url_classifier()
    - load_cti_classifier()
    - load_feature_encoders()
    - get_model_version()
    - check_model_availability()
```

**File: `backend/ml_models/feature_extractor.py`**
```python
# Generate URL feature extraction:
- is_trusted_domain
- has_suspicious_tld
- phishing_keyword_count
- domain_entropy
- url_entropy
- brand_impersonation
- excessive_subdomains
- [and 50+ more features]
```

### 9. Database Configuration

**File: `backend/database/session.py`**
```python
# Generate:
- DatabaseSession (dependency)
- get_db() context manager
- Connection pooling setup
- Transaction management
```

### 10. Testing Files

**File: `backend/tests/test_cti_analysis.py`**
```python
# Generate pytest tests:
- test_cti_analysis_valid_input()
- test_cti_analysis_invalid_input()
- test_risk_score_calculation()
- test_threat_classification()
```

**File: `backend/tests/test_url_analysis.py`**
```python
# Generate:
- test_url_feature_extraction()
- test_phishing_detection()
- test_malicious_url_detection()
- test_trusted_domain()
```

---

## 🐳 DEPLOYMENT FILES

### Docker Configuration

**File: `backend/docker/Dockerfile`**
```dockerfile
# Generate multi-stage build:
FROM python:3.11-slim as builder
# Build stage

FROM python:3.11-slim
# Runtime stage with non-root user
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3
```

**File: `backend/docker/docker-compose.yml`**
```yaml
# Generate services:
- API (FastAPI on port 8000)
- PostgreSQL (port 5432)
- Redis (port 6379)
- Elasticsearch (port 9200)
- Prometheus (port 9090)
- Grafana (port 3000)
- RabbitMQ (port 5672)
```

### Kubernetes Configuration

**File: `backend/kubernetes/deployment.yaml`**
```yaml
# Generate:
- Deployment (3 replicas)
- Health checks
- Resource limits
- Environment variables
```

**File: `backend/kubernetes/service.yaml`**
```yaml
# Generate:
- ClusterIP service
- Load balancer service
- Port configuration
```

---

## 🔧 ENVIRONMENT CONFIGURATION

**File: `backend/.env.example`**
```bash
# Database
DATABASE_URL=postgresql://user:password@localhost:5432/cti_nlp
DATABASE_POOL_SIZE=20

# Redis
REDIS_URL=redis://localhost:6379/0

# JWT
JWT_SECRET_KEY=your-secret-key-here-change-in-production
JWT_ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30

# API Keys
VIRUSTOTAL_API_KEY=
ABUSEIPDB_API_KEY=
SHODAN_API_KEY=

# Threat Feeds
MISP_URL=
MISP_API_KEY=

# Email
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=
SMTP_PASSWORD=

# Slack
SLACK_WEBHOOK_URL=

# Environment
ENVIRONMENT=development
DEBUG=False
LOG_LEVEL=INFO

# Paths
MODEL_PATH=/app/models
DATA_PATH=/app/data

# CORS
CORS_ORIGINS=http://localhost:3000,http://localhost:8000

# Rate Limiting
RATE_LIMIT_REQUESTS=100
RATE_LIMIT_PERIOD=60
```

---

## 📦 REQUIREMENTS.TXT

**File: `backend/requirements.txt`**
```
# Already provided in master prompt - copy all 60+ packages
```

---

## 🛠️ IMPLEMENTATION STEPS FOR LOVABLE

### Step 1: Generate Core Backend
```
Command: "Generate the FastAPI main application with:
- Application initialization
- CORS middleware
- Exception handlers
- Health check endpoint
- OpenAPI documentation
- Structured logging setup
Using the specifications in LOVABLE_MASTER_PROMPT.md"
```

### Step 2: Generate Database Layer
```
Command: "Generate SQLAlchemy database models, Pydantic schemas, 
and database session management for CTI-NLP v3.0 following specifications."
```

### Step 3: Generate Authentication
```
Command: "Generate JWT authentication system with:
- User model and schemas
- Password hashing with bcrypt
- Token generation and validation
- Protected route dependency
- Login/Register endpoints
- Rate limiting"
```

### Step 4: Generate Services
```
Command: "Generate all service classes:
1. ThreatAnalyzerService - ML-based threat detection
2. URLClassifierService - 70+ feature extraction
3. IPGeolocationService - IP tracking with threat intelligence
4. DeviceScannerService - Malware scanning
5. AlertEngineService - Alert management
6. ThreatFeedsService - External threat intelligence"
```

### Step 5: Generate API Routes
```
Command: "Generate all API endpoints for:
- Authentication
- CTI Analysis
- URL Analysis
- IP Tracking
- Device Scanning
- Alerts
- Threat Intelligence
Following REST best practices and error handling patterns."
```

### Step 6: Generate Deployment Files
```
Command: "Generate:
1. Dockerfile with multi-stage build
2. docker-compose.yml with all services
3. Kubernetes manifests (deployment, service, configmap)
4. Cloud deployment scripts (AWS, GCP, Azure)"
```

### Step 7: Generate Tests
```
Command: "Generate comprehensive pytest test suite with:
- Unit tests for all services
- Integration tests for API endpoints
- Database tests
- Authentication tests
- Minimum 80% code coverage"
```

---

## ⚡ OPTIMIZATION TIPS FOR LOVABLE

1. **Ask for complete, working code** - Not snippets
2. **Request type hints** - Full Python type annotations
3. **Ask for error handling** - Comprehensive exception management
4. **Request documentation** - Docstrings and comments
5. **Request tests** - Unit and integration tests
6. **Ask for production-ready** - Security, logging, monitoring

---

## 🔗 KALI LINUX INTEGRATION GUIDE

**File: `backend/routes/kali_integration.py`**
```python
# Generate:
- POST /api/v3/kali/nmap-import (Parse Nmap XML)
- POST /api/v3/kali/metasploit-sync (Sync exploit data)
- POST /api/v3/kali/burp-upload (Import Burp reports)
- GET /api/v3/kali/vulnerability-map (Vulnerability heatmap)
- POST /api/v3/kali/scan-correlate (Correlate scan results)

Features:
- Parse XML files from Kali tools
- Correlate threats with vulnerabilities
- Generate risk assessments
- Export findings
```

**Installation on Kali:**
```bash
sudo apt-get install python3-pip postgresql redis-server
git clone <repo>
cd cti-nlp-v3/backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

---

## 🦈 WIRESHARK INTEGRATION GUIDE

**File: `backend/services/pcap_analyzer.py`**
```python
# Generate:
class PCAPAnalyzerService:
    - parse_pcap_file()
    - extract_dns_queries()
    - analyze_http_traffic()
    - detect_anomalies()
    - extract_payloads()
    - correlate_threats()
    - generate_report()

API Endpoints:
- POST /api/v3/wireshark/upload-pcap
- GET /api/v3/wireshark/pcap/{id}/stats
- GET /api/v3/wireshark/pcap/{id}/threats
- POST /api/v3/wireshark/analyze-live

Features:
- Real-time packet capture
- DNS poisoning detection
- MITM attack detection
- Botnet communication detection
- Data exfiltration detection
- C2 command detection
```

**Installation:**
```bash
pip install scapy pyshark wireshark-python
# Or install Wireshark from: https://www.wireshark.org/download/
```

---

## 📊 CLOUD DEPLOYMENT SCRIPTS

**File: `scripts/deploy_aws.sh`**
```bash
#!/bin/bash
# Generate deployment script for AWS:
- Build Docker image
- Push to ECR
- Deploy to ECS/EKS
- Setup RDS PostgreSQL
- Configure ElastiCache Redis
- Setup S3 for file storage
- Configure CloudFront CDN
- Setup Route53 DNS
- Configure CloudWatch monitoring
```

**File: `scripts/deploy_gcp.sh`**
```bash
#!/bin/bash
# Generate deployment script for GCP:
- Build and push to GCR
- Deploy to GKE
- Setup Cloud SQL
- Setup Memorystore Redis
- Configure Cloud Storage
- Setup Cloud CDN
- Configure Cloud Monitoring
```

**File: `scripts/deploy_azure.sh`**
```bash
#!/bin/bash
# Generate deployment script for Azure:
- Build and push to ACR
- Deploy to AKS
- Setup Azure Database
- Setup Azure Cache
- Configure Blob Storage
- Setup Application Insights
```

---

## ✅ FINAL CHECKLIST FOR LOVABLE GENERATION

```
Backend Core:
☐ FastAPI application structure
☐ Database models and migrations
☐ Pydantic schemas for validation
☐ JWT authentication system
☐ API route handlers (all endpoints)

Services Layer:
☐ Threat analyzer service
☐ URL classifier service
☐ IP geolocation service
☐ Device scanner service
☐ Alert engine service
☐ Threat feeds service

ML Models:
☐ Model loader and initialization
☐ Feature extractor (70+ URL features)
☐ Risk score calculation
☐ Ensemble predictions

Deployment:
☐ Dockerfile (multi-stage)
☐ docker-compose.yml
☐ Kubernetes manifests
☐ Cloud deployment scripts

Integration:
☐ Kali Linux integration
☐ Wireshark PCAP analysis
☐ External threat feeds

Testing:
☐ Unit tests (80%+ coverage)
☐ Integration tests
☐ End-to-end tests
☐ Security tests

Documentation:
☐ API documentation (Swagger)
☐ Deployment guide
☐ Architecture documentation
☐ Kali integration guide
☐ Wireshark integration guide
```

---

## 🚀 DEPLOY IN 5 MINUTES

```bash
# 1. Clone and setup
git clone <repo>
cd cti-nlp-v3/backend

# 2. Copy environment
cp .env.example .env

# 3. Run with Docker Compose
docker-compose up -d

# 4. Wait for services
sleep 30

# 5. Access API
open http://localhost:8000/docs

# Done! 🎉
```

---

## 📞 TROUBLESHOOTING

```
Issue: Lovable rate limit
→ Break generation into smaller parts
  "Generate only the main.py file first..."

Issue: Incomplete code generation
→ Ask for "complete, production-ready code"
  "Generate complete, production-ready..."

Issue: Missing dependencies
→ Generate requirements.txt file
  "Generate complete requirements.txt with all 60+ packages"

Issue: No type hints
→ Explicitly request them
  "Generate with full type hints for all functions"
```

---

**READY TO BUILD WITH LOVABLE! 🚀**

Copy this entire document + LOVABLE_MASTER_PROMPT.md to Lovable AI and start generating!
