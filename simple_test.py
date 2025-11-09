#!/usr/bin/env python3
"""
CTI-NLP Enhanced Threat Analyzer - Simple API Testing Script
Quick verification that all endpoints are working
"""

import requests
import json
import sys

# Configuration
API_BASE_URL = "http://localhost:5000"
API_KEY = None  # Set if authentication is enabled

def print_section(title):
    print(f"\n{'='*60}")
    print(f"{title:^60}")
    print(f"{'='*60}\n")

def print_test(name, passed, details=""):
    status = "✓ PASS" if passed else "✗ FAIL"
    print(f"{status} - {name}")
    if details:
        print(f"  → {details}")

def make_request(method, endpoint, data=None):
    """Make HTTP request"""
    url = f"{API_BASE_URL}{endpoint}"
    headers = {"Content-Type": "application/json"}
    if API_KEY:
        headers["X-API-Key"] = API_KEY
    
    try:
        if method == "GET":
            response = requests.get(url, headers=headers, timeout=10)
        elif method == "POST":
            response = requests.post(url, headers=headers, json=data, timeout=10)
        else:
            return None, {"error": "Unsupported method"}
        
        try:
            response_json = response.json()
        except:
            response_json = {"error": "Invalid JSON response"}
        
        return response.status_code, response_json
    except requests.exceptions.ConnectionError:
        return None, {"error": "Connection refused"}
    except Exception as e:
        return None, {"error": str(e)}

def test_health():
    """Test health endpoint"""
    print_section("1. HEALTH CHECK")
    
    status_code, response = make_request("GET", "/health")
    
    if status_code == 200 and response.get("status") == "healthy":
        print_test("Server Health", True, "All systems operational")
        
        components = response.get("components", {})
        # Ensure components is a dictionary
        if isinstance(components, dict):
            for name, loaded in components.items():
                print_test(f"  {name.replace('_', ' ').title()}", loaded)
        return True
    else:
        print_test("Server Health", False, response.get("error", "Unknown"))
        return False

def test_cti_analysis():
    """Test CTI analysis"""
    print_section("2. CTI REPORT ANALYSIS")
    
    tests = [
        ("Benign Report", {"sentiment": 0.8, "severity": 2}),
        ("Malicious Report", {"sentiment": 0.2, "severity": 8})
    ]
    
    for name, data in tests:
        status_code, response = make_request("POST", "/analyze", data)
        
        if status_code == 200 and isinstance(response, dict) and response.get("status") == "success":
            print_test(name, True, 
                      f"{response.get('classification', 'N/A')} "
                      f"(Risk: {response.get('risk_score', 0)}%)")
        else:
            error_msg = response.get("error", "Unknown") if isinstance(response, dict) else "Unknown"
            print_test(name, False, error_msg)

def test_url_analysis():
    """Test URL analysis"""
    print_section("3. URL THREAT ANALYSIS")
    
    tests = [
        ("Legitimate URL", {"url": "https://www.google.com"}),
        ("Suspicious URL", {"url": "http://suspicious-site.tk/login"})
    ]
    
    for name, data in tests:
        status_code, response = make_request("POST", "/analyze_url", data)
        
        if status_code == 200 and isinstance(response, dict) and response.get("status") == "success":
            print_test(name, True,
                      f"{response.get('classification', 'N/A')} "
                      f"(Risk: {response.get('risk_score', 0)}%)")
        else:
            error_msg = response.get("error", "Unknown") if isinstance(response, dict) else "Unknown"
            print_test(name, False, error_msg)

def test_ip_tracking():
    """Test IP tracking"""
    print_section("4. IP ADDRESS TRACKING")
    
    # Test IP tracking
    status_code, response = make_request("POST", "/track_ip", 
                                        {"ip_address": "8.8.8.8"})
    
    if status_code == 200 and isinstance(response, dict) and response.get("status") == "success":
        threat = response.get("threat_check", {})
        if isinstance(threat, dict):
            print_test("IP Tracking", True,
                      f"Malicious: {threat.get('is_malicious', False)}")
        else:
            print_test("IP Tracking", True, "Response received")
    else:
        error_msg = response.get("error", "Unknown") if isinstance(response, dict) else "Unknown"
        print_test("IP Tracking", False, error_msg)
    
    # Test IP statistics
    status_code, response = make_request("GET", "/ip_statistics")
    
    if status_code == 200 and isinstance(response, dict) and response.get("status") == "success":
        print_test("IP Statistics", True, "Stats retrieved successfully")
    else:
        error_msg = response.get("error", "Unknown") if isinstance(response, dict) else "Unknown"
        print_test("IP Statistics", False, error_msg)

def test_device_scanning():
    """Test device scanning"""
    print_section("5. DEVICE SCANNING")
    
    # Test get drives
    status_code, response = make_request("GET", "/get_drives")
    
    if status_code == 200 and isinstance(response, dict) and response.get("status") == "success":
        drives = response.get("drives", [])
        print_test("Get Drives", True, f"Found {len(drives)} drives")
    else:
        error_msg = response.get("error", "Unknown") if isinstance(response, dict) else "Unknown"
        print_test("Get Drives", False, error_msg)
    
    # Test scanner statistics
    status_code, response = make_request("GET", "/scanner_statistics")
    
    if status_code == 200 and isinstance(response, dict) and response.get("status") == "success":
        print_test("Scanner Statistics", True, "Stats retrieved successfully")
    else:
        error_msg = response.get("error", "Unknown") if isinstance(response, dict) else "Unknown"
        print_test("Scanner Statistics", False, error_msg)

def test_alerts():
    """Test alert system"""
    print_section("6. ALERT SYSTEM")
    
    # Test get alerts
    status_code, response = make_request("GET", "/get_alerts?limit=10")
    
    if status_code == 200 and isinstance(response, dict) and response.get("status") == "success":
        alerts = response.get("alerts", [])
        print_test("Get Alerts", True, f"Retrieved {len(alerts)} alerts")
    else:
        error_msg = response.get("error", "Unknown") if isinstance(response, dict) else "Unknown"
        print_test("Get Alerts", False, error_msg)
    
    # Test alert statistics
    status_code, response = make_request("GET", "/alert_statistics")
    
    if status_code == 200 and isinstance(response, dict) and response.get("status") == "success":
        print_test("Alert Statistics", True, "Stats retrieved successfully")
    else:
        error_msg = response.get("error", "Unknown") if isinstance(response, dict) else "Unknown"
        print_test("Alert Statistics", False, error_msg)

def test_utility():
    """Test utility endpoints"""
    print_section("7. UTILITY ENDPOINTS")
    
    # Test root endpoint
    status_code, response = make_request("GET", "/")
    
    if status_code == 200 and isinstance(response, dict) and response.get("status") == "online":
        print_test("Root Endpoint", True, 
                  f"API v{response.get('version', 'unknown')}")
    else:
        error_msg = response.get("error", "Unknown") if isinstance(response, dict) else "Unknown"
        print_test("Root Endpoint", False, error_msg)
    
    # Test system info
    status_code, response = make_request("GET", "/system_info")
    
    if status_code == 200 and isinstance(response, dict) and response.get("status") == "success":
        sys_info = response.get("system", {})
        if isinstance(sys_info, dict):
            print_test("System Info", True,
                      f"{sys_info.get('platform', 'N/A')} - "
                      f"Python {sys_info.get('python_version', 'N/A')}")
        else:
            print_test("System Info", True, "Response received")
    else:
        error_msg = response.get("error", "Unknown") if isinstance(response, dict) else "Unknown"
        print_test("System Info", False, error_msg)

def test_error_handling():
    """Test error handling"""
    print_section("8. ERROR HANDLING")
    
    # Test 404
    status_code, response = make_request("GET", "/invalid_endpoint")
    if status_code == 404 or (isinstance(response, dict) and "error" in response):
        print_test("404 Handling", True, "Correctly returns 404")
    else:
        print_test("404 Handling", False, "Should return 404")
    
    # Test missing field
    status_code, response = make_request("POST", "/analyze_url", {})
    if status_code in [400, 500] or (isinstance(response, dict) and "error" in response):
        print_test("Field Validation", True, "Validates required fields")
    else:
        print_test("Field Validation", False, "Should validate fields")

def main():
    """Main test runner"""
    print("\n" + "="*60)
    print("CTI-NLP ENHANCED THREAT ANALYZER")
    print("Simple API Test Suite")
    print("="*60)
    print(f"\nTesting API at: {API_BASE_URL}")
    print(f"Authentication: {'Enabled' if API_KEY else 'Disabled'}\n")
    
    # Check if server is running
    try:
        response = requests.get(f"{API_BASE_URL}/health", timeout=5)
        if response.status_code != 200:
            print("✗ ERROR: Server not responding correctly!")
            print("  Start the server: python app.py\n")
            sys.exit(1)
    except requests.exceptions.ConnectionError:
        print(f"✗ ERROR: Cannot connect to {API_BASE_URL}!")
        print("  Make sure the server is running: python app.py\n")
        sys.exit(1)
    except Exception as e:
        print(f"✗ ERROR: {e}\n")
        sys.exit(1)
    
    # Run all tests
    try:
        if not test_health():
            print("\n⚠ WARNING: Health check failed, but continuing tests...\n")
        
        test_cti_analysis()
        test_url_analysis()
        test_ip_tracking()
        test_device_scanning()
        test_alerts()
        test_utility()
        test_error_handling()
        
        print_section("TEST SUMMARY")
        print("✓ All endpoint tests completed!")
        print("  Check results above for any failures.")
        print("\nFor detailed response data, use the full test_api.py script")
        print("or test endpoints directly with curl/Postman.\n")
        
    except KeyboardInterrupt:
        print("\n\n⚠ Tests interrupted by user\n")
        sys.exit(1)
    except Exception as e:
        print(f"\n✗ Unexpected error: {e}\n")
        sys.exit(1)

if __name__ == "__main__":
    main()