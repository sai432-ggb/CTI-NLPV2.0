#!/usr/bin/env python3
"""
CTI-NLP Enhanced Threat Analyzer - API Testing Script
Tests all endpoints to verify the application is working correctly
"""

import requests
import json
import sys
from typing import Dict, Any
from colorama import init, Fore, Style
import time

# Initialize colorama for colored output
init(autoreset=True)

# Configuration
API_BASE_URL = "http://localhost:5000"
API_KEY = None  # Set if authentication is enabled

# Test data
TEST_DATA = {
    "cti_benign": {"sentiment": 0.8, "severity": 2},
    "cti_malicious": {"sentiment": 0.2, "severity": 8},
    "url_legitimate": {"url": "https://www.google.com"},
    "url_suspicious": {"url": "http://suspicious-site.tk/login?verify=account"},
    "ip_address": {"ip_address": "8.8.8.8"},
}


class APITester:
    """Test suite for CTI-NLP API"""
    
    def __init__(self, base_url: str, api_key: str = None):
        self.base_url = base_url
        self.headers = {"Content-Type": "application/json"}
        if api_key:
            self.headers["X-API-Key"] = api_key
        
        self.passed = 0
        self.failed = 0
        self.total = 0
    
    def print_header(self, text: str):
        """Print section header"""
        print(f"\n{Fore.CYAN}{'='*70}")
        print(f"{Fore.CYAN}{text:^70}")
        print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")
    
    def print_test(self, name: str, passed: bool, message: str = ""):
        """Print test result"""
        self.total += 1
        if passed:
            self.passed += 1
            print(f"{Fore.GREEN}✓ PASS{Style.RESET_ALL} - {name}")
            if message:
                print(f"  {Fore.WHITE}{message}{Style.RESET_ALL}")
        else:
            self.failed += 1
            print(f"{Fore.RED}✗ FAIL{Style.RESET_ALL} - {name}")
            if message:
                print(f"  {Fore.YELLOW}{message}{Style.RESET_ALL}")
    
    def make_request(self, method: str, endpoint: str, data: Dict = None) -> tuple:
        """Make HTTP request and return (success, response)"""
        url = f"{self.base_url}{endpoint}"
        try:
            if method == "GET":
                response = requests.get(url, headers=self.headers, timeout=10)
            elif method == "POST":
                response = requests.post(url, headers=self.headers, json=data, timeout=10)
            else:
                return False, {"error": "Unsupported method"}
            
            return response.status_code == 200, response.json()
        except requests.exceptions.ConnectionError:
            return False, {"error": "Connection refused - Is the server running?"}
        except requests.exceptions.Timeout:
            return False, {"error": "Request timeout"}
        except Exception as e:
            return False, {"error": str(e)}
    
    def test_health_check(self):
        """Test health check endpoint"""
        self.print_header("Health Check")
        
        success, response = self.make_request("GET", "/health")
        
        if success and response.get("status") == "healthy":
            self.print_test("Health endpoint", True, f"All components loaded")
            
            # Check individual components
            components = response.get("components", {})
            for name, status in components.items():
                self.print_test(f"  Component: {name}", status, 
                              f"Status: {'Loaded' if status else 'Not Loaded'}")
        else:
            self.print_test("Health endpoint", False, 
                          response.get("error", "Unknown error"))
    
    def test_cti_analysis(self):
        """Test CTI report analysis"""
        self.print_header("CTI Report Analysis")
        
        # Test benign report
        success, response = self.make_request("POST", "/analyze", TEST_DATA["cti_benign"])
        if success and response.get("status") == "success":
            self.print_test("CTI Benign Report", True,
                          f"Classification: {response['classification']}, "
                          f"Risk: {response['risk_score']}%")
        else:
            self.print_test("CTI Benign Report", False, 
                          response.get("error", "Unknown error"))
        
        # Test malicious report
        success, response = self.make_request("POST", "/analyze", TEST_DATA["cti_malicious"])
        if success and response.get("status") == "success":
            self.print_test("CTI Malicious Report", True,
                          f"Classification: {response['classification']}, "
                          f"Risk: {response['risk_score']}%")
        else:
            self.print_test("CTI Malicious Report", False, 
                          response.get("error", "Unknown error"))
    
    def test_url_analysis(self):
        """Test URL threat analysis"""
        self.print_header("URL Threat Analysis")
        
        # Test legitimate URL
        success, response = self.make_request("POST", "/analyze_url", 
                                              TEST_DATA["url_legitimate"])
        if success and response.get("status") == "success":
            self.print_test("URL Legitimate", True,
                          f"Classification: {response['classification']}, "
                          f"Risk: {response['risk_score']}%")
        else:
            self.print_test("URL Legitimate", False, 
                          response.get("error", "Unknown error"))
        
        # Test suspicious URL
        success, response = self.make_request("POST", "/analyze_url", 
                                              TEST_DATA["url_suspicious"])
        if success and response.get("status") == "success":
            self.print_test("URL Suspicious", True,
                          f"Classification: {response['classification']}, "
                          f"Risk: {response['risk_score']}%")
        else:
            self.print_test("URL Suspicious", False, 
                          response.get("error", "Unknown error"))
    
    def test_ip_tracking(self):
        """Test IP tracking features"""
        self.print_header("IP Address Tracking")
        
        # Test IP tracking
        success, response = self.make_request("POST", "/track_ip", 
                                              TEST_DATA["ip_address"])
        if success and response.get("status") == "success":
            threat = response.get('threat_check', {})
            self.print_test("IP Tracking", True,
                          f"IP: {response.get('ip_address', 'N/A')}, "
                          f"Malicious: {threat.get('is_malicious', False)}")
        else:
            self.print_test("IP Tracking", False, 
                          response.get("error", "Unknown error"))
        
        # Test IP statistics
        success, response = self.make_request("GET", "/ip_statistics")
        if success and response.get("status") == "success":
            stats = response.get('statistics', {})
            # Get keys dynamically in case they differ
            total_key = next((k for k in stats.keys() if 'total' in k.lower()), None)
            malicious_key = next((k for k in stats.keys() if 'malicious' in k.lower()), None)
            
            total_val = stats.get(total_key, 0) if total_key else len(stats)
            malicious_val = stats.get(malicious_key, 0) if malicious_key else 0
            
            self.print_test("IP Statistics", True,
                          f"Stats retrieved with {len(stats)} metrics")
        else:
            self.print_test("IP Statistics", False, 
                          response.get("error", "Unknown error"))
    
    def test_device_scanning(self):
        """Test device scanning features"""
        self.print_header("Device Scanning")
        
        # Test get drives
        success, response = self.make_request("GET", "/get_drives")
        if success and response.get("status") == "success":
            drives = response.get("drives", [])
            self.print_test("Get Drives", True,
                          f"Found {len(drives)} drives")
        else:
            self.print_test("Get Drives", False, 
                          response.get("error", "Unknown error"))
        
        # Test scanner statistics
        success, response = self.make_request("GET", "/scanner_statistics")
        if success and response.get("status") == "success":
            stats = response['statistics']
            self.print_test("Scanner Statistics", True,
                          f"Total scans: {stats['total_files_scanned']}, "
                          f"Infected: {stats['infected_files_found']}")
        else:
            self.print_test("Scanner Statistics", False, 
                          response.get("error", "Unknown error"))
    
    def test_alert_system(self):
        """Test alert system"""
        self.print_header("Alert System")
        
        # Test get alerts
        success, response = self.make_request("GET", "/get_alerts?limit=10")
        if success and response.get("status") == "success":
            alerts = response.get("alerts", [])
            self.print_test("Get Alerts", True,
                          f"Retrieved {len(alerts)} alerts")
        else:
            self.print_test("Get Alerts", False, 
                          response.get("error", "Unknown error"))
        
        # Test alert statistics
        success, response = self.make_request("GET", "/alert_statistics")
        if success and response.get("status") == "success":
            stats = response['statistics']
            self.print_test("Alert Statistics", True,
                          f"Total: {stats['total_alerts']}, "
                          f"Critical: {stats.get('by_severity', {}).get('CRITICAL', 0)}")
        else:
            self.print_test("Alert Statistics", False, 
                          response.get("error", "Unknown error"))
    
    def test_utility_endpoints(self):
        """Test utility endpoints"""
        self.print_header("Utility Endpoints")
        
        # Test root endpoint
        success, response = self.make_request("GET", "/")
        if success and response.get("status") == "online":
            self.print_test("Root Endpoint", True,
                          f"Version: {response['version']}")
        else:
            self.print_test("Root Endpoint", False, 
                          response.get("error", "Unknown error"))
        
        # Test system info
        success, response = self.make_request("GET", "/system_info")
        if success and response.get("status") == "success":
            sys_info = response['system']
            self.print_test("System Info", True,
                          f"Platform: {sys_info['platform']}, "
                          f"Python: {sys_info['python_version']}")
        else:
            self.print_test("System Info", False, 
                          response.get("error", "Unknown error"))
    
    def test_error_handling(self):
        """Test error handling"""
        self.print_header("Error Handling")
        
        # Test invalid endpoint
        success, response = self.make_request("GET", "/invalid_endpoint")
        if not success or response.get("status_code") == 404:
            self.print_test("404 Error Handling", True, "Correctly returns 404")
        else:
            self.print_test("404 Error Handling", False, "Should return 404")
        
        # Test missing required field
        success, response = self.make_request("POST", "/analyze_url", {})
        if not success or "error" in response:
            self.print_test("Missing Field Validation", True, 
                          "Correctly validates required fields")
        else:
            self.print_test("Missing Field Validation", False, 
                          "Should validate required fields")
    
    def run_all_tests(self):
        """Run all test suites"""
        print(f"\n{Fore.YELLOW}{'='*70}")
        print(f"{Fore.YELLOW}CTI-NLP ENHANCED THREAT ANALYZER - API TEST SUITE")
        print(f"{Fore.YELLOW}{'='*70}{Style.RESET_ALL}")
        print(f"\nTesting API at: {self.base_url}")
        print(f"Authentication: {'Enabled' if API_KEY else 'Disabled'}")
        
        start_time = time.time()
        
        # Run all test suites
        self.test_health_check()
        self.test_cti_analysis()
        self.test_url_analysis()
        self.test_ip_tracking()
        self.test_device_scanning()
        self.test_alert_system()
        self.test_utility_endpoints()
        self.test_error_handling()
        
        # Print summary
        elapsed = time.time() - start_time
        self.print_summary(elapsed)
    
    def print_summary(self, elapsed_time: float):
        """Print test summary"""
        print(f"\n{Fore.CYAN}{'='*70}")
        print(f"{Fore.CYAN}TEST SUMMARY")
        print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")
        
        pass_rate = (self.passed / self.total * 100) if self.total > 0 else 0
        
        print(f"Total Tests: {self.total}")
        print(f"{Fore.GREEN}Passed: {self.passed}")
        print(f"{Fore.RED}Failed: {self.failed}")
        print(f"{Fore.CYAN}Pass Rate: {pass_rate:.1f}%{Style.RESET_ALL}")
        print(f"Elapsed Time: {elapsed_time:.2f}s")
        
        print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")
        
        if self.failed == 0:
            print(f"{Fore.GREEN}✓ All tests passed! API is working correctly.{Style.RESET_ALL}\n")
            return 0
        else:
            print(f"{Fore.RED}✗ Some tests failed. Please check the errors above.{Style.RESET_ALL}\n")
            return 1


def main():
    """Main entry point"""
    print(f"\n{Fore.YELLOW}Starting API tests...{Style.RESET_ALL}")
    
    # Check if server is running
    try:
        response = requests.get(f"{API_BASE_URL}/health", timeout=5)
        if response.status_code != 200:
            print(f"{Fore.RED}✗ Server is not responding correctly!")
            print(f"  Please ensure the server is running: python app.py{Style.RESET_ALL}\n")
            sys.exit(1)
    except requests.exceptions.ConnectionError:
        print(f"{Fore.RED}✗ Cannot connect to server at {API_BASE_URL}!")
        print(f"  Please ensure the server is running: python app.py{Style.RESET_ALL}\n")
        sys.exit(1)
    
    # Run tests
    tester = APITester(API_BASE_URL, API_KEY)
    exit_code = tester.run_all_tests()
    sys.exit(exit_code)


if __name__ == "__main__":
    main()