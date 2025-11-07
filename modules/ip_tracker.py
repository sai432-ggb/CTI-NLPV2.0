# ========================================
# IP Address Tracking & Threat Detection
# ========================================

import os
import csv
import json
import socket
import requests
import psutil
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import ipaddress

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class IPTracker:
    """
    Tracks IP addresses, detects malicious IPs, and performs geolocation.
    """
    
    def __init__(self, config=None):
        self.config = config or {}
        self.malicious_ips_db = self._load_malicious_ips()
        self.trusted_ips = self._load_trusted_ips()
        self.connection_cache = {}
        self.alert_history = []
        
        logger.info("IPTracker initialized successfully")
    
    def _load_malicious_ips(self) -> set:
        """Load known malicious IPs from database"""
        malicious_ips = set()
        
        try:
            db_path = Path(__file__).parent.parent / 'data' / 'malicious_ips.csv'
            
            if db_path.exists():
                with open(db_path, 'r') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        malicious_ips.add(row['ip_address'])
                logger.info(f"Loaded {len(malicious_ips)} malicious IPs from database")
            else:
                logger.warning(f"Malicious IPs database not found: {db_path}")
                # Create sample database
                self._create_sample_malicious_ips_db(db_path)
        
        except Exception as e:
            logger.error(f"Error loading malicious IPs: {e}")
        
        return malicious_ips
    
    def _create_sample_malicious_ips_db(self, db_path: Path):
        """Create sample malicious IPs database"""
        sample_data = [
            {'ip_address': '192.0.2.1', 'threat_type': 'botnet', 'severity': 'high', 'last_seen': '2024-01-15', 'country': 'Unknown'},
            {'ip_address': '198.51.100.1', 'threat_type': 'malware', 'severity': 'critical', 'last_seen': '2024-01-14', 'country': 'Unknown'},
            {'ip_address': '203.0.113.1', 'threat_type': 'scanner', 'severity': 'medium', 'last_seen': '2024-01-13', 'country': 'Unknown'},
        ]
        
        try:
            db_path.parent.mkdir(exist_ok=True)
            with open(db_path, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=['ip_address', 'threat_type', 'severity', 'last_seen', 'country'])
                writer.writeheader()
                writer.writerows(sample_data)
            logger.info(f"Created sample malicious IPs database: {db_path}")
        except Exception as e:
            logger.error(f"Error creating sample database: {e}")
    
    def _load_trusted_ips(self) -> set:
        """Load trusted IPs from file"""
        trusted_ips = set()
        
        try:
            trusted_file = Path(__file__).parent.parent / 'data' / 'trusted_ips.txt'
            
            if trusted_file.exists():
                with open(trusted_file, 'r') as f:
                    for line in f:
                        ip = line.strip()
                        if ip and not ip.startswith('#'):
                            trusted_ips.add(ip)
                logger.info(f"Loaded {len(trusted_ips)} trusted IPs")
        
        except Exception as e:
            logger.error(f"Error loading trusted IPs: {e}")
        
        return trusted_ips
    
    def get_active_connections(self) -> List[Dict]:
        """Get all active network connections"""
        connections = []
        
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    remote_ip = conn.raddr.ip
                    remote_port = conn.raddr.port
                    
                    connections.append({
                        'local_address': f"{conn.laddr.ip}:{conn.laddr.port}",
                        'remote_address': f"{remote_ip}:{remote_port}",
                        'remote_ip': remote_ip,
                        'remote_port': remote_port,
                        'status': conn.status,
                        'pid': conn.pid
                    })
        
        except Exception as e:
            logger.error(f"Error getting connections: {e}")
        
        return connections
    
    def check_ip_malicious(self, ip_address: str) -> Dict:
        """
        Check if an IP address is malicious
        
        Returns:
            {
                'is_malicious': bool,
                'threat_type': str,
                'severity': str,
                'reason': str
            }
        """
        result = {
            'ip': ip_address,
            'is_malicious': False,
            'threat_type': 'none',
            'severity': 'low',
            'reason': 'Clean',
            'timestamp': datetime.now().isoformat()
        }
        
        try:
            # Check if in trusted list
            if ip_address in self.trusted_ips:
                result['reason'] = 'Trusted IP'
                return result
            
            # Check if localhost or private
            try:
                ip_obj = ipaddress.ip_address(ip_address)
                if ip_obj.is_private or ip_obj.is_loopback:
                    result['reason'] = 'Private/Localhost IP'
                    return result
            except:
                pass
            
            # Check against malicious database
            if ip_address in self.malicious_ips_db:
                result['is_malicious'] = True
                result['threat_type'] = 'known_malicious'
                result['severity'] = 'high'
                result['reason'] = 'Found in malicious IP database'
                logger.warning(f"Malicious IP detected: {ip_address}")
                return result
            
            # Additional heuristics
            suspicious = self._apply_heuristics(ip_address)
            if suspicious:
                result['is_malicious'] = True
                result['threat_type'] = suspicious['type']
                result['severity'] = suspicious['severity']
                result['reason'] = suspicious['reason']
        
        except Exception as e:
            logger.error(f"Error checking IP {ip_address}: {e}")
            result['reason'] = f'Error: {str(e)}'
        
        return result
    
    def _apply_heuristics(self, ip_address: str) -> Optional[Dict]:
        """Apply heuristic rules to detect suspicious IPs"""
        
        # Check connection frequency
        if ip_address in self.connection_cache:
            count = self.connection_cache[ip_address]['count']
            if count > 50:  # Too many connections
                return {
                    'type': 'suspicious_activity',
                    'severity': 'medium',
                    'reason': f'High connection frequency ({count} connections)'
                }
        
        return None
    
    def get_ip_geolocation(self, ip_address: str) -> Dict:
        """
        Get geolocation information for an IP address
        Uses ip-api.com (free, no key required, 45 req/min limit)
        """
        geo_info = {
            'ip': ip_address,
            'country': 'Unknown',
            'city': 'Unknown',
            'isp': 'Unknown',
            'latitude': 0,
            'longitude': 0
        }
        
        try:
            # Skip private IPs
            ip_obj = ipaddress.ip_address(ip_address)
            if ip_obj.is_private or ip_obj.is_loopback:
                geo_info['country'] = 'Private/Local'
                return geo_info
            
            # Use free IP-API service
            response = requests.get(
                f'http://ip-api.com/json/{ip_address}',
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    geo_info.update({
                        'country': data.get('country', 'Unknown'),
                        'city': data.get('city', 'Unknown'),
                        'isp': data.get('isp', 'Unknown'),
                        'latitude': data.get('lat', 0),
                        'longitude': data.get('lon', 0),
                        'timezone': data.get('timezone', 'Unknown')
                    })
        
        except Exception as e:
            logger.error(f"Error getting geolocation for {ip_address}: {e}")
        
        return geo_info
    
    def track_connection(self, ip_address: str):
        """Track a connection to an IP address"""
        if ip_address not in self.connection_cache:
            self.connection_cache[ip_address] = {
                'count': 0,
                'first_seen': datetime.now(),
                'last_seen': datetime.now()
            }
        
        self.connection_cache[ip_address]['count'] += 1
        self.connection_cache[ip_address]['last_seen'] = datetime.now()
    
    def scan_current_connections(self) -> Dict:
        """
        Scan all current connections for threats
        
        Returns:
            {
                'total_connections': int,
                'malicious_count': int,
                'connections': List[Dict],
                'alerts': List[Dict]
            }
        """
        connections = self.get_active_connections()
        analyzed_connections = []
        alerts = []
        malicious_count = 0
        
        for conn in connections:
            ip = conn['remote_ip']
            
            # Track connection
            self.track_connection(ip)
            
            # Check if malicious
            threat_check = self.check_ip_malicious(ip)
            
            # Get geolocation
            geo_info = self.get_ip_geolocation(ip)
            
            # Combine information
            connection_info = {
                **conn,
                'threat_check': threat_check,
                'geolocation': geo_info
            }
            
            analyzed_connections.append(connection_info)
            
            # Generate alert if malicious
            if threat_check['is_malicious']:
                malicious_count += 1
                alert = {
                    'timestamp': datetime.now().isoformat(),
                    'type': 'malicious_connection',
                    'severity': threat_check['severity'],
                    'ip': ip,
                    'threat_type': threat_check['threat_type'],
                    'reason': threat_check['reason'],
                    'location': f"{geo_info['city']}, {geo_info['country']}"
                }
                alerts.append(alert)
                self.alert_history.append(alert)
                logger.warning(f"ALERT: {alert}")
        
        return {
            'total_connections': len(connections),
            'malicious_count': malicious_count,
            'connections': analyzed_connections,
            'alerts': alerts,
            'timestamp': datetime.now().isoformat()
        }
    
    def get_my_public_ip(self) -> str:
        """Get the public IP address of this machine"""
        try:
            response = requests.get('https://api.ipify.org?format=json', timeout=5)
            if response.status_code == 200:
                return response.json()['ip']
        except:
            pass
        
        return 'Unknown'
    
    def get_alert_history(self, limit: int = 50) -> List[Dict]:
        """Get recent alerts"""
        return self.alert_history[-limit:]
    
    def add_trusted_ip(self, ip_address: str) -> bool:
        """Add an IP to the trusted list"""
        try:
            self.trusted_ips.add(ip_address)
            
            trusted_file = Path(__file__).parent.parent / 'data' / 'trusted_ips.txt'
            with open(trusted_file, 'a') as f:
                f.write(f"{ip_address}\n")
            
            logger.info(f"Added trusted IP: {ip_address}")
            return True
        
        except Exception as e:
            logger.error(f"Error adding trusted IP: {e}")
            return False
    
    def add_malicious_ip(self, ip_address: str, threat_type: str = 'manual', severity: str = 'high') -> bool:
        """Add an IP to the malicious database"""
        try:
            self.malicious_ips_db.add(ip_address)
            
            db_path = Path(__file__).parent.parent / 'data' / 'malicious_ips.csv'
            with open(db_path, 'a', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([ip_address, threat_type, severity, datetime.now().strftime('%Y-%m-%d'), 'Manual'])
            
            logger.info(f"Added malicious IP: {ip_address}")
            return True
        
        except Exception as e:
            logger.error(f"Error adding malicious IP: {e}")
            return False
    
    def get_statistics(self) -> Dict:
        """Get tracking statistics"""
        return {
            'total_tracked_ips': len(self.connection_cache),
            'malicious_ips_count': len(self.malicious_ips_db),
            'trusted_ips_count': len(self.trusted_ips),
            'total_alerts': len(self.alert_history),
            'most_frequent_ips': self._get_most_frequent_ips(5)
        }
    
    def _get_most_frequent_ips(self, limit: int) -> List[Dict]:
        """Get most frequently connected IPs"""
        sorted_ips = sorted(
            self.connection_cache.items(),
            key=lambda x: x[1]['count'],
            reverse=True
        )[:limit]
        
        return [
            {
                'ip': ip,
                'count': data['count'],
                'first_seen': data['first_seen'].isoformat(),
                'last_seen': data['last_seen'].isoformat()
            }
            for ip, data in sorted_ips
        ]


# ========================================
# TESTING
# ========================================
if __name__ == '__main__':
    print("=" * 60)
    print("IP TRACKER - Testing Module")
    print("=" * 60)
    
    tracker = IPTracker()
    
    # Test 1: Get public IP
    print("\n1. Your Public IP:")
    public_ip = tracker.get_my_public_ip()
    print(f"   {public_ip}")
    
    # Test 2: Scan current connections
    print("\n2. Scanning Current Connections...")
    scan_result = tracker.scan_current_connections()
    print(f"   Total Connections: {scan_result['total_connections']}")
    print(f"   Malicious Found: {scan_result['malicious_count']}")
    
    if scan_result['connections']:
        print("\n   Sample Connection:")
        conn = scan_result['connections'][0]
        print(f"   - Remote IP: {conn['remote_ip']}")
        print(f"   - Location: {conn['geolocation']['city']}, {conn['geolocation']['country']}")
        print(f"   - Malicious: {conn['threat_check']['is_malicious']}")
    
    # Test 3: Check specific IP
    print("\n3. Testing Specific IPs:")
    test_ips = ['8.8.8.8', '192.0.2.1', '127.0.0.1']
    for ip in test_ips:
        result = tracker.check_ip_malicious(ip)
        print(f"   {ip}: {'🚨 MALICIOUS' if result['is_malicious'] else '✓ Clean'} - {result['reason']}")
    
    # Test 4: Statistics
    print("\n4. Statistics:")
    stats = tracker.get_statistics()
    for key, value in stats.items():
        if key != 'most_frequent_ips':
            print(f"   {key}: {value}")
    
    print("\n" + "=" * 60)
    print("✓ Testing Complete!")
    print("=" * 60)