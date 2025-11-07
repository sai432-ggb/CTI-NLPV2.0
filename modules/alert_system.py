# ========================================
# Alert & Notification System
# ========================================

import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional
from collections import deque

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class AlertSystem:
    """
    Manages security alerts and notifications
    """
    
    # Alert severity levels
    SEVERITY_LOW = 1
    SEVERITY_MEDIUM = 2
    SEVERITY_HIGH = 3
    SEVERITY_CRITICAL = 4
    
    SEVERITY_NAMES = {
        1: 'LOW',
        2: 'MEDIUM',
        3: 'HIGH',
        4: 'CRITICAL'
    }
    
    # Alert types
    ALERT_MALICIOUS_IP = 'malicious_ip'
    ALERT_MALICIOUS_FILE = 'malicious_file'
    ALERT_SUSPICIOUS_ACTIVITY = 'suspicious_activity'
    ALERT_SYSTEM_RESOURCE = 'system_resource'
    ALERT_DEVICE_CONNECTED = 'device_connected'
    
    def __init__(self, config=None):
        self.config = config or {}
        self.alerts = deque(maxlen=500)  # Keep last 500 alerts
        self.alert_history_file = Path(__file__).parent.parent / 'logs' / 'alerts.log'
        self.alert_history_file.parent.mkdir(exist_ok=True)
        
        # Alert counters by severity
        self.alert_counts = {
            'LOW': 0,
            'MEDIUM': 0,
            'HIGH': 0,
            'CRITICAL': 0
        }
        
        # Load alert history
        self._load_alert_history()
        
        logger.info("AlertSystem initialized successfully")
    
    def _load_alert_history(self):
        """Load recent alerts from log file"""
        try:
            if self.alert_history_file.exists():
                with open(self.alert_history_file, 'r') as f:
                    for line in f:
                        try:
                            alert = json.loads(line.strip())
                            self.alerts.append(alert)
                            
                            # Update counters
                            severity = alert.get('severity', 'LOW')
                            if severity in self.alert_counts:
                                self.alert_counts[severity] += 1
                        except:
                            continue
                
                logger.info(f"Loaded {len(self.alerts)} alerts from history")
        
        except Exception as e:
            logger.error(f"Error loading alert history: {e}")
    
    def _save_alert(self, alert: Dict):
        """Save alert to log file"""
        try:
            with open(self.alert_history_file, 'a') as f:
                f.write(json.dumps(alert) + '\n')
        except Exception as e:
            logger.error(f"Error saving alert: {e}")
    
    def create_alert(
        self,
        alert_type: str,
        severity: int,
        title: str,
        message: str,
        details: Optional[Dict] = None
    ) -> Dict:
        """
        Create a new security alert
        
        Args:
            alert_type: Type of alert (malicious_ip, malicious_file, etc.)
            severity: Severity level (1-4)
            title: Short alert title
            message: Detailed alert message
            details: Additional context information
        
        Returns:
            Alert dictionary
        """
        alert = {
            'id': f"alert_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}",
            'type': alert_type,
            'severity': self.SEVERITY_NAMES.get(severity, 'UNKNOWN'),
            'severity_level': severity,
            'title': title,
            'message': message,
            'details': details or {},
            'timestamp': datetime.now().isoformat(),
            'acknowledged': False,
            'resolved': False
        }
        
        # Add to alerts queue
        self.alerts.append(alert)
        
        # Update counter
        if alert['severity'] in self.alert_counts:
            self.alert_counts[alert['severity']] += 1
        
        # Save to log
        self._save_alert(alert)
        
        # Log based on severity
        log_message = f"[{alert['severity']}] {alert['title']}: {alert['message']}"
        if severity == self.SEVERITY_CRITICAL:
            logger.critical(log_message)
        elif severity == self.SEVERITY_HIGH:
            logger.error(log_message)
        elif severity == self.SEVERITY_MEDIUM:
            logger.warning(log_message)
        else:
            logger.info(log_message)
        
        return alert
    
    def get_alerts(
        self,
        limit: int = 50,
        severity: Optional[str] = None,
        alert_type: Optional[str] = None,
        unacknowledged_only: bool = False
    ) -> List[Dict]:
        """
        Get alerts with optional filtering
        
        Args:
            limit: Maximum number of alerts to return
            severity: Filter by severity (LOW, MEDIUM, HIGH, CRITICAL)
            alert_type: Filter by alert type
            unacknowledged_only: Only return unacknowledged alerts
        
        Returns:
            List of alerts (most recent first)
        """
        filtered_alerts = list(self.alerts)
        
        # Apply filters
        if severity:
            filtered_alerts = [a for a in filtered_alerts if a['severity'] == severity]
        
        if alert_type:
            filtered_alerts = [a for a in filtered_alerts if a['type'] == alert_type]
        
        if unacknowledged_only:
            filtered_alerts = [a for a in filtered_alerts if not a['acknowledged']]
        
        # Sort by timestamp (most recent first) and limit
        filtered_alerts.sort(key=lambda x: x['timestamp'], reverse=True)
        return filtered_alerts[:limit]
    
    def acknowledge_alert(self, alert_id: str) -> bool:
        """Mark an alert as acknowledged"""
        for alert in self.alerts:
            if alert['id'] == alert_id:
                alert['acknowledged'] = True
                alert['acknowledged_at'] = datetime.now().isoformat()
                logger.info(f"Alert acknowledged: {alert_id}")
                return True
        return False
    
    def resolve_alert(self, alert_id: str, resolution_note: str = "") -> bool:
        """Mark an alert as resolved"""
        for alert in self.alerts:
            if alert['id'] == alert_id:
                alert['resolved'] = True
                alert['resolved_at'] = datetime.now().isoformat()
                alert['resolution_note'] = resolution_note
                logger.info(f"Alert resolved: {alert_id}")
                return True
        return False
    
    def get_alert_statistics(self) -> Dict:
        """Get statistics about alerts"""
        now = datetime.now()
        last_24h = now - timedelta(hours=24)
        last_hour = now - timedelta(hours=1)
        
        stats = {
            'total_alerts': len(self.alerts),
            'by_severity': dict(self.alert_counts),
            'last_24_hours': 0,
            'last_hour': 0,
            'unacknowledged': 0,
            'critical_unresolved': 0
        }
        
        for alert in self.alerts:
            alert_time = datetime.fromisoformat(alert['timestamp'])
            
            # Count alerts in last 24 hours
            if alert_time >= last_24h:
                stats['last_24_hours'] += 1
            
            # Count alerts in last hour
            if alert_time >= last_hour:
                stats['last_hour'] += 1
            
            # Count unacknowledged
            if not alert['acknowledged']:
                stats['unacknowledged'] += 1
            
            # Count critical unresolved
            if alert['severity'] == 'CRITICAL' and not alert['resolved']:
                stats['critical_unresolved'] += 1
        
        return stats
    
    def get_recent_alerts(self, minutes: int = 60) -> List[Dict]:
        """Get alerts from the last N minutes"""
        cutoff_time = datetime.now() - timedelta(minutes=minutes)
        
        recent = []
        for alert in self.alerts:
            alert_time = datetime.fromisoformat(alert['timestamp'])
            if alert_time >= cutoff_time:
                recent.append(alert)
        
        recent.sort(key=lambda x: x['timestamp'], reverse=True)
        return recent
    
    def clear_old_alerts(self, days: int = 30) -> int:
        """Remove alerts older than specified days"""
        cutoff_time = datetime.now() - timedelta(days=days)
        initial_count = len(self.alerts)
        
        # Filter out old alerts
        self.alerts = deque(
            [a for a in self.alerts if datetime.fromisoformat(a['timestamp']) >= cutoff_time],
            maxlen=500
        )
        
        removed_count = initial_count - len(self.alerts)
        logger.info(f"Removed {removed_count} old alerts (older than {days} days)")
        return removed_count
    
    # Convenience methods for creating specific alert types
    
    def alert_malicious_ip(self, ip_address: str, threat_type: str, details: Dict) -> Dict:
        """Create alert for malicious IP detection"""
        return self.create_alert(
            alert_type=self.ALERT_MALICIOUS_IP,
            severity=self.SEVERITY_HIGH,
            title=f"Malicious IP Detected: {ip_address}",
            message=f"Connection attempt from malicious IP address ({threat_type})",
            details={
                'ip_address': ip_address,
                'threat_type': threat_type,
                **details
            }
        )
    
    def alert_malicious_file(self, file_path: str, threat_name: str, details: Dict) -> Dict:
        """Create alert for malicious file detection"""
        return self.create_alert(
            alert_type=self.ALERT_MALICIOUS_FILE,
            severity=self.SEVERITY_CRITICAL,
            title=f"Malicious File Detected",
            message=f"Threat '{threat_name}' found in {file_path}",
            details={
                'file_path': file_path,
                'threat_name': threat_name,
                **details
            }
        )
    
    def alert_device_connected(self, device_name: str, scan_result: Dict) -> Dict:
        """Create alert for new device connection"""
        severity = self.SEVERITY_CRITICAL if scan_result.get('malicious_files', 0) > 0 else self.SEVERITY_LOW
        
        return self.create_alert(
            alert_type=self.ALERT_DEVICE_CONNECTED,
            severity=severity,
            title=f"Device Connected: {device_name}",
            message=f"New device scanned. Found {scan_result.get('malicious_files', 0)} threats.",
            details={
                'device_name': device_name,
                'scan_result': scan_result
            }
        )
    
    def alert_suspicious_activity(self, activity_type: str, description: str, details: Dict) -> Dict:
        """Create alert for suspicious activity"""
        return self.create_alert(
            alert_type=self.ALERT_SUSPICIOUS_ACTIVITY,
            severity=self.SEVERITY_MEDIUM,
            title=f"Suspicious Activity: {activity_type}",
            message=description,
            details=details
        )
    
    def alert_system_resource(self, resource_type: str, value: float, threshold: float) -> Dict:
        """Create alert for system resource issues"""
        return self.create_alert(
            alert_type=self.ALERT_SYSTEM_RESOURCE,
            severity=self.SEVERITY_MEDIUM,
            title=f"High {resource_type} Usage",
            message=f"{resource_type} usage at {value:.1f}% (threshold: {threshold}%)",
            details={
                'resource_type': resource_type,
                'current_value': value,
                'threshold': threshold
            }
        )


# ========================================
# TESTING
# ========================================
if __name__ == '__main__':
    print("=" * 60)
    print("ALERT SYSTEM - Testing Module")
    print("=" * 60)
    
    alert_system = AlertSystem()
    
    # Test 1: Create different types of alerts
    print("\n1. Creating Test Alerts...")
    
    alert_system.alert_malicious_ip(
        "192.0.2.1",
        "botnet",
        {'country': 'Unknown', 'port': 8080}
    )
    
    alert_system.alert_malicious_file(
        "/tmp/virus.exe",
        "Trojan.Generic",
        {'file_hash': 'abc123', 'file_size': 1024}
    )
    
    alert_system.create_alert(
        alert_type='test_alert',
        severity=AlertSystem.SEVERITY_LOW,
        title="Test Alert",
        message="This is a test alert for demonstration"
    )
    
    print("   ✓ Created 3 test alerts")
    
    # Test 2: Get alerts
    print("\n2. Recent Alerts:")
    alerts = alert_system.get_alerts(limit=5)
    for i, alert in enumerate(alerts, 1):
        severity_emoji = {'LOW': '✓', 'MEDIUM': '⚠', 'HIGH': '❗'}