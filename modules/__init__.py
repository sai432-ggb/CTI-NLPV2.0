# ========================================
# CTI-NLP Enhanced Analyzer - Modules Package
# ========================================

"""
Security monitoring modules for the CTI-NLP Analyzer.

Modules:
- ip_tracker: IP address tracking and threat detection
- device_scanner: USB/drive virus scanning
- alert_system: Alert and notification management
"""

__version__ = '2.0.0'
__author__ = 'CTI-NLP Team'

# Import main classes for easy access
from .ip_tracker import IPTracker
from .device_scanner import DeviceScanner
from .alert_system import AlertSystem

__all__ = ['IPTracker', 'DeviceScanner', 'AlertSystem']