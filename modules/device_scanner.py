# ========================================
# Device & File Scanner - Virus Detection
# ========================================

import os
import hashlib
import json
import shutil
import psutil
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional
import mimetypes

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class DeviceScanner:
    """
    Scans USB drives and files for malware using signature-based detection.
    """
    
    def __init__(self, config=None):
        self.config = config or {}
        self.virus_signatures = self._load_virus_signatures()
        self.scan_history = []
        self.quarantine_dir = Path(__file__).parent.parent / 'quarantine'
        self.quarantine_dir.mkdir(exist_ok=True)
        
        # Known malicious file hashes (MD5)
        self.malicious_hashes = set([
            'd41d8cd98f00b204e9800998ecf8427e',  # Sample hash
            '098f6bcd4621d373cade4e832627b4f6',  # Sample hash
        ])
        
        # Suspicious file patterns
        self.suspicious_patterns = [
            'autorun.inf',
            'desktop.ini',
            '*.vbs',
            '*.bat',
            '*.cmd',
            '*.ps1'
        ]
        
        logger.info("DeviceScanner initialized successfully")
    
    def _load_virus_signatures(self) -> Dict:
        """Load virus signature database"""
        signatures = {'signatures': []}
        
        try:
            sig_path = Path(__file__).parent.parent / 'data' / 'virus_signatures.json'
            
            if sig_path.exists():
                with open(sig_path, 'r') as f:
                    signatures = json.load(f)
                logger.info(f"Loaded {len(signatures['signatures'])} virus signatures")
            else:
                logger.warning(f"Virus signatures not found: {sig_path}")
                # Create sample database
                self._create_sample_signatures_db(sig_path)
        
        except Exception as e:
            logger.error(f"Error loading virus signatures: {e}")
        
        return signatures
    
    def _create_sample_signatures_db(self, sig_path: Path):
        """Create sample virus signatures database"""
        sample_signatures = {
            'signatures': [
                {
                    'name': 'Trojan.Generic',
                    'hash': 'd41d8cd98f00b204e9800998ecf8427e',
                    'type': 'trojan',
                    'severity': 'high',
                    'description': 'Generic trojan detection'
                },
                {
                    'name': 'Worm.AutoRun',
                    'pattern': 'autorun.inf',
                    'type': 'worm',
                    'severity': 'medium',
                    'description': 'AutoRun worm detection'
                },
                {
                    'name': 'Ransomware.Sample',
                    'extensions': ['.encrypted', '.locked', '.crypto'],
                    'type': 'ransomware',
                    'severity': 'critical',
                    'description': 'Ransomware file extension detection'
                },
                {
                    'name': 'Script.Malicious',
                    'extensions': ['.vbs', '.js', '.wsf'],
                    'type': 'script',
                    'severity': 'medium',
                    'description': 'Potentially malicious script'
                }
            ],
            'version': '1.0',
            'last_updated': datetime.now().strftime('%Y-%m-%d')
        }
        
        try:
            sig_path.parent.mkdir(exist_ok=True)
            with open(sig_path, 'w') as f:
                json.dump(sample_signatures, f, indent=2)
            logger.info(f"Created sample virus signatures: {sig_path}")
        except Exception as e:
            logger.error(f"Error creating signatures database: {e}")
    
    def get_connected_drives(self) -> List[Dict]:
        """Get all connected drives/USB devices"""
        drives = []
        
        try:
            partitions = psutil.disk_partitions()
            
            for partition in partitions:
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    
                    # Determine drive type
                    is_removable = 'removable' in partition.opts.lower()
                    
                    drive_info = {
                        'device': partition.device,
                        'mountpoint': partition.mountpoint,
                        'fstype': partition.fstype,
                        'is_removable': is_removable,
                        'total_space_gb': round(usage.total / (1024**3), 2),
                        'used_space_gb': round(usage.used / (1024**3), 2),
                        'free_space_gb': round(usage.free / (1024**3), 2),
                        'usage_percent': usage.percent
                    }
                    
                    drives.append(drive_info)
                
                except PermissionError:
                    continue
        
        except Exception as e:
            logger.error(f"Error getting drives: {e}")
        
        return drives
    
    def calculate_file_hash(self, file_path: str, algorithm: str = 'md5') -> str:
        """Calculate hash of a file"""
        try:
            hash_func = getattr(hashlib, algorithm)()
            
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    hash_func.update(chunk)
            
            return hash_func.hexdigest()
        
        except Exception as e:
            logger.error(f"Error calculating hash for {file_path}: {e}")
            return ""
    
    def scan_file(self, file_path: str) -> Dict:
        """
        Scan a single file for threats
        
        Returns:
            {
                'file_path': str,
                'is_malicious': bool,
                'threat_type': str,
                'severity': str,
                'detection_method': str,
                'details': str
            }
        """
        result = {
            'file_path': file_path,
            'file_name': os.path.basename(file_path),
            'is_malicious': False,
            'threat_type': 'none',
            'severity': 'low',
            'detection_method': 'none',
            'details': 'Clean',
            'file_size_bytes': 0,
            'file_hash': '',
            'timestamp': datetime.now().isoformat()
        }
        
        try:
            # Check if file exists and is accessible
            if not os.path.isfile(file_path):
                result['details'] = 'File not found or not accessible'
                return result
            
            # Get file info
            file_stat = os.stat(file_path)
            result['file_size_bytes'] = file_stat.st_size
            result['file_size_mb'] = round(file_stat.st_size / (1024**2), 2)
            
            # Skip very large files (>100MB by default)
            max_size = self.config.get('MAX_FILE_SIZE_MB', 100) * 1024 * 1024
            if file_stat.st_size > max_size:
                result['details'] = f'File too large to scan ({result["file_size_mb"]} MB)'
                return result
            
            # Calculate file hash
            file_hash = self.calculate_file_hash(file_path)
            result['file_hash'] = file_hash
            
            # Check 1: Hash-based detection
            if file_hash in self.malicious_hashes:
                result['is_malicious'] = True
                result['threat_type'] = 'known_malware'
                result['severity'] = 'critical'
                result['detection_method'] = 'hash_signature'
                result['details'] = f'Known malicious hash: {file_hash[:16]}...'
                logger.warning(f"Malicious file detected (hash): {file_path}")
                return result
            
            # Check against signature database
            for signature in self.virus_signatures.get('signatures', []):
                if 'hash' in signature and signature['hash'] == file_hash:
                    result['is_malicious'] = True
                    result['threat_type'] = signature['type']
                    result['severity'] = signature['severity']
                    result['detection_method'] = 'signature_match'
                    result['details'] = f"Detected: {signature['name']} - {signature['description']}"
                    logger.warning(f"Threat detected: {signature['name']} in {file_path}")
                    return result
            
            # Check 2: Extension-based detection
            file_extension = Path(file_path).suffix.lower()
            dangerous_extensions = ['.exe', '.dll', '.bat', '.cmd', '.vbs', '.js', '.scr', '.com', '.pif']
            
            if file_extension in dangerous_extensions:
                # Additional checks for executable files
                if self._is_suspicious_executable(file_path):
                    result['is_malicious'] = True
                    result['threat_type'] = 'suspicious_executable'
                    result['severity'] = 'medium'
                    result['detection_method'] = 'heuristic_analysis'
                    result['details'] = f'Suspicious {file_extension} file detected'
            
            # Check 3: Filename pattern detection
            file_name_lower = os.path.basename(file_path).lower()
            suspicious_names = ['autorun.inf', 'desktop.ini', 'thumbs.db']
            
            if file_name_lower in suspicious_names:
                result['is_malicious'] = True
                result['threat_type'] = 'suspicious_file'
                result['severity'] = 'medium'
                result['detection_method'] = 'filename_pattern'
                result['details'] = f'Suspicious filename: {file_name_lower}'
            
            # Check 4: Ransomware extension check
            ransomware_extensions = ['.encrypted', '.locked', '.crypto', '.crypt', '.locked', '.cerber']
            if file_extension in ransomware_extensions:
                result['is_malicious'] = True
                result['threat_type'] = 'ransomware'
                result['severity'] = 'critical'
                result['detection_method'] = 'extension_analysis'
                result['details'] = f'Ransomware extension detected: {file_extension}'
        
        except PermissionError:
            result['details'] = 'Permission denied'
        except Exception as e:
            result['details'] = f'Scan error: {str(e)}'
            logger.error(f"Error scanning file {file_path}: {e}")
        
        return result
    
    def _is_suspicious_executable(self, file_path: str) -> bool:
        """Apply heuristics to detect suspicious executables"""
        try:
            file_size = os.path.getsize(file_path)
            
            # Very small executables are suspicious
            if file_size < 1024:  # Less than 1KB
                return True
            
            # Check for hidden attribute (Windows)
            if os.name == 'nt':
                import ctypes
                attrs = ctypes.windll.kernel32.GetFileAttributesW(file_path)
                if attrs & 2:  # FILE_ATTRIBUTE_HIDDEN
                    return True
        
        except Exception as e:
            logger.error(f"Error in heuristic analysis: {e}")
        
        return False
    
    def scan_directory(self, directory_path: str, recursive: bool = True, max_files: int = 1000) -> Dict:
        """
        Scan all files in a directory
        
        Returns:
            {
                'directory': str,
                'total_files': int,
                'scanned_files': int,
                'malicious_files': int,
                'threats': List[Dict],
                'scan_duration_seconds': float
            }
        """
        start_time = datetime.now()
        
        result = {
            'directory': directory_path,
            'total_files': 0,
            'scanned_files': 0,
            'malicious_files': 0,
            'threats': [],
            'errors': [],
            'timestamp': start_time.isoformat()
        }
        
        try:
            # Get all files
            if recursive:
                all_files = []
                for root, dirs, files in os.walk(directory_path):
                    for file in files:
                        all_files.append(os.path.join(root, file))
                        if len(all_files) >= max_files:
                            break
                    if len(all_files) >= max_files:
                        break
            else:
                all_files = [
                    os.path.join(directory_path, f) 
                    for f in os.listdir(directory_path) 
                    if os.path.isfile(os.path.join(directory_path, f))
                ][:max_files]
            
            result['total_files'] = len(all_files)
            
            # Scan each file
            for file_path in all_files:
                try:
                    scan_result = self.scan_file(file_path)
                    result['scanned_files'] += 1
                    
                    if scan_result['is_malicious']:
                        result['malicious_files'] += 1
                        result['threats'].append(scan_result)
                        logger.warning(f"Threat found: {file_path}")
                
                except Exception as e:
                    result['errors'].append({
                        'file': file_path,
                        'error': str(e)
                    })
        
        except Exception as e:
            logger.error(f"Error scanning directory {directory_path}: {e}")
            result['errors'].append({
                'directory': directory_path,
                'error': str(e)
            })
        
        # Calculate duration
        end_time = datetime.now()
        result['scan_duration_seconds'] = (end_time - start_time).total_seconds()
        
        # Add to history
        self.scan_history.append(result)
        
        return result
    
    def scan_drive(self, drive_path: str) -> Dict:
        """Scan an entire drive (USB/removable media)"""
        logger.info(f"Starting drive scan: {drive_path}")
        return self.scan_directory(drive_path, recursive=True, max_files=5000)
    
    def quarantine_file(self, file_path: str) -> bool:
        """Move a malicious file to quarantine"""
        try:
            file_name = os.path.basename(file_path)
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            quarantine_name = f"{timestamp}_{file_name}"
            quarantine_path = self.quarantine_dir / quarantine_name
            
            # Move file to quarantine
            shutil.move(file_path, quarantine_path)
            
            # Create metadata file
            metadata = {
                'original_path': file_path,
                'quarantine_date': datetime.now().isoformat(),
                'file_hash': self.calculate_file_hash(str(quarantine_path)),
                'reason': 'Malicious file detected'
            }
            
            metadata_path = self.quarantine_dir / f"{quarantine_name}.json"
            with open(metadata_path, 'w') as f:
                json.dump(metadata, f, indent=2)
            
            logger.info(f"File quarantined: {file_path} -> {quarantine_path}")
            return True
        
        except Exception as e:
            logger.error(f"Error quarantining file {file_path}: {e}")
            return False
    
    def get_quarantined_files(self) -> List[Dict]:
        """Get list of all quarantined files"""
        quarantined = []
        
        try:
            for file_path in self.quarantine_dir.glob('*.json'):
                with open(file_path, 'r') as f:
                    metadata = json.load(f)
                    metadata['quarantine_file'] = str(file_path).replace('.json', '')
                    quarantined.append(metadata)
        
        except Exception as e:
            logger.error(f"Error getting quarantined files: {e}")
        
        return quarantined
    
    def delete_quarantined_file(self, quarantine_file: str) -> bool:
        """Permanently delete a quarantined file"""
        try:
            # Delete the file
            if os.path.exists(quarantine_file):
                os.remove(quarantine_file)
            
            # Delete metadata
            metadata_file = f"{quarantine_file}.json"
            if os.path.exists(metadata_file):
                os.remove(metadata_file)
            
            logger.info(f"Deleted quarantined file: {quarantine_file}")
            return True
        
        except Exception as e:
            logger.error(f"Error deleting quarantined file: {e}")
            return False
    
    def get_scan_history(self, limit: int = 10) -> List[Dict]:
        """Get recent scan history"""
        return self.scan_history[-limit:]
    
    def get_statistics(self) -> Dict:
        """Get scanner statistics"""
        total_scans = len(self.scan_history)
        total_files_scanned = sum(scan['scanned_files'] for scan in self.scan_history)
        total_threats = sum(scan['malicious_files'] for scan in self.scan_history)
        
        return {
            'total_scans': total_scans,
            'total_files_scanned': total_files_scanned,
            'total_threats_detected': total_threats,
            'quarantined_files': len(self.get_quarantined_files()),
            'virus_signatures_loaded': len(self.virus_signatures.get('signatures', []))
        }


# ========================================
# TESTING
# ========================================
if __name__ == '__main__':
    print("=" * 60)
    print("DEVICE SCANNER - Testing Module")
    print("=" * 60)
    
    scanner = DeviceScanner()
    
    # Test 1: Get connected drives
    print("\n1. Connected Drives:")
    drives = scanner.get_connected_drives()
    for drive in drives:
        drive_type = "🔌 USB" if drive['is_removable'] else "💾 Local"
        print(f"   {drive_type} {drive['device']} - {drive['mountpoint']}")
        print(f"      Space: {drive['used_space_gb']} GB / {drive['total_space_gb']} GB ({drive['usage_percent']}%)")
    
    # Test 2: Scan current directory (limited)
    print("\n2. Scanning Current Directory...")
    current_dir = os.path.dirname(os.path.abspath(__file__))
    scan_result = scanner.scan_directory(current_dir, recursive=False, max_files=10)
    print(f"   Files Scanned: {scan_result['scanned_files']}")
    print(f"   Threats Found: {scan_result['malicious_files']}")
    print(f"   Scan Duration: {scan_result['scan_duration_seconds']:.2f} seconds")
    
    # Test 3: Statistics
    print("\n3. Scanner Statistics:")
    stats = scanner.get_statistics()
    for key, value in stats.items():
        print(f"   {key}: {value}")
    
    # Test 4: Quarantine info
    print("\n4. Quarantine Status:")
    quarantined = scanner.get_quarantined_files()
    print(f"   Quarantined Files: {len(quarantined)}")
    
    print("\n" + "=" * 60)
    print("✓ Testing Complete!")
    print("=" * 60)