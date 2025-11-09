from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class ScanHistory(db.Model):
    __tablename__ = 'scan_history'
    
    id = db.Column(db.Integer, primary_key=True)
    scan_type = db.Column(db.String(50), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    result = db.Column(db.JSON)
    status = db.Column(db.String(20), default='completed')
    ip_address = db.Column(db.String(50))
    domain = db.Column(db.String(255))
    
    def __init__(self, scan_type, result, ip_address=None, domain=None):
        self.scan_type = scan_type
        self.result = result
        self.ip_address = ip_address
        self.domain = domain
    
    def to_dict(self):
        return {
            'id': self.id,
            'scan_type': self.scan_type,
            'timestamp': self.timestamp.isoformat(),
            'result': self.result,
            'status': self.status,
            'ip_address': self.ip_address,
            'domain': self.domain
        }

    def __repr__(self):
        return f'<ScanHistory {self.id}: {self.scan_type}>'