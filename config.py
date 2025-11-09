# config.py
import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key')
    API_KEY = os.getenv('API_KEY')
    DATABASE_URI = os.getenv('DATABASE_URI', 'sqlite:///cti_nlp.db')
    MAX_FILE_SIZE_MB = int(os.getenv('MAX_FILE_SIZE_MB', 100))
    ENABLE_THREAT_FEEDS = os.getenv('ENABLE_THREAT_FEEDS', 'true').lower() == 'true'