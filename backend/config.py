"""
Configuration settings for CTI Dashboard
"""
import os
from datetime import timedelta
from dotenv import load_dotenv
from pathlib import Path

# Load environment variables explicitly from backend/.env first, then fall back to process env
_backend_env_path = Path(__file__).with_name('.env')
load_dotenv(dotenv_path=_backend_env_path)
load_dotenv(override=False)


class Config:
    """Base configuration class"""
    
    # Flask settings
    SECRET_KEY = os.getenv('FLASK_SECRET_KEY', 'change_me_in_production')
    
    # MongoDB settings
    MONGO_URI = os.getenv('MONGO_URI')
    MONGO_DB = os.getenv('MONGO_DB', 'cti')
    
    # JWT settings
    JWT_SECRET_KEY = SECRET_KEY
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(seconds=int(os.getenv('JWT_ACCESS_TTL', 3600)))  # 1 hour (increased from 15 minutes)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(seconds=int(os.getenv('JWT_REFRESH_TTL', 2592000)))  # 30 days
    JWT_ALGORITHM = 'HS256'
    JWT_DECODE_LEEWAY = 10  # 10 seconds leeway for clock skew
    JWT_ERROR_MESSAGE_KEY = 'message'
    JWT_ACCESS_COOKIE_NAME = 'access_token_cookie'
    JWT_REFRESH_COOKIE_NAME = 'refresh_token_cookie'
    
    # External API keys
    VT_API_KEY = os.getenv('VT_API_KEY')
    ABUSEIPDB_API_KEY = os.getenv('ABUSEIPDB_API_KEY')
    
    # Scheduler settings
    SCHEDULER_TIMEZONE = os.getenv('SCHEDULER_TIMEZONE', 'UTC')
    
    # Export settings
    EXPORT_DIR = os.getenv('EXPORT_DIR', './exports')
    
    # Rate limiting
    RATE_LIMIT_LOOKUP_PER_MIN = int(os.getenv('RATE_LIMIT_LOOKUP_PER_MIN', 60))
    
    # URLHaus settings
    URLHAUS_FEED_URL = 'https://urlhaus.abuse.ch/downloads/csv_recent/'
    
    # CORS settings
    CORS_ORIGINS = os.getenv('CORS_ORIGINS', 'http://localhost:3000,http://localhost:3001,http://localhost:3002,http://127.0.0.1:3000,http://127.0.0.1:3001,http://127.0.0.1:3002').split(',')
    
    # Remove empty strings from CORS origins
    CORS_ORIGINS = [origin.strip() for origin in CORS_ORIGINS if origin.strip()]
    
    # VirusTotal settings (using v3 API)
    VT_RATE_LIMIT = 4  # requests per minute for free tier
    
    # AbuseIPDB settings
    ABUSEIPDB_BASE_URL = 'https://api.abuseipdb.com/api/v2'
    ABUSEIPDB_RATE_LIMIT = 1000  # requests per day for free tier
