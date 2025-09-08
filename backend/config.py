"""
Configuration settings for CTI Dashboard
"""
import os
from datetime import timedelta
from dotenv import load_dotenv

load_dotenv()


class Config:
    """Base configuration class"""
    
    # Flask settings
    SECRET_KEY = os.getenv('FLASK_SECRET_KEY', 'change_me_in_production')
    
    # MongoDB settings
    MONGO_URI = os.getenv('MONGO_URI', 'mongodb+srv://aniket00736:ak802135@cluster0.h8lwxvz.mongodb.net/cti?retryWrites=true&w=majority&appName=Cluster0')
    MONGO_DB = os.getenv('MONGO_DB', 'cti')
    
    # JWT settings
    JWT_SECRET_KEY = SECRET_KEY
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(seconds=int(os.getenv('JWT_ACCESS_TTL', 900)))  # 15 minutes
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(seconds=int(os.getenv('JWT_REFRESH_TTL', 2592000)))  # 30 days
    JWT_ALGORITHM = 'HS256'
    JWT_DECODE_LEEWAY = 10  # 10 seconds leeway for clock skew
    JWT_ERROR_MESSAGE_KEY = 'message'
    
    # External API keys
    VT_API_KEY = os.getenv('VT_API_KEY', 'a6fe6ff191183ed733f251326a6d015722737640121f03734fce3265609f9573')
    ABUSEIPDB_API_KEY = os.getenv('ABUSEIPDB_API_KEY', '26868134edb1a27b3fd8315c9de81ab80228a43fffd5f2e5011333437d21c18ea3e238e57332bbc1')
    
    # Scheduler settings
    SCHEDULER_TIMEZONE = os.getenv('SCHEDULER_TIMEZONE', 'UTC')
    
    # Export settings
    EXPORT_DIR = os.getenv('EXPORT_DIR', './exports')
    
    # Rate limiting
    RATE_LIMIT_LOOKUP_PER_MIN = int(os.getenv('RATE_LIMIT_LOOKUP_PER_MIN', 60))
    
    # URLHaus settings
    URLHAUS_FEED_URL = 'https://urlhaus.abuse.ch/downloads/csv_recent/'
    
    # VirusTotal settings (using v3 API)
    VT_RATE_LIMIT = 4  # requests per minute for free tier
    
    # AbuseIPDB settings
    ABUSEIPDB_BASE_URL = 'https://api.abuseipdb.com/api/v2'
    ABUSEIPDB_RATE_LIMIT = 1000  # requests per day for free tier
