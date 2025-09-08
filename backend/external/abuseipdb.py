"""
AbuseIPDB API client for IP reputation checking
"""
import asyncio
import httpx
from datetime import datetime, timedelta
from typing import Dict, Optional
from tenacity import retry, stop_after_attempt, wait_exponential
import logging

from config import Config

logger = logging.getLogger(__name__)


class AbuseIPDBClient:
    """AbuseIPDB API client with rate limiting"""
    
    def __init__(self):
        self.api_key = Config.ABUSEIPDB_API_KEY
        self.base_url = Config.ABUSEIPDB_BASE_URL
        self.rate_limit = Config.ABUSEIPDB_RATE_LIMIT  # requests per day
        self.daily_request_count = 0
        self.last_reset_date = datetime.utcnow().date()
        
        if not self.api_key:
            logger.warning("AbuseIPDB API key not configured")
    
    async def _check_rate_limit(self):
        """Check and enforce daily rate limiting"""
        now = datetime.utcnow()
        today = now.date()
        
        # Reset counter if new day
        if today > self.last_reset_date:
            self.daily_request_count = 0
            self.last_reset_date = today
        
        # Check if rate limit exceeded
        if self.daily_request_count >= self.rate_limit:
            logger.warning("AbuseIPDB daily rate limit exceeded")
            raise Exception("Daily rate limit exceeded")
    
    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=10))
    async def _make_request(self, endpoint: str, params: Dict) -> Optional[Dict]:
        """Make HTTP request to AbuseIPDB API with retry logic"""
        if not self.api_key:
            logger.error("AbuseIPDB API key not configured")
            return None
        
        await self._check_rate_limit()
        
        url = f"{self.base_url}/{endpoint}"
        headers = {
            'Key': self.api_key,
            'Accept': 'application/json'
        }
        
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(url, params=params, headers=headers)
                self.daily_request_count += 1
                
                if response.status_code == 200:
                    data = response.json()
                    return data
                elif response.status_code == 422:
                    # Unprocessable Entity - usually invalid IP
                    logger.warning(f"AbuseIPDB invalid request (422): {response.text}")
                    return None
                elif response.status_code == 429:
                    # Rate limit exceeded
                    logger.warning("AbuseIPDB rate limit exceeded")
                    raise Exception("Rate limit exceeded")
                else:
                    logger.error(f"AbuseIPDB API error: {response.status_code} - {response.text}")
                    return None
        
        except httpx.RequestError as e:
            logger.error(f"AbuseIPDB API request failed: {e}")
            raise
        except Exception as e:
            logger.error(f"AbuseIPDB API request failed: {e}")
            raise
    
    async def lookup_ip(self, ip: str, max_age_days: int = 90) -> Optional[Dict]:
        """Lookup IP address in AbuseIPDB"""
        try:
            # Validate IP format
            import ipaddress
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                logger.warning(f"Invalid IP address format: {ip}")
                return None
            
            params = {
                'ipAddress': ip,
                'maxAgeInDays': max_age_days,
                'verbose': ''
            }
            
            result = await self._make_request('check', params)
            if result and 'data' in result:
                data = result['data']
                return {
                    'last_fetched_at': datetime.utcnow().isoformat(),
                    'abuseConfidenceScore': data.get('abuseConfidencePercentage', 0),
                    'reports': data.get('totalReports', 0),
                    'isPublic': data.get('isPublic', False),
                    'isWhitelisted': data.get('isWhitelisted', False),
                    'countryCode': data.get('countryCode'),
                    'countryName': data.get('countryName'),
                    'usageType': data.get('usageType'),
                    'isp': data.get('isp'),
                    'domain': data.get('domain'),
                    'lastReportedAt': data.get('lastReportedAt'),
                    'numDistinctUsers': data.get('numDistinctUsers', 0)
                }
            return {
                'last_fetched_at': datetime.utcnow().isoformat(),
                'abuseConfidenceScore': 0,
                'reports': 0,
                'isPublic': False,
                'isWhitelisted': False
            }
        except Exception as e:
            logger.error(f"AbuseIPDB lookup failed for {ip}: {e}")
            return None
    
    async def lookup_ioc(self, ioc_type: str, value: str) -> Optional[Dict]:
        """Lookup IOC if it's an IP address"""
        if ioc_type == 'ip':
            return await self.lookup_ip(value)
        else:
            # AbuseIPDB only supports IP addresses
            return None
