"""
VirusTotal API client for IOC enrichment - Using v3 API
"""
import asyncio
import httpx
import base64
from datetime import datetime, timedelta
from typing import Dict, Optional
from tenacity import retry, stop_after_attempt, wait_exponential
import logging

from config import Config

logger = logging.getLogger(__name__)


class VirusTotalClient:
    """VirusTotal API v3 client with rate limiting and caching"""
    
    def __init__(self):
        self.api_key = Config.VT_API_KEY
        self.base_url = 'https://www.virustotal.com/api/v3'  # Use v3 API
        self.rate_limit = Config.VT_RATE_LIMIT  # requests per minute
        self.last_request_time = datetime.utcnow()
        self.request_count = 0
        
        if not self.api_key:
            logger.warning("VirusTotal API key not configured")
    
    async def _check_rate_limit(self):
        """Check and enforce rate limiting with improved logic"""
        now = datetime.utcnow()
        
        # Reset counter if minute has passed
        if now - self.last_request_time > timedelta(minutes=1):
            self.request_count = 0
            self.last_request_time = now
        
        # Wait if rate limit exceeded, but cap the wait time
        if self.request_count >= self.rate_limit:
            sleep_time = 60 - (now - self.last_request_time).total_seconds()
            if sleep_time > 0:
                # Cap sleep time to maximum 60 seconds to prevent excessive delays
                capped_sleep_time = min(sleep_time, 60)
                logger.info(f"Rate limit reached, sleeping for {capped_sleep_time:.2f} seconds")
                await asyncio.sleep(capped_sleep_time)
                self.request_count = 0
                self.last_request_time = datetime.utcnow()
        
        # Add small delay between requests to prevent bursting
        if self.request_count > 0:
            await asyncio.sleep(15)  # 15 seconds between requests for free tier
    
    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=10))
    async def _make_request(self, endpoint: str, headers: Dict = None) -> Optional[Dict]:
        """Make HTTP request to VirusTotal API v3 with retry logic"""
        if not self.api_key:
            logger.error("VirusTotal API key not configured")
            return None
        
        await self._check_rate_limit()
        
        url = f"{self.base_url}/{endpoint}"
        request_headers = {
            'X-Apikey': self.api_key,
            'Accept': 'application/json'
        }
        if headers:
            request_headers.update(headers)
        
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(url, headers=request_headers)
                self.request_count += 1
                
                if response.status_code == 200:
                    data = response.json()
                    return data
                elif response.status_code == 404:
                    # Not found in VirusTotal database - return a proper structure
                    logger.info(f"Resource not found in VirusTotal: {endpoint}")
                    return {
                        'data': {
                            'attributes': {
                                'last_analysis_stats': {
                                    'malicious': 0, 
                                    'suspicious': 0, 
                                    'harmless': 0, 
                                    'undetected': 0
                                },
                                'reputation': 0,
                                'categories': {}
                            }
                        }
                    }
                elif response.status_code == 429:
                    # Rate limit exceeded
                    logger.warning("VirusTotal rate limit exceeded")
                    raise Exception("Rate limit exceeded")
                else:
                    logger.error(f"VirusTotal API error: {response.status_code} - {response.text}")
                    return None
        
        except httpx.RequestError as e:
            logger.error(f"VirusTotal API request failed: {e}")
            raise
        except Exception as e:
            logger.error(f"VirusTotal API request failed: {e}")
            raise
    
    async def lookup_ip(self, ip: str) -> Optional[Dict]:
        """Lookup IP address in VirusTotal v3 API"""
        try:
            result = await self._make_request(f'ip_addresses/{ip}')
            if result and 'data' in result:
                attributes = result['data'].get('attributes', {})
                last_analysis_stats = attributes.get('last_analysis_stats', {})
                
                malicious = last_analysis_stats.get('malicious', 0)
                suspicious = last_analysis_stats.get('suspicious', 0)
                harmless = last_analysis_stats.get('harmless', 0)
                undetected = last_analysis_stats.get('undetected', 0)
                total = malicious + suspicious + harmless + undetected
                
                return {
                    'last_fetched_at': datetime.utcnow().isoformat(),
                    'positives': malicious + suspicious,
                    'total': total,
                    'categories': list(attributes.get('categories', {}).keys()),
                    'country': attributes.get('country'),
                    'asn': attributes.get('asn'),
                    'as_owner': attributes.get('as_owner'),
                    'permalink': f"https://www.virustotal.com/gui/ip-address/{ip}",
                    'last_analysis_stats': last_analysis_stats
                }
            return {
                'last_fetched_at': datetime.utcnow().isoformat(),
                'positives': 0,
                'total': 0,
                'categories': [],
                'country': None,
                'asn': None,
                'as_owner': None,
                'permalink': f"https://www.virustotal.com/gui/ip-address/{ip}",
                'last_analysis_stats': {'malicious': 0, 'suspicious': 0, 'harmless': 0, 'undetected': 0}
            }
        except Exception as e:
            logger.error(f"VirusTotal IP lookup failed for {ip}: {e}")
            return None
    
    async def lookup_domain(self, domain: str) -> Optional[Dict]:
        """Lookup domain in VirusTotal v3 API"""
        try:
            result = await self._make_request(f'domains/{domain}')
            if result and 'data' in result:
                attributes = result['data'].get('attributes', {})
                last_analysis_stats = attributes.get('last_analysis_stats', {})
                
                malicious = last_analysis_stats.get('malicious', 0)
                suspicious = last_analysis_stats.get('suspicious', 0)
                harmless = last_analysis_stats.get('harmless', 0)
                undetected = last_analysis_stats.get('undetected', 0)
                total = malicious + suspicious + harmless + undetected
                
                return {
                    'last_fetched_at': datetime.utcnow().isoformat(),
                    'positives': malicious + suspicious,
                    'total': total,
                    'categories': list(attributes.get('categories', {}).keys()),
                    'reputation': attributes.get('reputation', 0),
                    'whois': attributes.get('whois'),
                    'permalink': f"https://www.virustotal.com/gui/domain/{domain}",
                    'last_analysis_stats': last_analysis_stats
                }
            return {
                'last_fetched_at': datetime.utcnow().isoformat(),
                'positives': 0,
                'total': 0,
                'categories': [],
                'permalink': f"https://www.virustotal.com/gui/domain/{domain}"
            }
        except Exception as e:
            logger.error(f"VirusTotal domain lookup failed for {domain}: {e}")
            return None
    
    async def lookup_url(self, url: str) -> Optional[Dict]:
        """Lookup URL in VirusTotal v3 API"""
        try:
            # Create URL identifier for v3 API
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip('=')
            
            result = await self._make_request(f'urls/{url_id}')
            if result and 'data' in result:
                attributes = result['data'].get('attributes', {})
                last_analysis_stats = attributes.get('last_analysis_stats', {})
                
                malicious = last_analysis_stats.get('malicious', 0)
                suspicious = last_analysis_stats.get('suspicious', 0)
                harmless = last_analysis_stats.get('harmless', 0)
                undetected = last_analysis_stats.get('undetected', 0)
                total = malicious + suspicious + harmless + undetected
                
                return {
                    'last_fetched_at': datetime.utcnow().isoformat(),
                    'positives': malicious + suspicious,
                    'total': total,
                    'categories': list(attributes.get('categories', {}).keys()),
                    'reputation': attributes.get('reputation', 0),
                    'title': attributes.get('title'),
                    'final_url': attributes.get('final_url'),
                    'permalink': f"https://www.virustotal.com/gui/url/{url_id}",
                    'last_analysis_stats': last_analysis_stats
                }
            return {
                'last_fetched_at': datetime.utcnow().isoformat(),
                'positives': 0,
                'total': 0,
                'categories': [],
                'permalink': f"https://www.virustotal.com/gui/url/{url_id}"
            }
        except Exception as e:
            logger.error(f"VirusTotal URL lookup failed for {url}: {e}")
            return None
    
    async def lookup_file_hash(self, file_hash: str) -> Optional[Dict]:
        """Lookup file hash in VirusTotal v3 API"""
        try:
            result = await self._make_request(f'files/{file_hash}')
            if result and 'data' in result:
                attributes = result['data'].get('attributes', {})
                last_analysis_stats = attributes.get('last_analysis_stats', {})
                
                malicious = last_analysis_stats.get('malicious', 0)
                suspicious = last_analysis_stats.get('suspicious', 0)
                harmless = last_analysis_stats.get('harmless', 0)
                undetected = last_analysis_stats.get('undetected', 0)
                total = malicious + suspicious + harmless + undetected
                
                return {
                    'last_fetched_at': datetime.utcnow().isoformat(),
                    'positives': malicious + suspicious,
                    'total': total,
                    'sha256': attributes.get('sha256'),
                    'sha1': attributes.get('sha1'),
                    'md5': attributes.get('md5'),
                    'size': attributes.get('size'),
                    'type_description': attributes.get('type_description'),
                    'magic': attributes.get('magic'),
                    'reputation': attributes.get('reputation', 0),
                    'permalink': f"https://www.virustotal.com/gui/file/{file_hash}",
                    'last_analysis_stats': last_analysis_stats
                }
            return {
                'last_fetched_at': datetime.utcnow().isoformat(),
                'positives': 0,
                'total': 0,
                'permalink': f"https://www.virustotal.com/gui/file/{file_hash}"
            }
        except Exception as e:
            logger.error(f"VirusTotal hash lookup failed for {file_hash}: {e}")
            return None
    
    async def lookup_ioc(self, ioc_type: str, value: str) -> Optional[Dict]:
        """Lookup IOC based on type"""
        if ioc_type == 'ip':
            return await self.lookup_ip(value)
        elif ioc_type == 'domain':
            return await self.lookup_domain(value)
        elif ioc_type == 'url':
            return await self.lookup_url(value)
        elif ioc_type in ['md5', 'sha1', 'sha256']:
            return await self.lookup_file_hash(value)
        else:
            logger.warning(f"Unsupported IOC type for VirusTotal: {ioc_type}")
            return None
