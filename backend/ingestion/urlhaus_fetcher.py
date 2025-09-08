"""
URLHaus feed fetcher for threat intelligence ingestion
"""
import csv
import io
from datetime import datetime
from typing import List, Dict, Optional
import httpx
from tenacity import retry, stop_after_attempt, wait_exponential
import logging

from config import Config
from iocs.models import IOC
from database import MongoDB

logger = logging.getLogger(__name__)


class URLHausFetcher:
    """URLHaus CSV feed fetcher and processor"""
    
    def __init__(self):
        self.feed_url = Config.URLHAUS_FEED_URL
        self.source_name = 'urlhaus'
    
    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=10))
    async def fetch_feed(self) -> Optional[str]:
        """Fetch URLHaus CSV feed"""
        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.get(self.feed_url)
                response.raise_for_status()
                return response.text
        except Exception as e:
            logger.error(f"Failed to fetch URLHaus feed: {e}")
            raise
    
    def parse_csv_feed(self, csv_content: str, limit: int = None) -> List[Dict]:
        """Parse URLHaus CSV feed into IOC records"""
        iocs = []
        
        # URLHaus CSV format (skip comments starting with #)
        csv_reader = csv.DictReader(
            io.StringIO(csv_content),
            fieldnames=['id', 'dateadded', 'url', 'url_status', 'last_seen', 'threat', 'tags', 'urlhaus_link', 'reporter']
        )
        
        for row in csv_reader:
            # Skip comment lines
            if row['id'].startswith('#'):
                continue
            
            try:
                # Extract URL
                url = row['url'].strip()
                if not url:
                    continue
                
                # Parse dates
                date_added = self._parse_date(row['dateadded'])
                last_seen = self._parse_date(row['last_seen']) or date_added
                
                # Create IOC record
                ioc_data = {
                    'type': 'url',
                    'value': url,
                    'first_seen': date_added,
                    'last_seen': last_seen,
                    'source_info': {
                        'threat': row.get('threat', '').strip(),
                        'tags': row.get('tags', '').strip(),
                        'reporter': row.get('reporter', '').strip(),
                        'reference': row.get('urlhaus_link', '').strip(),
                        'status': row.get('url_status', '').strip()
                    }
                }
                
                iocs.append(ioc_data)
                
                # Check limit
                if limit and len(iocs) >= limit:
                    logger.info(f"Reached limit of {limit} IOCs, stopping parsing")
                    break
                
            except Exception as e:
                logger.warning(f"Failed to parse URLHaus row: {row}, error: {e}")
                continue
        
        logger.info(f"Parsed {len(iocs)} IOCs from URLHaus feed")
        return iocs
    
    def _parse_date(self, date_str: str) -> Optional[datetime]:
        """Parse date string from URLHaus format"""
        if not date_str or date_str.strip() == '':
            return None
        
        try:
            # URLHaus uses format: YYYY-MM-DD HH:MM:SS
            return datetime.strptime(date_str.strip(), '%Y-%m-%d %H:%M:%S')
        except ValueError:
            try:
                # Fallback format
                return datetime.strptime(date_str.strip(), '%Y-%m-%d')
            except ValueError:
                logger.warning(f"Failed to parse date: {date_str}")
                return None
    
    async def ingest_iocs(self, ioc_records: List[Dict], batch_size: int = 1000) -> Dict[str, int]:
        """Ingest IOC records into database with progress logging"""
        stats = {
            'fetched_count': len(ioc_records),
            'new_count': 0,
            'updated_count': 0,
            'error_count': 0
        }
        
        total_records = len(ioc_records)
        processed = 0
        
        for i, ioc_data in enumerate(ioc_records):
            # Log progress every batch_size records
            if i > 0 and i % batch_size == 0:
                progress = (i / total_records) * 100
                logger.info(f"Ingestion progress: {i}/{total_records} ({progress:.1f}%) - Stats: new={stats['new_count']}, updated={stats['updated_count']}, errors={stats['error_count']}")
            try:
                # Check if IOC already exists
                existing_ioc = IOC.find_by_value(ioc_data['type'], ioc_data['value'])
                
                if existing_ioc:
                    # Update existing IOC
                    existing_ioc.add_source(
                        self.source_name,
                        ioc_data['source_info'].get('reference', '')
                    )
                    existing_ioc.last_seen = ioc_data['last_seen']
                    
                    # Add threat type as tag if available
                    threat = ioc_data['source_info'].get('threat', '').strip()
                    if threat:
                        existing_ioc.add_tag(f"threat:{threat}")
                    
                    existing_ioc.save()
                    stats['updated_count'] += 1
                    
                else:
                    # Create new IOC
                    ioc = IOC(
                        ioc_type=ioc_data['type'],
                        value=ioc_data['value'],
                        first_seen=ioc_data['first_seen'],
                        last_seen=ioc_data['last_seen']
                    )
                    
                    # Add URLHaus as source
                    ioc.add_source(
                        self.source_name,
                        ioc_data['source_info'].get('reference', '')
                    )
                    
                    # Add threat type as tag
                    threat = ioc_data['source_info'].get('threat', '').strip()
                    if threat:
                        ioc.add_tag(f"threat:{threat}")
                    
                    # Add source tags
                    tags = ioc_data['source_info'].get('tags', '').strip()
                    if tags:
                        for tag in tags.split(','):
                            tag = tag.strip()
                            if tag:
                                ioc.add_tag(tag)
                    
                    ioc.save()
                    stats['new_count'] += 1
                
            except Exception as e:
                logger.error(f"Failed to ingest IOC {ioc_data.get('value', 'unknown')}: {e}")
                stats['error_count'] += 1
        
        return stats
    
    def record_ingest_run(self, stats: Dict[str, int], started_at: datetime = None, error: str = None) -> str:
        """Record ingestion run statistics"""
        try:
            logger.info(f"Starting to record ingestion run with stats: {stats}")
            
            # Test database connection
            db = MongoDB.get_database()
            logger.info(f"Database connection successful: {db.name}")
            
            ingest_runs = MongoDB.get_collection('ingest_runs')
            logger.info(f"Got ingest_runs collection: {ingest_runs.name}")
            
            now = datetime.utcnow()
            run_data = {
                'source': self.source_name,
                'status': 'error' if error else 'completed',
                'started_at': started_at or now,
                'finished_at': now,
                'fetched_count': stats.get('fetched_count', 0),
                'new_count': stats.get('new_count', 0),
                'updated_count': stats.get('updated_count', 0),
                'error_count': stats.get('error_count', 0),
                'error': error,
                'created_at': now  # Add explicit created_at for TTL and tracking
            }
            
            logger.info(f"Preparing to insert run data: {run_data}")
            
            result = ingest_runs.insert_one(run_data)
            inserted_id = str(result.inserted_id)
            
            logger.info(f"Successfully inserted ingestion run with ID: {inserted_id}")
            
            # Verify the record was actually saved
            verification = ingest_runs.find_one({'_id': result.inserted_id})
            if verification:
                logger.info(f"Verification successful: Record exists in database")
            else:
                logger.error(f"Verification failed: Record not found in database!")
            
            # Check total count of ingest_runs
            total_count = ingest_runs.count_documents({})
            logger.info(f"Total ingest_runs count after insertion: {total_count}")
            
            return inserted_id
            
        except Exception as e:
            logger.error(f"Failed to record ingestion run: {e}")
            logger.error(f"Stats were: {stats}")
            logger.error(f"Error type: {type(e).__name__}")
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}")
            raise
    
    async def fetch_and_ingest(self, limit: int = None) -> Dict[str, int]:
        """Complete URLHaus fetch and ingestion process"""
        started_at = datetime.utcnow()
        logger.info(f"Starting URLHaus feed ingestion (limit: {limit or 'none'})")
        
        try:
            # Fetch feed
            logger.info("Fetching URLHaus feed...")
            csv_content = await self.fetch_feed()
            if not csv_content:
                raise Exception("Empty feed content")
            
            # Parse IOCs
            logger.info("Parsing URLHaus CSV feed...")
            ioc_records = self.parse_csv_feed(csv_content, limit)
            if not ioc_records:
                raise Exception("No IOCs parsed from feed")
            
            # Ingest IOCs
            logger.info(f"Ingesting {len(ioc_records)} IOCs...")
            stats = await self.ingest_iocs(ioc_records)
            
            # Record successful run
            self.record_ingest_run(stats, started_at)
            
            logger.info(f"URLHaus ingestion completed successfully: {stats}")
            return stats
            
        except Exception as e:
            error_msg = f"URLHaus ingestion failed: {e}"
            logger.error(error_msg)
            
            # Record failed run
            self.record_ingest_run({}, started_at, error_msg)
            
            raise e
