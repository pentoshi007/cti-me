"""
Lookup service for IOC enrichment
"""
import asyncio
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple
import logging

from iocs.models import IOC
from lookup.models import Lookup
from external.virustotal import VirusTotalClient
from external.abuseipdb import AbuseIPDBClient

logger = logging.getLogger(__name__)


class LookupService:
    """Service for performing IOC lookups with enrichment"""
    
    def __init__(self):
        self.vt_client = VirusTotalClient()
        self.abuseipdb_client = AbuseIPDBClient()
    
    async def perform_lookup(self, indicator_value: str, user_id: str) -> Tuple[Optional[IOC], Optional[Lookup]]:
        """
        Perform IOC lookup with enrichment
        Returns (IOC, Lookup) tuple
        """
        # Detect IOC type
        ioc_type = IOC.detect_type(indicator_value)
        if ioc_type == 'unknown':
            return None, None
        
        # Create lookup record
        lookup = Lookup(
            indicator={'type': ioc_type, 'value': indicator_value},
            user_id=user_id,
            status='pending'
        )
        lookup.save()
        
        try:
            # Check if IOC already exists in database
            existing_ioc = IOC.find_by_value(ioc_type, indicator_value)
            
            if existing_ioc:
                # Check if enrichment data is recent (less than 24 hours old)
                needs_enrichment = self._needs_enrichment(existing_ioc)
                
                if needs_enrichment:
                    logger.info(f"Enriching existing IOC: {ioc_type}:{indicator_value}")
                    await self._enrich_ioc(existing_ioc)
                    existing_ioc.save()
                
                lookup.mark_done(str(existing_ioc._id))
                return existing_ioc, lookup
            else:
                # Create new IOC
                logger.info(f"Creating new IOC: {ioc_type}:{indicator_value}")
                ioc = IOC(ioc_type=ioc_type, value=indicator_value)
                ioc.add_source('lookup', f'Looked up by user')
                
                # Enrich with external sources
                await self._enrich_ioc(ioc)
                ioc.save()
                
                lookup.mark_done(str(ioc._id))
                return ioc, lookup
        
        except Exception as e:
            logger.error(f"Lookup failed for {ioc_type}:{indicator_value}: {e}")
            lookup.mark_error(str(e))
            return None, lookup
    
    def _needs_enrichment(self, ioc: IOC) -> bool:
        """Check if IOC needs enrichment (data older than 24 hours)"""
        now = datetime.utcnow()
        
        # Check VirusTotal data
        vt_last_fetched = ioc.vt.get('last_fetched_at')
        if vt_last_fetched:
            if isinstance(vt_last_fetched, str):
                try:
                    vt_last_fetched = datetime.fromisoformat(vt_last_fetched.replace('Z', '+00:00'))
                except (ValueError, AttributeError):
                    vt_fresh = False
                else:
                    vt_fresh = (now - vt_last_fetched) < timedelta(hours=24)
            elif isinstance(vt_last_fetched, datetime):
                vt_fresh = (now - vt_last_fetched) < timedelta(hours=24)
            else:
                vt_fresh = False
        else:
            vt_fresh = False
        
        # Check AbuseIPDB data (only for IPs)
        if ioc.type == 'ip':
            abuseipdb_last_fetched = ioc.abuseipdb.get('last_fetched_at')
            if abuseipdb_last_fetched:
                if isinstance(abuseipdb_last_fetched, str):
                    try:
                        abuseipdb_last_fetched = datetime.fromisoformat(abuseipdb_last_fetched.replace('Z', '+00:00'))
                    except (ValueError, AttributeError):
                        abuseipdb_fresh = False
                    else:
                        abuseipdb_fresh = (now - abuseipdb_last_fetched) < timedelta(hours=24)
                elif isinstance(abuseipdb_last_fetched, datetime):
                    abuseipdb_fresh = (now - abuseipdb_last_fetched) < timedelta(hours=24)
                else:
                    abuseipdb_fresh = False
            else:
                abuseipdb_fresh = False
            
            return not (vt_fresh and abuseipdb_fresh)
        else:
            return not vt_fresh
    
    async def _enrich_ioc(self, ioc: IOC):
        """Enrich IOC with external threat intelligence"""
        tasks = []
        
        # Add VirusTotal lookup task
        tasks.append(self._enrich_with_virustotal(ioc))
        
        # Add AbuseIPDB lookup task (only for IPs)
        if ioc.type == 'ip':
            tasks.append(self._enrich_with_abuseipdb(ioc))
        
        # Execute all enrichment tasks concurrently
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
    
    async def _enrich_with_virustotal(self, ioc: IOC):
        """Enrich IOC with VirusTotal data"""
        try:
            logger.info(f"Starting VirusTotal enrichment for {ioc.type}:{ioc.value}")
            vt_data = await self.vt_client.lookup_ioc(ioc.type, ioc.value)
            if vt_data:
                ioc.vt = vt_data
                logger.info(f"VirusTotal enrichment completed for {ioc.type}:{ioc.value} - Positives: {vt_data.get('positives', 0)}/{vt_data.get('total', 0)}")
            else:
                logger.warning(f"No VirusTotal data returned for {ioc.type}:{ioc.value}")
        except Exception as e:
            logger.error(f"VirusTotal enrichment failed for {ioc.type}:{ioc.value}: {e}")
    
    async def _enrich_with_abuseipdb(self, ioc: IOC):
        """Enrich IOC with AbuseIPDB data"""
        try:
            logger.info(f"Starting AbuseIPDB enrichment for {ioc.type}:{ioc.value}")
            abuseipdb_data = await self.abuseipdb_client.lookup_ioc(ioc.type, ioc.value)
            if abuseipdb_data:
                # Map the response to match the expected structure
                mapped_data = {
                    'abuse_confidence': abuseipdb_data.get('abuseConfidenceScore', 0),
                    'country_code': abuseipdb_data.get('countryCode'),
                    'usage_type': abuseipdb_data.get('usageType'),
                    'isp': abuseipdb_data.get('isp'),
                    'domain': abuseipdb_data.get('domain'),
                    'total_reports': abuseipdb_data.get('reports', 0),
                    'num_distinct_users': abuseipdb_data.get('numDistinctUsers', 0),
                    'is_whitelisted': abuseipdb_data.get('isWhitelisted', False),
                    'last_reported_at': abuseipdb_data.get('lastReportedAt'),
                    'last_fetched_at': abuseipdb_data.get('last_fetched_at')
                }
                ioc.abuseipdb = mapped_data
                logger.info(f"AbuseIPDB enrichment completed for {ioc.type}:{ioc.value} - Confidence: {mapped_data['abuse_confidence']}%")
            else:
                logger.warning(f"No AbuseIPDB data returned for {ioc.type}:{ioc.value}")
        except Exception as e:
            logger.error(f"AbuseIPDB enrichment failed for {ioc.type}:{ioc.value}: {e}")
    
    def record_enrichment_run(self, stats: Dict, started_at: datetime = None, error: str = None) -> str:
        """Record enrichment run statistics"""
        from database import MongoDB
        enrichment_runs = MongoDB.get_collection('enrichment_runs')
        
        now = datetime.utcnow()
        run_data = {
            'operation': 'bulk_enrichment',
            'status': 'error' if error else 'completed',
            'started_at': started_at or now,
            'finished_at': now,
            'processed_count': stats.get('processed_count', 0),
            'enriched_count': stats.get('enriched_count', 0),
            'error_count': stats.get('error_count', 0),
            'total_candidates': stats.get('total_candidates', 0),
            'duration_seconds': stats.get('duration_seconds', 0),
            'error': error
        }
        
        result = enrichment_runs.insert_one(run_data)
        logger.info(f"Recorded enrichment run: {run_data}")
        return str(result.inserted_id)

    async def bulk_enrich_recent_iocs(self, limit: int = 500):
        """Enrich recent IOCs that need updating"""
        started_at = datetime.utcnow()
        enriched_count = 0
        error_count = 0
        processed_count = 0
        
        logger.info(f"Starting bulk enrichment of up to {limit} recent IOCs")
        
        try:
            # Find IOCs updated in last 24h that need enrichment
            from database import MongoDB
            indicators = MongoDB.get_collection('indicators')
            
            cutoff_time = datetime.utcnow() - timedelta(hours=24)
            query = {
                'updated_at': {'$gte': cutoff_time}
            }
            
            total_candidates = indicators.count_documents(query)
            logger.info(f"Found {total_candidates} IOCs updated in last 24h")
            
            cursor = indicators.find(query).limit(limit)
            
            for doc in cursor:
                processed_count += 1
                try:
                    ioc = IOC.from_dict(doc)
                    if self._needs_enrichment(ioc):
                        logger.info(f"Bulk enriching IOC {processed_count}/{min(total_candidates, limit)}: {ioc.type}:{ioc.value}")
                        await self._enrich_ioc(ioc)
                        ioc.save()
                        enriched_count += 1
                    else:
                        logger.debug(f"IOC {ioc.type}:{ioc.value} does not need enrichment")
                except Exception as e:
                    error_count += 1
                    logger.error(f"Bulk enrichment failed for IOC {doc.get('_id')}: {e}")
            
            duration = (datetime.utcnow() - started_at).total_seconds()
            stats = {
                'processed_count': processed_count,
                'enriched_count': enriched_count,
                'error_count': error_count,
                'total_candidates': total_candidates,
                'duration_seconds': duration
            }
            
            # Record successful run
            self.record_enrichment_run(stats, started_at)
            
            logger.info(f"Bulk enrichment completed in {duration:.2f}s: processed={processed_count}, enriched={enriched_count}, errors={error_count}")
            return stats
            
        except Exception as e:
            duration = (datetime.utcnow() - started_at).total_seconds()
            error_msg = f"Bulk enrichment failed after {duration:.2f}s: {e}"
            logger.error(error_msg)
            
            # Record failed run
            stats = {
                'processed_count': processed_count,
                'enriched_count': enriched_count,
                'error_count': error_count,
                'total_candidates': 0,
                'duration_seconds': duration
            }
            self.record_enrichment_run(stats, started_at, str(e))
            
            raise
