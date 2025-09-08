"""
Metrics API routes - Full Flask blueprint implementation
"""
import logging
from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required
from datetime import datetime, timedelta
from typing import Dict, List, Any

from database import MongoDB

logger = logging.getLogger(__name__)

metrics_bp = Blueprint('metrics', __name__)


@metrics_bp.route('/overview', methods=['GET'])
@jwt_required()
def get_overview():
    """Get overview metrics for dashboard"""
    try:
        from database import MongoDB
        indicators = MongoDB.get_collection('indicators')
        lookups = MongoDB.get_collection('lookups')
        tags_collection = MongoDB.get_collection('tags')

        # Current date ranges
        now = datetime.utcnow()
        last_24h = now - timedelta(hours=24)
        last_7d = now - timedelta(days=7)
        last_30d = now - timedelta(days=30)

        # IOC metrics
        total_iocs = indicators.count_documents({})
        recent_iocs_24h = indicators.count_documents({'created_at': {'$gte': last_24h}})
        recent_iocs_7d = indicators.count_documents({'created_at': {'$gte': last_7d}})
        recent_iocs_30d = indicators.count_documents({'created_at': {'$gte': last_30d}})

        # IOC by type
        ioc_types_pipeline = [
            {'$group': {'_id': '$type', 'count': {'$sum': 1}}},
            {'$sort': {'count': -1}}
        ]
        ioc_types_result = indicators.aggregate(ioc_types_pipeline)
        ioc_types = {doc['_id']: doc['count'] for doc in ioc_types_result}

        # IOC by severity
        severity_pipeline = [
            {'$group': {'_id': '$severity', 'count': {'$sum': 1}}},
            {'$sort': {'count': -1}}
        ]
        severity_result = indicators.aggregate(severity_pipeline)
        severity_breakdown = {doc['_id']: doc['count'] for doc in severity_result}

        # High severity IOCs
        high_severity = indicators.count_documents({'severity': {'$in': ['high', 'critical']}})

        # Recent activity (lookups)
        recent_lookups_24h = lookups.count_documents({'started_at': {'$gte': last_24h}})
        recent_lookups_7d = lookups.count_documents({'started_at': {'$gte': last_7d}})

        # Lookup success rate
        total_lookups = lookups.count_documents({})
        successful_lookups = lookups.count_documents({'status': 'done'})

        # Tags usage
        total_tags = tags_collection.count_documents({})
        tags_usage_pipeline = [
            {'$unwind': '$tags'},
            {'$group': {'_id': '$tags', 'count': {'$sum': 1}}},
            {'$sort': {'count': -1}},
            {'$limit': 10}
        ]
        tags_usage_result = indicators.aggregate(tags_usage_pipeline)
        top_tags = [{'name': doc['_id'], 'count': doc['count']} for doc in tags_usage_result]

        # Sources breakdown
        sources_pipeline = [
            {'$unwind': '$sources'},
            {'$group': {'_id': '$sources.name', 'count': {'$sum': 1}}},
            {'$sort': {'count': -1}},
            {'$limit': 10}
        ]
        sources_result = indicators.aggregate(sources_pipeline)
        top_sources = [{'name': doc['_id'], 'count': doc['count']} for doc in sources_result]

        return jsonify({
            'ioc_metrics': {
                'total': total_iocs,
                'recent_24h': recent_iocs_24h,
                'recent_7d': recent_iocs_7d,
                'recent_30d': recent_iocs_30d,
                'by_type': ioc_types,
                'by_severity': severity_breakdown,
                'high_severity_count': high_severity
            },
            'lookup_metrics': {
                'total': total_lookups,
                'recent_24h': recent_lookups_24h,
                'recent_7d': recent_lookups_7d,
                'success_rate': (successful_lookups / total_lookups * 100) if total_lookups > 0 else 0
            },
            'tag_metrics': {
                'total_tags': total_tags,
                'top_tags': top_tags
            },
            'source_metrics': {
                'top_sources': top_sources
            },
            'generated_at': now.isoformat()
        })

    except Exception as e:
        logger.error(f"Error retrieving overview metrics: {e}")
        return jsonify({'error': 'Failed to retrieve overview metrics'}), 500


@metrics_bp.route('/timeseries', methods=['GET'])
@jwt_required()
def get_timeseries():
    """Get time series data for charts"""
    try:
        from database import MongoDB
        indicators = MongoDB.get_collection('indicators')
        lookups = MongoDB.get_collection('lookups')

        # Get date range from query params (default to last 30 days)
        days = min(int(request.args.get('days', 30)), 365)  # Max 1 year
        now = datetime.utcnow()
        start_date = now - timedelta(days=days)

        # IOC creation timeseries
        ioc_pipeline = [
            {'$match': {'created_at': {'$gte': start_date}}},
            {'$group': {
                '_id': {
                    '$dateToString': {
                        'format': '%Y-%m-%d',
                        'date': '$created_at'
                    }
                },
                'count': {'$sum': 1},
                'by_type': {
                    '$push': '$type'
                }
            }},
            {'$sort': {'_id': 1}}
        ]

        ioc_result = indicators.aggregate(ioc_pipeline)
        ioc_timeseries = []
        for doc in ioc_result:
            # Count by type for this day
            type_counts = {}
            for ioc_type in doc['by_type']:
                type_counts[ioc_type] = type_counts.get(ioc_type, 0) + 1

            ioc_timeseries.append({
                'date': doc['_id'],
                'total': doc['count'],
                'by_type': type_counts
            })

        # Lookup timeseries
        lookup_pipeline = [
            {'$match': {'started_at': {'$gte': start_date}}},
            {'$group': {
                '_id': {
                    '$dateToString': {
                        'format': '%Y-%m-%d',
                        'date': '$started_at'
                    }
                },
                'total': {'$sum': 1},
                'successful': {
                    '$sum': {'$cond': [{'$eq': ['$status', 'done']}, 1, 0]}
                },
                'failed': {
                    '$sum': {'$cond': [{'$eq': ['$status', 'error']}, 1, 0]}
                }
            }},
            {'$sort': {'_id': 1}}
        ]

        lookup_result = lookups.aggregate(lookup_pipeline)
        lookup_timeseries = []
        for doc in lookup_result:
            lookup_timeseries.append({
                'date': doc['_id'],
                'total': doc['total'],
                'successful': doc['successful'],
                'failed': doc['failed'],
                'success_rate': (doc['successful'] / doc['total'] * 100) if doc['total'] > 0 else 0
            })

        # Score distribution
        score_pipeline = [
            {'$match': {'score': {'$exists': True}}},
            {'$group': {
                '_id': {
                    '$switch': {
                        'branches': [
                            {'case': {'$lte': ['$score', 25]}, 'then': '0-25'},
                            {'case': {'$lte': ['$score', 50]}, 'then': '26-50'},
                            {'case': {'$lte': ['$score', 75]}, 'then': '51-75'},
                            {'case': {'$lte': ['$score', 100]}, 'then': '76-100'}
                        ],
                        'default': 'unknown'
                    }
                },
                'count': {'$sum': 1}
            }},
            {'$sort': {'_id': 1}}
        ]

        score_result = indicators.aggregate(score_pipeline)
        score_distribution = {doc['_id']: doc['count'] for doc in score_result}

        return jsonify({
            'ioc_timeseries': ioc_timeseries,
            'lookup_timeseries': lookup_timeseries,
            'score_distribution': score_distribution,
            'period_days': days,
            'generated_at': now.isoformat()
        })

    except Exception as e:
        logger.error(f"Error retrieving timeseries metrics: {e}")
        return jsonify({'error': 'Failed to retrieve timeseries metrics'}), 500


@metrics_bp.route('/threats', methods=['GET'])
@jwt_required()
def get_threats():
    """Get threat intelligence metrics"""
    try:
        from database import MongoDB
        indicators = MongoDB.get_collection('indicators')

        # Threat level breakdown
        threat_levels = {
            'critical': indicators.count_documents({'severity': 'critical'}),
            'high': indicators.count_documents({'severity': 'high'}),
            'medium': indicators.count_documents({'severity': 'medium'}),
            'low': indicators.count_documents({'severity': 'low'}),
            'info': indicators.count_documents({'severity': 'info'})
        }

        # Recent high-severity threats
        recent_high_severity = []
        high_severity_docs = indicators.find(
            {'severity': {'$in': ['high', 'critical']}},
            {'_id': 1, 'type': 1, 'value': 1, 'score': 1, 'severity': 1, 'last_seen': 1}
        ).sort('last_seen', -1).limit(10)

        for doc in high_severity_docs:
            recent_high_severity.append({
                'id': str(doc['_id']),
                'type': doc['type'],
                'value': doc['value'],
                'score': doc['score'],
                'severity': doc['severity'],
                'last_seen': doc.get('last_seen')
            })

        # VirusTotal stats
        vt_stats_pipeline = [
            {'$match': {'vt': {'$exists': True}}},
            {'$group': {
                '_id': None,
                'total_with_vt': {'$sum': 1},
                'malicious_detections': {
                    '$sum': {'$cond': [{'$gt': ['$vt.positives', 0]}, 1, 0]}
                },
                'avg_positives': {'$avg': '$vt.positives'},
                'max_positives': {'$max': '$vt.positives'}
            }}
        ]

        vt_stats_result = list(indicators.aggregate(vt_stats_pipeline))
        vt_stats = vt_stats_result[0] if vt_stats_result else {}

        # AbuseIPDB stats (for IPs only)
        abuseipdb_stats_pipeline = [
            {'$match': {'type': 'ip', 'abuseipdb': {'$exists': True}}},
            {'$group': {
                '_id': None,
                'total_with_abuseipdb': {'$sum': 1},
                'high_confidence': {
                    '$sum': {'$cond': [{'$gte': ['$abuseipdb.abuse_confidence', 75]}, 1, 0]}
                },
                'avg_confidence': {'$avg': '$abuseipdb.abuse_confidence'}
            }}
        ]

        abuseipdb_stats_result = list(indicators.aggregate(abuseipdb_stats_pipeline))
        abuseipdb_stats = abuseipdb_stats_result[0] if abuseipdb_stats_result else {}

        return jsonify({
            'threat_levels': threat_levels,
            'recent_high_severity': recent_high_severity,
            'virustotal_stats': {
                'total_scanned': vt_stats.get('total_with_vt', 0),
                'malicious_count': vt_stats.get('malicious_detections', 0),
                'avg_positives': round(vt_stats.get('avg_positives', 0), 2),
                'max_positives': vt_stats.get('max_positives', 0)
            },
            'abuseipdb_stats': {
                'total_scanned': abuseipdb_stats.get('total_with_abuseipdb', 0),
                'high_confidence_count': abuseipdb_stats.get('high_confidence', 0),
                'avg_confidence': round(abuseipdb_stats.get('avg_confidence', 0), 2)
            },
            'generated_at': datetime.utcnow().isoformat()
        })

    except Exception as e:
        logger.error(f"Error retrieving threat metrics: {e}")
        return jsonify({'error': 'Failed to retrieve threat metrics'}), 500


@metrics_bp.route('/system', methods=['GET'])
@jwt_required()
def get_system_stats():
    """Get system-level statistics"""
    try:
        from database import MongoDB
        indicators = MongoDB.get_collection('indicators')
        lookups = MongoDB.get_collection('lookups')
        tags_collection = MongoDB.get_collection('tags')
        enrichment_runs = MongoDB.get_collection('enrichment_runs')

        # Database sizes
        db_stats = MongoDB.get_database().command('dbStats')
        total_size = db_stats.get('dataSize', 0) + db_stats.get('indexSize', 0)

        # Collection counts
        collection_counts = {
            'indicators': indicators.count_documents({}),
            'lookups': lookups.count_documents({}),
            'tags': tags_collection.count_documents({}),
            'enrichment_runs': enrichment_runs.count_documents({})
        }

        # Recent activity
        now = datetime.utcnow()
        last_hour = now - timedelta(hours=1)
        last_24h = now - timedelta(hours=24)

        recent_activity = {
            'last_hour': {
                'new_iocs': indicators.count_documents({'created_at': {'$gte': last_hour}}),
                'lookups': lookups.count_documents({'started_at': {'$gte': last_hour}})
            },
            'last_24h': {
                'new_iocs': indicators.count_documents({'created_at': {'$gte': last_24h}}),
                'lookups': lookups.count_documents({'started_at': {'$gte': last_24h}})
            }
        }

        # Last enrichment run
        last_enrichment = enrichment_runs.find_one(sort=[('finished_at', -1)])
        enrichment_info = None
        if last_enrichment:
            enrichment_info = {
                'last_run': last_enrichment.get('finished_at'),
                'status': last_enrichment.get('status'),
                'processed_count': last_enrichment.get('processed_count', 0),
                'duration_seconds': last_enrichment.get('duration_seconds', 0)
            }

        return jsonify({
            'database': {
                'total_size_mb': round(total_size / (1024 * 1024), 2),
                'collections': collection_counts
            },
            'recent_activity': recent_activity,
            'enrichment': enrichment_info,
            'generated_at': now.isoformat()
        })

    except Exception as e:
        logger.error(f"Error retrieving system stats: {e}")
        return jsonify({'error': 'Failed to retrieve system statistics'}), 500
