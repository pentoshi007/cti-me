"""
Metrics API routes for dashboard analytics
"""
from datetime import datetime, timedelta
from flask import request
from flask_restx import Resource, Namespace, fields
from flask_jwt_extended import jwt_required

from database import MongoDB
from utils.decorators import require_permission

metrics_ns = Namespace('metrics', description='Dashboard metrics and analytics')

# API Models
overview_model = metrics_ns.model('Overview', {
    'total_iocs': fields.Integer(description='Total number of IOCs'),
    'severity_counts': fields.Raw(description='Count by severity level'),
    'recent_iocs_24h': fields.Integer(description='IOCs added in last 24 hours'),
    'recent_iocs_7d': fields.Integer(description='IOCs added in last 7 days'),
    'top_sources': fields.Raw(description='Top IOC sources'),
    'top_tags': fields.Raw(description='Most used tags')
})

timeseries_model = metrics_ns.model('TimeSeries', {
    'labels': fields.List(fields.String, description='Time labels'),
    'datasets': fields.List(fields.Raw, description='Data series')
})


@metrics_ns.route('/overview')
class MetricsOverview(Resource):
    @metrics_ns.marshal_with(overview_model)
    def get(self):
        """Get dashboard overview metrics"""
        indicators = MongoDB.get_collection('indicators')
        
        # Total IOCs
        total_iocs = indicators.count_documents({})
        
        # Severity counts
        severity_pipeline = [
            {'$group': {'_id': '$severity', 'count': {'$sum': 1}}},
            {'$sort': {'_id': 1}}
        ]
        severity_result = indicators.aggregate(severity_pipeline)
        severity_counts = {doc['_id']: doc['count'] for doc in severity_result}
        
        # Recent IOCs (last 24h and 7d)
        now = datetime.utcnow()
        last_24h = now - timedelta(hours=24)
        last_7d = now - timedelta(days=7)
        
        recent_24h = indicators.count_documents({'created_at': {'$gte': last_24h}})
        recent_7d = indicators.count_documents({'created_at': {'$gte': last_7d}})
        
        # Top sources
        sources_pipeline = [
            {'$unwind': '$sources'},
            {'$group': {'_id': '$sources.name', 'count': {'$sum': 1}}},
            {'$sort': {'count': -1}},
            {'$limit': 5}
        ]
        sources_result = indicators.aggregate(sources_pipeline)
        top_sources = [{'name': doc['_id'], 'count': doc['count']} for doc in sources_result]
        
        # Top tags
        tags_pipeline = [
            {'$unwind': '$tags'},
            {'$group': {'_id': '$tags', 'count': {'$sum': 1}}},
            {'$sort': {'count': -1}},
            {'$limit': 10}
        ]
        tags_result = indicators.aggregate(tags_pipeline)
        top_tags = [{'name': doc['_id'], 'count': doc['count']} for doc in tags_result]
        
        return {
            'total_iocs': total_iocs,
            'severity_counts': severity_counts,
            'recent_iocs_24h': recent_24h,
            'recent_iocs_7d': recent_7d,
            'top_sources': top_sources,
            'top_tags': top_tags
        }


@metrics_ns.route('/timeseries')
class MetricsTimeSeries(Resource):
    @metrics_ns.marshal_with(timeseries_model)
    @metrics_ns.doc(params={
        'interval': 'Time interval (day, week)',
        'from': 'Start date (YYYY-MM-DD)',
        'to': 'End date (YYYY-MM-DD)',
        'group_by': 'Group by field (severity, type, source)'
    })
    def get(self):
        """Get time series data for IOC trends"""
        interval = request.args.get('interval', 'day')
        from_date = request.args.get('from')
        to_date = request.args.get('to')
        group_by = request.args.get('group_by', 'total')
        
        # Parse dates
        if from_date:
            try:
                from_date = datetime.fromisoformat(from_date)
            except ValueError:
                from_date = datetime.utcnow() - timedelta(days=30)
        else:
            from_date = datetime.utcnow() - timedelta(days=30)
        
        if to_date:
            try:
                to_date = datetime.fromisoformat(to_date)
            except ValueError:
                to_date = datetime.utcnow()
        else:
            to_date = datetime.utcnow()
        
        # Determine date format based on interval
        if interval == 'week':
            date_format = '%Y-%W'  # Year-Week
            timedelta_unit = timedelta(weeks=1)
        else:
            date_format = '%Y-%m-%d'  # Year-Month-Day
            timedelta_unit = timedelta(days=1)
        
        indicators = MongoDB.get_collection('indicators')
        
        # Build aggregation pipeline
        if group_by == 'severity':
            pipeline = [
                {'$match': {'created_at': {'$gte': from_date, '$lte': to_date}}},
                {
                    '$group': {
                        '_id': {
                            'date': {'$dateToString': {'format': date_format, 'date': '$created_at'}},
                            'severity': '$severity'
                        },
                        'count': {'$sum': 1}
                    }
                },
                {'$sort': {'_id.date': 1}}
            ]
        elif group_by == 'type':
            pipeline = [
                {'$match': {'created_at': {'$gte': from_date, '$lte': to_date}}},
                {
                    '$group': {
                        '_id': {
                            'date': {'$dateToString': {'format': date_format, 'date': '$created_at'}},
                            'type': '$type'
                        },
                        'count': {'$sum': 1}
                    }
                },
                {'$sort': {'_id.date': 1}}
            ]
        else:
            # Total counts
            pipeline = [
                {'$match': {'created_at': {'$gte': from_date, '$lte': to_date}}},
                {
                    '$group': {
                        '_id': {'$dateToString': {'format': date_format, 'date': '$created_at'}},
                        'count': {'$sum': 1}
                    }
                },
                {'$sort': {'_id': 1}}
            ]
        
        result = indicators.aggregate(pipeline)
        
        # Process results
        if group_by in ['severity', 'type']:
            # Multi-series data
            data_by_date = {}
            categories = set()
            
            for doc in result:
                date = doc['_id']['date']
                category = doc['_id'][group_by]
                count = doc['count']
                
                if date not in data_by_date:
                    data_by_date[date] = {}
                
                data_by_date[date][category] = count
                categories.add(category)
            
            # Generate labels (all dates in range)
            labels = []
            current_date = from_date
            while current_date <= to_date:
                labels.append(current_date.strftime(date_format.replace('%Y-%W', '%Y-W%W')))
                current_date += timedelta_unit
            
            # Generate datasets
            datasets = []
            for category in sorted(categories):
                data = []
                for label in labels:
                    data.append(data_by_date.get(label, {}).get(category, 0))
                
                datasets.append({
                    'label': category,
                    'data': data
                })
            
        else:
            # Single series data
            data_by_date = {doc['_id']: doc['count'] for doc in result}
            
            # Generate labels
            labels = []
            data = []
            current_date = from_date
            while current_date <= to_date:
                date_str = current_date.strftime(date_format)
                labels.append(date_str)
                data.append(data_by_date.get(date_str, 0))
                current_date += timedelta_unit
            
            datasets = [{
                'label': 'IOCs',
                'data': data
            }]
        
        return {
            'labels': labels,
            'datasets': datasets
        }
