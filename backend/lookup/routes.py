"""
Lookup API routes - Full Flask blueprint implementation
"""
import asyncio
import logging
from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required
from utils.decorators import get_current_user
from bson import ObjectId
from datetime import datetime
import nest_asyncio

from lookup.models import Lookup
from lookup.service import LookupService
from auth.models import User

logger = logging.getLogger(__name__)

lookup_bp = Blueprint('lookup', __name__)


@lookup_bp.route('/', methods=['POST'])
@jwt_required()
def perform_lookup():
    """Perform IOC lookup with enrichment"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400

        indicator_value = data.get('indicator', '').strip()
        if not indicator_value:
            return jsonify({'error': 'Indicator value is required'}), 400

        user = get_current_user()
        if not user:
            return jsonify({'error': 'User authentication required'}), 401

        # Create lookup service
        lookup_service = LookupService()

        # Apply nest_asyncio to handle nested event loops in serverless environment
        nest_asyncio.apply()

        try:
            # Run the async lookup
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

            try:
                # Perform lookup asynchronously
                result = loop.run_until_complete(
                    lookup_service.perform_lookup(indicator_value, str(user._id))
                )
                ioc, lookup = result

                if not ioc:
                    return jsonify({
                        'error': 'Failed to process indicator',
                        'lookup_id': str(lookup._id) if lookup else None
                    }), 400

                # Return successful result
                return jsonify({
                    'ioc': ioc.to_dict(),
                    'lookup_id': str(lookup._id) if lookup else None,
                    'status': lookup.status if lookup else 'unknown'
                }), 201

            finally:
                loop.close()

        except Exception as e:
            logger.error(f"Async lookup failed: {e}")
            return jsonify({'error': f'Lookup failed: {str(e)}'}), 500

    except Exception as e:
        logger.error(f"Error performing lookup: {e}")
        return jsonify({'error': 'Failed to perform lookup'}), 500


@lookup_bp.route('/history', methods=['GET'])
@jwt_required()
def lookup_history():
    """Get lookup history for the current user"""
    try:
        user = get_current_user()
        if not user:
            return jsonify({'error': 'User authentication required'}), 401

        # Query parameters
        page = int(request.args.get('page', 1))
        limit = min(int(request.args.get('limit', 20)), 100)  # Max 100 per page
        skip = (page - 1) * limit

        # Filters
        status = request.args.get('status')
        date_from = request.args.get('date_from')
        date_to = request.args.get('date_to')

        from database import MongoDB
        lookups_collection = MongoDB.get_collection('lookups')

        # Build query
        query = {'user_id': str(user._id)}

        if status and status in Lookup.STATUSES:
            query['status'] = status

        if date_from:
            try:
                from_date = datetime.fromisoformat(date_from.replace('Z', '+00:00'))
                query['started_at'] = {'$gte': from_date}
            except (ValueError, AttributeError):
                pass

        if date_to:
            try:
                to_date = datetime.fromisoformat(date_to.replace('Z', '+00:00'))
                if 'started_at' not in query:
                    query['started_at'] = {}
                query['started_at']['$lte'] = to_date
            except (ValueError, AttributeError):
                pass

        # Get total count
        total = lookups_collection.count_documents(query)

        # Get results with pagination and sorting
        cursor = lookups_collection.find(query).sort('started_at', -1).skip(skip).limit(limit)
        lookups_data = []

        for doc in cursor:
            lookup = Lookup.from_dict(doc)
            lookup_dict = lookup.to_dict()

            # Add IOC information if available
            if lookup.result_indicator_id:
                from iocs.models import IOC
                ioc = IOC.find_by_id(lookup.result_indicator_id)
                if ioc:
                    lookup_dict['ioc'] = {
                        'id': ioc._id,
                        'type': ioc.type,
                        'value': ioc.value,
                        'score': ioc.score,
                        'severity': ioc.severity
                    }

            lookups_data.append(lookup_dict)

        return jsonify({
            'lookups': lookups_data,
            'pagination': {
                'page': page,
                'limit': limit,
                'total': total,
                'pages': (total + limit - 1) // limit
            }
        })

    except Exception as e:
        logger.error(f"Error retrieving lookup history: {e}")
        return jsonify({'error': 'Failed to retrieve lookup history'}), 500


@lookup_bp.route('/<lookup_id>', methods=['GET'])
@jwt_required()
def get_lookup(lookup_id):
    """Get specific lookup by ID"""
    try:
        if not ObjectId.is_valid(lookup_id):
            return jsonify({'error': 'Invalid lookup ID format'}), 400

        user = get_current_user()
        if not user:
            return jsonify({'error': 'User authentication required'}), 401

        lookup = Lookup.find_by_id(lookup_id)
        if not lookup:
            return jsonify({'error': 'Lookup not found'}), 404

        # Check if user owns this lookup
        if lookup.user_id != str(user._id):
            return jsonify({'error': 'Access denied'}), 403

        lookup_dict = lookup.to_dict()

        # Add IOC information if available
        if lookup.result_indicator_id:
            from iocs.models import IOC
            ioc = IOC.find_by_id(lookup.result_indicator_id)
            if ioc:
                lookup_dict['ioc'] = ioc.to_dict()

        return jsonify(lookup_dict)

    except Exception as e:
        logger.error(f"Error retrieving lookup {lookup_id}: {e}")
        return jsonify({'error': 'Failed to retrieve lookup'}), 500


@lookup_bp.route('/<lookup_id>', methods=['DELETE'])
@jwt_required()
def delete_lookup(lookup_id):
    """Delete a lookup record"""
    try:
        if not ObjectId.is_valid(lookup_id):
            return jsonify({'error': 'Invalid lookup ID format'}), 400

        user = get_current_user()
        if not user:
            return jsonify({'error': 'User authentication required'}), 401

        lookup = Lookup.find_by_id(lookup_id)
        if not lookup:
            return jsonify({'error': 'Lookup not found'}), 404

        # Check if user owns this lookup
        if lookup.user_id != str(user._id):
            return jsonify({'error': 'Access denied'}), 403

        # Delete from database
        from database import MongoDB
        lookups_collection = MongoDB.get_collection('lookups')
        result = lookups_collection.delete_one({'_id': ObjectId(lookup_id)})

        if result.deleted_count > 0:
            logger.info(f"Deleted lookup {lookup_id} by user {user.username}")
            return jsonify({'message': 'Lookup deleted successfully'})
        else:
            return jsonify({'error': 'Failed to delete lookup'}), 500

    except Exception as e:
        logger.error(f"Error deleting lookup {lookup_id}: {e}")
        return jsonify({'error': 'Failed to delete lookup'}), 500


@lookup_bp.route('/stats', methods=['GET'])
@jwt_required()
def lookup_stats():
    """Get lookup statistics for the current user"""
    try:
        user = get_current_user()
        if not user:
            return jsonify({'error': 'User authentication required'}), 401

        from database import MongoDB
        lookups_collection = MongoDB.get_collection('lookups')

        # Get stats for current user
        pipeline = [
            {'$match': {'user_id': str(user._id)}},
            {'$group': {
                '_id': '$status',
                'count': {'$sum': 1},
                'avg_duration': {
                    '$avg': {
                        '$cond': {
                            'if': {'$and': ['$started_at', '$finished_at']},
                            'then': {'$subtract': ['$finished_at', '$started_at']},
                            'else': None
                        }
                    }
                }
            }}
        ]

        stats_result = lookups_collection.aggregate(pipeline)
        stats = {doc['_id']: doc for doc in stats_result}

        # Get total lookups
        total_lookups = lookups_collection.count_documents({'user_id': str(user._id)})

        # Get recent activity (last 7 days)
        seven_days_ago = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
        recent_lookups = lookups_collection.count_documents({
            'user_id': str(user._id),
            'started_at': {'$gte': seven_days_ago}
        })

        return jsonify({
            'total_lookups': total_lookups,
            'recent_lookups': recent_lookups,
            'status_breakdown': {
                'pending': stats.get('pending', {}).get('count', 0),
                'done': stats.get('done', {}).get('count', 0),
                'error': stats.get('error', {}).get('count', 0)
            },
            'performance': {
                'success_rate': (stats.get('done', {}).get('count', 0) / total_lookups * 100) if total_lookups > 0 else 0,
                'error_rate': (stats.get('error', {}).get('count', 0) / total_lookups * 100) if total_lookups > 0 else 0
            }
        })

    except Exception as e:
        logger.error(f"Error retrieving lookup stats: {e}")
        return jsonify({'error': 'Failed to retrieve lookup statistics'}), 500
