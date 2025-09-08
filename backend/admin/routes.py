"""
Admin API routes - Full Flask blueprint implementation
"""
import asyncio
import logging
from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_current_user
from datetime import datetime
import nest_asyncio

from auth.models import User
from lookup.service import LookupService
from ingestion.urlhaus_fetcher import URLHausFetcher

logger = logging.getLogger(__name__)

admin_bp = Blueprint('admin', __name__)


def require_admin():
    """Decorator to check admin permissions"""
    def decorator(f):
        def wrapper(*args, **kwargs):
            user = get_current_user()
            if not user or not user.has_permission('admin'):
                return jsonify({'error': 'Admin permission required'}), 403
            return f(*args, **kwargs)
        wrapper.__name__ = f.__name__
        return wrapper
    return decorator


@admin_bp.route('/system/stats', methods=['GET'])
@jwt_required()
@require_admin()
def get_system_stats():
    """Get system statistics and health information"""
    try:
        from database import MongoDB
        indicators = MongoDB.get_collection('indicators')
        lookups = MongoDB.get_collection('lookups')
        tags_collection = MongoDB.get_collection('tags')
        users = MongoDB.get_collection('users')

        # Database statistics
        total_iocs = indicators.count_documents({})
        total_lookups = lookups.count_documents({})
        total_tags = tags_collection.count_documents({})
        total_users = users.count_documents({})

        # Recent activity (last 24 hours)
        now = datetime.utcnow()
        last_24h = now.replace(hour=0, minute=0, second=0, microsecond=0)

        recent_iocs = indicators.count_documents({'created_at': {'$gte': last_24h}})
        recent_lookups = lookups.count_documents({'started_at': {'$gte': last_24h}})

        # IOC breakdown by type
        ioc_types_pipeline = [
            {'$group': {'_id': '$type', 'count': {'$sum': 1}}},
            {'$sort': {'count': -1}}
        ]
        ioc_types = list(indicators.aggregate(ioc_types_pipeline))

        # User roles breakdown
        user_roles_pipeline = [
            {'$group': {'_id': '$role', 'count': {'$sum': 1}}},
            {'$sort': {'count': -1}}
        ]
        user_roles = list(users.aggregate(user_roles_pipeline))

        return jsonify({
            'database': {
                'total_iocs': total_iocs,
                'total_lookups': total_lookups,
                'total_tags': total_tags,
                'total_users': total_users
            },
            'recent_activity': {
                'iocs_last_24h': recent_iocs,
                'lookups_last_24h': recent_lookups
            },
            'breakdown': {
                'ioc_types': ioc_types,
                'user_roles': user_roles
            },
            'generated_at': now.isoformat()
        })

    except Exception as e:
        logger.error(f"Error retrieving system stats: {e}")
        return jsonify({'error': 'Failed to retrieve system statistics'}), 500


@admin_bp.route('/ingest/runs', methods=['GET'])
@jwt_required()
@require_admin()
def get_ingest_runs():
    """Get recent ingestion run statistics"""
    try:
        from database import MongoDB
        enrichment_runs = MongoDB.get_collection('enrichment_runs')

        # Get recent runs (last 50)
        runs = list(enrichment_runs.find().sort('finished_at', -1).limit(50))

        # Convert ObjectIds to strings
        for run in runs:
            run['_id'] = str(run['_id'])

        return jsonify({
            'runs': runs,
            'total_runs': len(runs)
        })

    except Exception as e:
        logger.error(f"Error retrieving ingest runs: {e}")
        return jsonify({'error': 'Failed to retrieve ingest runs'}), 500


@admin_bp.route('/all-runs', methods=['GET'])
@jwt_required()
@require_admin()
def get_all_runs():
    """Get all run statistics (ingestion and enrichment)"""
    try:
        from database import MongoDB
        enrichment_runs = MongoDB.get_collection('enrichment_runs')

        # Get all runs
        all_runs = list(enrichment_runs.find().sort('finished_at', -1))

        # Convert ObjectIds to strings
        for run in all_runs:
            run['_id'] = str(run['_id'])

        # Summary statistics
        total_runs = len(all_runs)
        successful_runs = len([r for r in all_runs if r.get('status') == 'completed'])
        failed_runs = len([r for r in all_runs if r.get('status') == 'error'])

        return jsonify({
            'runs': all_runs,
            'summary': {
                'total_runs': total_runs,
                'successful_runs': successful_runs,
                'failed_runs': failed_runs,
                'success_rate': (successful_runs / total_runs * 100) if total_runs > 0 else 0
            }
        })

    except Exception as e:
        logger.error(f"Error retrieving all runs: {e}")
        return jsonify({'error': 'Failed to retrieve runs'}), 500


@admin_bp.route('/ingest/run', methods=['POST'])
@jwt_required()
@require_admin()
def trigger_ingest():
    """Manually trigger URLHaus ingestion"""
    try:
        data = request.get_json() or {}
        source = data.get('source', 'manual')

        logger.info(f"Starting manual ingestion from source: {source}")

        # Create URLHaus fetcher
        urlhaus_fetcher = URLHausFetcher()

        # Apply nest_asyncio to handle nested event loops in serverless environment
        nest_asyncio.apply()

        try:
            # Run the async ingestion
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

            try:
                # Perform ingestion asynchronously
                result = loop.run_until_complete(
                    urlhaus_fetcher.fetch_and_ingest()
                )

                return jsonify({
                    'message': 'Ingestion completed successfully',
                    'result': result,
                    'source': source,
                    'status': 'completed'
                }), 200

            finally:
                loop.close()

        except Exception as e:
            logger.error(f"Ingestion failed: {e}")
            return jsonify({
                'error': f'Ingestion failed: {str(e)}',
                'source': source,
                'status': 'failed'
            }), 500

    except Exception as e:
        logger.error(f"Error triggering ingestion: {e}")
        return jsonify({'error': 'Failed to trigger ingestion'}), 500


@admin_bp.route('/enrichment/run', methods=['POST'])
@jwt_required()
@require_admin()
def trigger_enrichment():
    """Manually trigger IOC enrichment"""
    try:
        data = request.get_json() or {}
        limit = data.get('limit', 500)

        logger.info(f"Starting manual enrichment for up to {limit} IOCs")

        # Create lookup service
        lookup_service = LookupService()

        # Apply nest_asyncio to handle nested event loops in serverless environment
        nest_asyncio.apply()

        try:
            # Run the async enrichment
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

            try:
                # Perform enrichment asynchronously
                result = loop.run_until_complete(
                    lookup_service.bulk_enrich_recent_iocs(limit=limit)
                )

                return jsonify({
                    'message': 'Enrichment completed successfully',
                    'result': result,
                    'limit': limit,
                    'status': 'completed'
                }), 200

            finally:
                loop.close()

        except Exception as e:
            logger.error(f"Enrichment failed: {e}")
            return jsonify({
                'error': f'Enrichment failed: {str(e)}',
                'limit': limit,
                'status': 'failed'
            }), 500

    except Exception as e:
        logger.error(f"Error triggering enrichment: {e}")
        return jsonify({'error': 'Failed to trigger enrichment'}), 500


@admin_bp.route('/auto-run/check', methods=['GET'])
@jwt_required()
@require_admin()
def check_auto_run():
    """Check status of automatic background tasks"""
    try:
        # This would normally check the APScheduler status
        # For now, return a simple status
        return jsonify({
            'auto_ingestion': {
                'enabled': True,
                'interval_minutes': 30,
                'last_run': None,  # Would be populated from scheduler
                'next_run': None   # Would be populated from scheduler
            },
            'auto_enrichment': {
                'enabled': True,
                'interval_minutes': 60,
                'last_run': None,  # Would be populated from scheduler
                'next_run': None   # Would be populated from scheduler
            },
            'scheduler_status': 'active'
        })

    except Exception as e:
        logger.error(f"Error checking auto-run status: {e}")
        return jsonify({'error': 'Failed to check auto-run status'}), 500


@admin_bp.route('/users', methods=['GET'])
@jwt_required()
@require_admin()
def get_users():
    """Get all users (admin only)"""
    try:
        from database import MongoDB
        users_collection = MongoDB.get_collection('users')

        # Get all users
        users = list(users_collection.find({}, {'password_hash': 0}))  # Exclude password hashes

        # Convert ObjectIds to strings
        for user in users:
            user['_id'] = str(user['_id'])

        return jsonify({
            'users': users,
            'total_users': len(users)
        })

    except Exception as e:
        logger.error(f"Error retrieving users: {e}")
        return jsonify({'error': 'Failed to retrieve users'}), 500


@admin_bp.route('/users', methods=['POST'])
@jwt_required()
@require_admin()
def create_user():
    """Create a new user (admin only)"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400

        username = data.get('username', '').strip()
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        role = data.get('role', 'viewer').lower()

        # Validation
        if not username or len(username) < 3 or len(username) > 50:
            return jsonify({'error': 'Username must be 3-50 characters long'}), 400

        if not email or '@' not in email:
            return jsonify({'error': 'Valid email address required'}), 400

        if not password or len(password) < 8:
            return jsonify({'error': 'Password must be at least 8 characters long'}), 400

        if role not in ['admin', 'analyst', 'viewer']:
            role = 'viewer'

        # Check if user already exists
        if User.find_by_username(username):
            return jsonify({'error': 'Username already exists'}), 409

        if User.find_by_email(email):
            return jsonify({'error': 'Email already registered'}), 409

        # Create user
        user = User(
            username=username,
            email=email,
            role=role
        )
        user.set_password(password)
        user.save()

        logger.info(f"Admin created user: {username} with role: {role}")

        return jsonify({
            'message': 'User created successfully',
            'user': user.to_dict()
        }), 201

    except Exception as e:
        logger.error(f"Error creating user: {e}")
        return jsonify({'error': 'Failed to create user'}), 500


@admin_bp.route('/users/<user_id>', methods=['PATCH'])
@jwt_required()
@require_admin()
def update_user(user_id):
    """Update user information (admin only)"""
    try:
        from bson import ObjectId

        if not ObjectId.is_valid(user_id):
            return jsonify({'error': 'Invalid user ID format'}), 400

        user = User.find_by_id(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404

        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400

        # Update allowed fields
        if 'role' in data and data['role'] in ['admin', 'analyst', 'viewer']:
            user.role = data['role']

        if 'is_active' in data:
            user.is_active = bool(data['is_active'])

        user.save()

        logger.info(f"Admin updated user {user_id}: role={user.role}, active={user.is_active}")

        return jsonify({
            'message': 'User updated successfully',
            'user': user.to_dict()
        })

    except Exception as e:
        logger.error(f"Error updating user {user_id}: {e}")
        return jsonify({'error': 'Failed to update user'}), 500


@admin_bp.route('/users/<user_id>', methods=['DELETE'])
@jwt_required()
@require_admin()
def delete_user(user_id):
    """Delete a user (admin only)"""
    try:
        from bson import ObjectId

        if not ObjectId.is_valid(user_id):
            return jsonify({'error': 'Invalid user ID format'}), 400

        user = User.find_by_id(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404

        # Prevent deleting self
        current_user = get_current_user()
        if str(user._id) == str(current_user._id):
            return jsonify({'error': 'Cannot delete your own account'}), 400

        # Delete from database
        from database import MongoDB
        users_collection = MongoDB.get_collection('users')
        result = users_collection.delete_one({'_id': ObjectId(user_id)})

        if result.deleted_count > 0:
            logger.info(f"Admin deleted user: {user.username}")
            return jsonify({'message': 'User deleted successfully'})
        else:
            return jsonify({'error': 'Failed to delete user'}), 500

    except Exception as e:
        logger.error(f"Error deleting user {user_id}: {e}")
        return jsonify({'error': 'Failed to delete user'}), 500