"""
Admin API routes
"""
import asyncio
from flask import request
from flask_restx import Resource, Namespace, fields
from flask_jwt_extended import jwt_required

from ingestion.urlhaus_fetcher import URLHausFetcher
from lookup.service import LookupService
from auth.models import User
from utils.decorators import require_permission, get_current_user
from database import MongoDB

admin_ns = Namespace('admin', description='Administrative operations')

# API Models
ingest_run_model = admin_ns.model('IngestRun', {
    'id': fields.String(description='Run ID'),
    'source': fields.String(description='Data source'),
    'status': fields.String(description='Run status'),
    'started_at': fields.String(description='Start timestamp'),
    'finished_at': fields.String(description='Finish timestamp'),
    'fetched_count': fields.Integer(description='Number of items fetched'),
    'new_count': fields.Integer(description='Number of new items'),
    'updated_count': fields.Integer(description='Number of updated items'),
    'error_count': fields.Integer(description='Number of errors'),
    'error': fields.String(description='Error message if failed')
})

trigger_ingest_model = admin_ns.model('TriggerIngest', {
    'source': fields.String(description='Data source to ingest (optional, defaults to all)'),
    'limit': fields.Integer(description='Limit number of IOCs to process (optional, for testing)')
})

enrichment_run_model = admin_ns.model('EnrichmentRun', {
    'id': fields.String(description='Run ID'),
    'operation': fields.String(description='Operation type'),
    'status': fields.String(description='Run status'),
    'started_at': fields.String(description='Start timestamp'),
    'finished_at': fields.String(description='Finish timestamp'),
    'processed_count': fields.Integer(description='Number of IOCs processed'),
    'enriched_count': fields.Integer(description='Number of IOCs enriched'),
    'error_count': fields.Integer(description='Number of errors'),
    'total_candidates': fields.Integer(description='Total candidates found'),
    'duration_seconds': fields.Float(description='Operation duration in seconds'),
    'error': fields.String(description='Error message if failed')
})

system_stats_model = admin_ns.model('SystemStats', {
    'database_stats': fields.Raw(description='Database statistics'),
    'collection_counts': fields.Raw(description='Document counts by collection'),
    'recent_activity': fields.Raw(description='Recent system activity')
})

user_model = admin_ns.model('User', {
    'id': fields.String(description='User ID'),
    'username': fields.String(description='Username'),
    'email': fields.String(description='Email'),
    'role': fields.String(description='User role'),
    'created_at': fields.String(description='Creation timestamp'),
    'last_login': fields.String(description='Last login timestamp')
})

user_create_model = admin_ns.model('UserCreate', {
    'username': fields.String(required=True, description='Username'),
    'email': fields.String(required=True, description='Email'),
    'password': fields.String(required=True, description='Password'),
    'role': fields.String(required=True, description='User role', enum=['admin', 'analyst', 'viewer'])
})

user_update_model = admin_ns.model('UserUpdate', {
    'email': fields.String(description='Email'),
    'role': fields.String(description='User role', enum=['admin', 'analyst', 'viewer']),
    'password': fields.String(description='New password')
})


@admin_ns.route('/ingest/run')
class TriggerIngest(Resource):
    @jwt_required()
    @require_permission('admin')
    @admin_ns.expect(trigger_ingest_model, validate=False)
    def post(self):
        """Trigger manual data ingestion"""
        import logging
        logger = logging.getLogger(__name__)
        
        data = request.get_json() or {}
        source = data.get('source', 'urlhaus')
        limit = data.get('limit')  # Optional limit for testing
        
        logger.info(f"Admin triggering {source} ingestion (limit: {limit or 'none'})")
        
        if source == 'urlhaus':
            try:
                logger.info("Creating URLHausFetcher instance...")
                fetcher = URLHausFetcher()
                
                logger.info("Setting up asyncio loop...")
                # Run in asyncio loop
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                try:
                    logger.info("Starting URLHaus fetch and ingest...")
                    stats = loop.run_until_complete(fetcher.fetch_and_ingest(limit))
                    logger.info(f"URLHaus fetch and ingest completed with stats: {stats}")
                finally:
                    logger.info("Closing asyncio loop...")
                    loop.close()
                
                response = {
                    'success': True,
                    'message': 'URLHaus ingestion completed successfully',
                    'stats': stats,
                    'source': source
                }
                logger.info(f"URLHaus ingestion completed via admin: {stats}")
                
                # Double-check ingest_runs count after operation
                try:
                    ingest_runs = MongoDB.get_collection('ingest_runs')
                    run_count = ingest_runs.count_documents({})
                    logger.info(f"Total ingest_runs count after admin operation: {run_count}")
                except Exception as e:
                    logger.error(f"Failed to check ingest_runs count: {e}")
                
                return response, 200
                
            except Exception as e:
                error_msg = f'Ingestion failed: {str(e)}'
                logger.error(f"Admin ingestion failed: {error_msg}")
                return {
                    'success': False,
                    'message': error_msg,
                    'source': source,
                    'stats': {}
                }, 500
        else:
            return {
                'success': False,
                'message': 'Invalid or unsupported source',
                'source': source
            }, 400


@admin_ns.route('/ingest/runs')
class IngestRunList(Resource):
    @jwt_required()
    @require_permission('admin')
    @admin_ns.marshal_list_with(ingest_run_model)
    @admin_ns.doc(params={
        'source': 'Filter by source',
        'status': 'Filter by status',
        'limit': 'Number of runs to return (default: 20)'
    })
    def get(self):
        """Get list of ingestion runs"""
        import logging
        logger = logging.getLogger(__name__)
        
        try:
            source = request.args.get('source')
            status = request.args.get('status')
            limit = int(request.args.get('limit', 20))
            
            logger.info(f"Fetching ingestion runs: source={source}, status={status}, limit={limit}")
            
            ingest_runs = MongoDB.get_collection('ingest_runs')
            
            # Build query
            query = {}
            if source:
                query['source'] = source
            if status:
                query['status'] = status
            
            logger.info(f"Query: {query}")
            
            # Get runs
            cursor = ingest_runs.find(query).sort('started_at', -1).limit(limit)
            
            runs = []
            for doc in cursor:
                run_data = {
                    'id': str(doc['_id']),
                    'source': doc.get('source'),
                    'status': doc.get('status'),
                    'started_at': doc.get('started_at').isoformat() if doc.get('started_at') else None,
                    'finished_at': doc.get('finished_at').isoformat() if doc.get('finished_at') else None,
                    'fetched_count': doc.get('fetched_count', 0),
                    'new_count': doc.get('new_count', 0),
                    'updated_count': doc.get('updated_count', 0),
                    'error_count': doc.get('error_count', 0),
                    'error': doc.get('error')
                }
                runs.append(run_data)
            
            logger.info(f"Found {len(runs)} ingestion runs")
            return runs
            
        except Exception as e:
            logger.error(f"Error fetching ingestion runs: {e}")
            admin_ns.abort(500, f'Failed to fetch ingestion runs: {str(e)}')


@admin_ns.route('/enrichment/runs')
class EnrichmentRunList(Resource):
    @jwt_required()
    @require_permission('admin')
    @admin_ns.marshal_list_with(enrichment_run_model)
    @admin_ns.doc(params={
        'operation': 'Filter by operation type',
        'status': 'Filter by status',
        'limit': 'Number of runs to return (default: 20)'
    })
    def get(self):
        """Get list of enrichment runs"""
        import logging
        logger = logging.getLogger(__name__)
        
        try:
            operation = request.args.get('operation')
            status = request.args.get('status')
            limit = int(request.args.get('limit', 20))
            
            logger.info(f"Fetching enrichment runs: operation={operation}, status={status}, limit={limit}")
            
            enrichment_runs = MongoDB.get_collection('enrichment_runs')
            
            # Build query
            query = {}
            if operation:
                query['operation'] = operation
            if status:
                query['status'] = status
            
            logger.info(f"Query: {query}")
            
            # Get runs
            cursor = enrichment_runs.find(query).sort('started_at', -1).limit(limit)
            
            runs = []
            for doc in cursor:
                run_data = {
                    'id': str(doc['_id']),
                    'operation': doc.get('operation'),
                    'status': doc.get('status'),
                    'started_at': doc.get('started_at').isoformat() if doc.get('started_at') else None,
                    'finished_at': doc.get('finished_at').isoformat() if doc.get('finished_at') else None,
                    'processed_count': doc.get('processed_count', 0),
                    'enriched_count': doc.get('enriched_count', 0),
                    'error_count': doc.get('error_count', 0),
                    'total_candidates': doc.get('total_candidates', 0),
                    'duration_seconds': doc.get('duration_seconds', 0),
                    'error': doc.get('error')
                }
                runs.append(run_data)
            
            logger.info(f"Found {len(runs)} enrichment runs")
            return runs
            
        except Exception as e:
            logger.error(f"Error fetching enrichment runs: {e}")
            admin_ns.abort(500, f'Failed to fetch enrichment runs: {str(e)}')


@admin_ns.route('/all-runs')
class AllRunsList(Resource):
    @jwt_required()
    @require_permission('admin')
    @admin_ns.doc(params={
        'limit': 'Number of runs to return (default: 50)'
    })
    def get(self):
        """Get combined list of all ingestion and enrichment runs"""
        import logging
        logger = logging.getLogger(__name__)
        
        try:
            limit = int(request.args.get('limit', 50))
            
            logger.info(f"Fetching all runs with limit: {limit}")
            
            # Get ingestion runs
            ingest_runs = MongoDB.get_collection('ingest_runs')
            ingest_cursor = ingest_runs.find().sort('started_at', -1)
            
            # Get enrichment runs
            enrichment_runs = MongoDB.get_collection('enrichment_runs')
            enrichment_cursor = enrichment_runs.find().sort('started_at', -1)
            
            # Combine and sort all runs
            all_runs = []
            
            # Add ingestion runs
            for doc in ingest_cursor:
                run_data = {
                    'id': str(doc['_id']),
                    'type': 'ingestion',
                    'source': doc.get('source'),
                    'operation': doc.get('source', 'ingestion'),
                    'status': doc.get('status'),
                    'started_at': doc.get('started_at').isoformat() if doc.get('started_at') else None,
                    'finished_at': doc.get('finished_at').isoformat() if doc.get('finished_at') else None,
                    'stats': {
                        'fetched_count': doc.get('fetched_count', 0),
                        'new_count': doc.get('new_count', 0),
                        'updated_count': doc.get('updated_count', 0),
                        'error_count': doc.get('error_count', 0)
                    },
                    'error': doc.get('error')
                }
                all_runs.append(run_data)
            
            # Add enrichment runs
            for doc in enrichment_cursor:
                run_data = {
                    'id': str(doc['_id']),
                    'type': 'enrichment',
                    'source': 'enrichment',
                    'operation': doc.get('operation', 'enrichment'),
                    'status': doc.get('status'),
                    'started_at': doc.get('started_at').isoformat() if doc.get('started_at') else None,
                    'finished_at': doc.get('finished_at').isoformat() if doc.get('finished_at') else None,
                    'stats': {
                        'processed_count': doc.get('processed_count', 0),
                        'enriched_count': doc.get('enriched_count', 0),
                        'error_count': doc.get('error_count', 0),
                        'total_candidates': doc.get('total_candidates', 0),
                        'duration_seconds': doc.get('duration_seconds', 0)
                    },
                    'error': doc.get('error')
                }
                all_runs.append(run_data)
            
            # Sort all runs by started_at descending
            all_runs.sort(key=lambda x: x['started_at'] or '', reverse=True)
            
            # Limit results
            all_runs = all_runs[:limit]
            
            logger.info(f"Found {len(all_runs)} total runs")
            return {
                'runs': all_runs,
                'total': len(all_runs)
            }
            
        except Exception as e:
            logger.error(f"Error fetching all runs: {e}")
            admin_ns.abort(500, f'Failed to fetch runs: {str(e)}')


@admin_ns.route('/enrichment/run')
class TriggerEnrichment(Resource):
    @jwt_required()
    @require_permission('admin')
    def post(self):
        """Trigger bulk enrichment of recent IOCs"""
        import logging
        logger = logging.getLogger(__name__)
        
        logger.info("Admin triggering bulk enrichment")
        
        try:
            lookup_service = LookupService()
            
            # Run bulk enrichment
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                stats = loop.run_until_complete(lookup_service.bulk_enrich_recent_iocs())
            finally:
                loop.close()
            
            response = {
                'success': True,
                'message': 'Bulk enrichment completed successfully',
                'stats': stats
            }
            logger.info(f"Bulk enrichment completed via admin: {stats}")
            return response, 200
            
        except Exception as e:
            error_msg = f'Enrichment failed: {str(e)}'
            logger.error(f"Admin enrichment failed: {error_msg}")
            return {
                'success': False,
                'message': error_msg
            }, 500


@admin_ns.route('/system/stats')
class SystemStats(Resource):
    @jwt_required()
    @require_permission('admin')
    @admin_ns.marshal_with(system_stats_model)
    def get(self):
        """Get system statistics"""
        db = MongoDB.get_database()
        
        # Database stats
        db_stats = db.command('dbStats')
        
        # Collection counts
        collections = ['indicators', 'lookups', 'tags', 'exports', 'ingest_runs', 'enrichment_runs', 'users']
        collection_counts = {}
        
        for collection_name in collections:
            try:
                collection = db[collection_name]
                collection_counts[collection_name] = collection.count_documents({})
            except:
                collection_counts[collection_name] = 0
        
        # Recent activity (last 24 hours)
        from datetime import datetime, timedelta
        last_24h = datetime.utcnow() - timedelta(hours=24)
        
        recent_activity = {
            'new_iocs': db.indicators.count_documents({'created_at': {'$gte': last_24h}}),
            'lookups': db.lookups.count_documents({'created_at': {'$gte': last_24h}}),
            'exports': db.exports.count_documents({'created_at': {'$gte': last_24h}}),
            'ingest_runs': db.ingest_runs.count_documents({'started_at': {'$gte': last_24h}}),
            'enrichment_runs': db.enrichment_runs.count_documents({'started_at': {'$gte': last_24h}})
        }
        
        return {
            'database_stats': {
                'dataSize': db_stats.get('dataSize', 0),
                'storageSize': db_stats.get('storageSize', 0),
                'indexSize': db_stats.get('indexSize', 0),
                'collections': db_stats.get('collections', 0)
            },
            'collection_counts': collection_counts,
            'recent_activity': recent_activity
        }


@admin_ns.route('/users')
class UserManagement(Resource):
    @jwt_required()
    @require_permission('admin')
    @admin_ns.marshal_list_with(user_model)
    def get(self):
        """Get list of users (admin only)"""
        users = MongoDB.get_collection('users')
        cursor = users.find({}, {'password_hash': 0}).sort('created_at', -1)
        
        user_list = []
        for doc in cursor:
            user_list.append({
                'id': str(doc['_id']),
                'username': doc.get('username'),
                'email': doc.get('email'),
                'role': doc.get('role'),
                'created_at': doc.get('created_at').isoformat() if doc.get('created_at') else None,
                'last_login': doc.get('last_login').isoformat() if doc.get('last_login') else None
            })
        
        return user_list
    
    @jwt_required()
    @require_permission('admin')
    @admin_ns.expect(user_create_model)
    @admin_ns.marshal_with(user_model)
    def post(self):
        """Create a new user (admin only)"""
        data = request.get_json()
        username = data.get('username', '').strip()
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        role = data.get('role', 'viewer')
        
        # Validation
        if not username or len(username) < 3:
            admin_ns.abort(400, 'Username must be at least 3 characters long')
        
        if not email or '@' not in email:
            admin_ns.abort(400, 'Valid email address required')
        
        if not password or len(password) < 8:
            admin_ns.abort(400, 'Password must be at least 8 characters long')
        
        if role not in ['admin', 'analyst', 'viewer']:
            admin_ns.abort(400, 'Invalid role')
        
        # Check if user already exists
        if User.find_by_username(username):
            admin_ns.abort(409, 'Username already exists')
        
        if User.find_by_email(email):
            admin_ns.abort(409, 'Email already registered')
        
        # Create user
        try:
            user = User(username=username, email=email, role=role)
            user.set_password(password)
            user.save()
            return user.to_dict()
        except Exception as e:
            admin_ns.abort(500, f'User creation failed: {str(e)}')


@admin_ns.route('/users/<string:user_id>')
class UserDetail(Resource):
    @jwt_required()
    @require_permission('admin')
    @admin_ns.marshal_with(user_model)
    def get(self, user_id):
        """Get user details (admin only)"""
        user = User.find_by_id(user_id)
        if not user:
            admin_ns.abort(404, 'User not found')
        return user.to_dict()
    
    @jwt_required()
    @require_permission('admin')
    @admin_ns.expect(user_update_model)
    @admin_ns.marshal_with(user_model)
    def patch(self, user_id):
        """Update user (admin only)"""
        user = User.find_by_id(user_id)
        if not user:
            admin_ns.abort(404, 'User not found')
        
        data = request.get_json()
        
        # Prevent admin from changing their own role to non-admin
        current_user = get_current_user()
        if str(user._id) == str(current_user._id) and data.get('role') != 'admin':
            admin_ns.abort(400, 'Cannot change your own admin role')
        
        # Update fields
        if 'email' in data:
            email = data['email'].strip().lower()
            if email and '@' in email:
                # Check if email is already taken by another user
                existing_user = User.find_by_email(email)
                if existing_user and str(existing_user._id) != user_id:
                    admin_ns.abort(409, 'Email already taken')
                user.email = email
        
        if 'role' in data and data['role'] in ['admin', 'analyst', 'viewer']:
            user.role = data['role']
        
        if 'password' in data and data['password']:
            if len(data['password']) < 8:
                admin_ns.abort(400, 'Password must be at least 8 characters long')
            user.set_password(data['password'])
        
        try:
            user.save()
            return user.to_dict()
        except Exception as e:
            admin_ns.abort(500, f'User update failed: {str(e)}')
    
    @jwt_required()
    @require_permission('admin')
    def delete(self, user_id):
        """Delete user (admin only)"""
        user = User.find_by_id(user_id)
        if not user:
            admin_ns.abort(404, 'User not found')
        
        # Prevent admin from deleting themselves
        current_user = get_current_user()
        if str(user._id) == str(current_user._id):
            admin_ns.abort(400, 'Cannot delete your own account')
        
        try:
            users = MongoDB.get_collection('users')
            users.delete_one({'_id': user._id})
            return {'message': 'User deleted successfully'}
        except Exception as e:
            admin_ns.abort(500, f'User deletion failed: {str(e)}')


@admin_ns.route('/debug/database')
class DatabaseDebug(Resource):
    @jwt_required()
    @require_permission('admin')
    def get(self):
        """Debug database connection and collections"""
        import logging
        logger = logging.getLogger(__name__)
        
        try:
            logger.info("Starting database debug...")
            
            # Test database connection
            db = MongoDB.get_database()
            logger.info(f"Database: {db.name}")
            
            # Test collections
            collections = ['indicators', 'ingest_runs', 'enrichment_runs']
            results = {}
            
            for collection_name in collections:
                try:
                    collection = MongoDB.get_collection(collection_name)
                    count = collection.count_documents({})
                    
                    # Get latest record if any
                    latest = None
                    if count > 0:
                        latest = collection.find_one({}, sort=[('_id', -1)])
                        if latest and '_id' in latest:
                            latest['_id'] = str(latest['_id'])
                    
                    results[collection_name] = {
                        'count': count,
                        'latest': latest
                    }
                    
                    logger.info(f"Collection {collection_name}: {count} documents")
                    
                except Exception as e:
                    logger.error(f"Error with collection {collection_name}: {e}")
                    results[collection_name] = {'error': str(e)}
            
            # Test creating a dummy ingest run
            try:
                from datetime import datetime
                ingest_runs = MongoDB.get_collection('ingest_runs')
                
                test_run = {
                    'source': 'test',
                    'status': 'completed',
                    'started_at': datetime.utcnow(),
                    'finished_at': datetime.utcnow(),
                    'fetched_count': 1,
                    'new_count': 1,
                    'updated_count': 0,
                    'error_count': 0,
                    'created_at': datetime.utcnow()
                }
                
                test_result = ingest_runs.insert_one(test_run)
                logger.info(f"Test insert successful: {test_result.inserted_id}")
                
                # Verify it exists
                verification = ingest_runs.find_one({'_id': test_result.inserted_id})
                if verification:
                    logger.info("Test record verified in database")
                    # Clean up test record
                    ingest_runs.delete_one({'_id': test_result.inserted_id})
                    results['test_insert'] = {'success': True, 'id': str(test_result.inserted_id)}
                else:
                    logger.error("Test record not found after insert!")
                    results['test_insert'] = {'success': False, 'error': 'Record not found after insert'}
                    
            except Exception as e:
                logger.error(f"Test insert failed: {e}")
                results['test_insert'] = {'success': False, 'error': str(e)}
            
            return {
                'database_name': db.name,
                'collections': results,
                'timestamp': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Database debug failed: {e}")
            admin_ns.abort(500, f'Database debug failed: {str(e)}')


@admin_ns.route('/auto-run/check')
class AutoRunCheck(Resource):
    @jwt_required()
    @require_permission('admin')
    def get(self):
        """Check if operations should be run automatically (last run > 5 hours ago)"""
        import logging
        from datetime import datetime, timedelta
        logger = logging.getLogger(__name__)
        
        try:
            now = datetime.utcnow()
            threshold = now - timedelta(hours=5)
            
            # Check last ingestion run
            ingest_runs = MongoDB.get_collection('ingest_runs')
            last_ingest = ingest_runs.find_one({}, sort=[('started_at', -1)])
            
            should_run_ingestion = True
            last_ingest_time = None
            if last_ingest and last_ingest.get('started_at'):
                last_ingest_time = last_ingest['started_at']
                should_run_ingestion = last_ingest_time < threshold
            
            # Check last enrichment run
            enrichment_runs = MongoDB.get_collection('enrichment_runs')
            last_enrichment = enrichment_runs.find_one({}, sort=[('started_at', -1)])
            
            should_run_enrichment = True
            last_enrichment_time = None
            if last_enrichment and last_enrichment.get('started_at'):
                last_enrichment_time = last_enrichment['started_at']
                should_run_enrichment = last_enrichment_time < threshold
            
            return {
                'current_time': now.isoformat(),
                'threshold_time': threshold.isoformat(),
                'ingestion': {
                    'should_run': should_run_ingestion,
                    'last_run': last_ingest_time.isoformat() if last_ingest_time else None,
                    'hours_since_last': ((now - last_ingest_time).total_seconds() / 3600) if last_ingest_time else None
                },
                'enrichment': {
                    'should_run': should_run_enrichment,
                    'last_run': last_enrichment_time.isoformat() if last_enrichment_time else None,
                    'hours_since_last': ((now - last_enrichment_time).total_seconds() / 3600) if last_enrichment_time else None
                }
            }
            
        except Exception as e:
            logger.error(f"Auto-run check failed: {e}")
            admin_ns.abort(500, f'Auto-run check failed: {str(e)}')


@admin_ns.route('/auto-run/execute')
class AutoRunExecute(Resource):
    @jwt_required()
    @require_permission('admin')
    def post(self):
        """Execute operations automatically if they haven't run in 5+ hours"""
        import logging
        from datetime import datetime, timedelta
        logger = logging.getLogger(__name__)
        
        try:
            now = datetime.utcnow()
            threshold = now - timedelta(hours=5)
            
            results = {
                'ingestion': {'executed': False, 'reason': 'Not needed'},
                'enrichment': {'executed': False, 'reason': 'Not needed'}
            }
            
            # Check and run ingestion if needed
            ingest_runs = MongoDB.get_collection('ingest_runs')
            last_ingest = ingest_runs.find_one({}, sort=[('started_at', -1)])
            
            if not last_ingest or last_ingest.get('started_at', datetime.min) < threshold:
                logger.info("Auto-triggering URLHaus ingestion (5+ hours since last run)")
                try:
                    fetcher = URLHausFetcher()
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                    try:
                        stats = loop.run_until_complete(fetcher.fetch_and_ingest(limit=1000))  # Limit for auto-run
                        results['ingestion'] = {
                            'executed': True,
                            'reason': 'Auto-triggered after 5+ hours',
                            'stats': stats
                        }
                    finally:
                        loop.close()
                except Exception as e:
                    results['ingestion'] = {
                        'executed': False,
                        'reason': f'Failed: {str(e)}'
                    }
            
            # Check and run enrichment if needed
            enrichment_runs = MongoDB.get_collection('enrichment_runs')
            last_enrichment = enrichment_runs.find_one({}, sort=[('started_at', -1)])
            
            if not last_enrichment or last_enrichment.get('started_at', datetime.min) < threshold:
                logger.info("Auto-triggering bulk enrichment (5+ hours since last run)")
                try:
                    lookup_service = LookupService()
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                    try:
                        stats = loop.run_until_complete(lookup_service.bulk_enrich_recent_iocs(limit=100))  # Limit for auto-run
                        results['enrichment'] = {
                            'executed': True,
                            'reason': 'Auto-triggered after 5+ hours',
                            'stats': stats
                        }
                    finally:
                        loop.close()
                except Exception as e:
                    results['enrichment'] = {
                        'executed': False,
                        'reason': f'Failed: {str(e)}'
                    }
            
            return {
                'success': True,
                'message': 'Auto-run check completed',
                'results': results,
                'timestamp': now.isoformat()
            }
            
        except Exception as e:
            logger.error(f"Auto-run execution failed: {e}")
            admin_ns.abort(500, f'Auto-run execution failed: {str(e)}')
