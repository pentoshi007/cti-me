"""
Lookup API routes
"""
import asyncio
import threading
from concurrent.futures import ThreadPoolExecutor
from flask import request, current_app
from flask_restx import Resource, Namespace, fields
from flask_jwt_extended import jwt_required
from flask_limiter.util import get_remote_address

from lookup.service import LookupService
from lookup.models import Lookup
from utils.decorators import require_permission, get_current_user
from config import Config

lookup_ns = Namespace('lookup', description='IOC lookup operations')

# API Models
lookup_request_model = lookup_ns.model('LookupRequest', {
    'indicator': fields.String(required=True, description='IOC value to lookup (IP, domain, URL, hash)')
})

lookup_response_model = lookup_ns.model('LookupResponse', {
    'lookup_id': fields.String(description='Lookup request ID'),
    'ioc': fields.Raw(description='Enriched IOC data'),
    'status': fields.String(description='Lookup status'),
    'error': fields.String(description='Error message if failed')
})

lookup_status_model = lookup_ns.model('LookupStatus', {
    'id': fields.String(description='Lookup ID'),
    'indicator': fields.Raw(description='Indicator being looked up'),
    'status': fields.String(description='Lookup status'),
    'started_at': fields.String(description='Start timestamp'),
    'finished_at': fields.String(description='Finish timestamp'),
    'result_indicator_id': fields.String(description='Resulting IOC ID'),
    'error': fields.String(description='Error message if failed')
})


def run_async_in_thread(coro):
    """Run async function in a thread with a new event loop"""
    def thread_func():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(coro)
        finally:
            loop.close()
    
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(thread_func)
        return future.result(timeout=60)  # 60 second timeout


@lookup_ns.route('')
class IOCLookup(Resource):
    
    @lookup_ns.expect(lookup_request_model)
    @lookup_ns.marshal_with(lookup_response_model)
    @lookup_ns.doc(description='Perform IOC lookup with enrichment from external sources')
    def post(self):
        """Perform IOC lookup and enrichment"""
        try:
            data = request.get_json()
            if not data:
                lookup_ns.abort(400, 'JSON data required')
                
            indicator_value = data.get('indicator', '').strip()
            
            if not indicator_value:
                lookup_ns.abort(400, 'Indicator value is required')
            
            # Get current user (optional for public access)
            current_user = get_current_user()
            user_id = str(current_user._id) if current_user else 'anonymous'
            
            # Create lookup service
            lookup_service = LookupService()
            
            # Perform lookup using thread-based async execution
            try:
                ioc, lookup = run_async_in_thread(
                    lookup_service.perform_lookup(indicator_value, user_id)
                )
                
                if not lookup:
                    lookup_ns.abort(500, 'Lookup failed to initialize')
                
                if lookup.status == 'error':
                    return {
                        'lookup_id': str(lookup._id),
                        'status': 'error',
                        'error': lookup.error
                    }, 400
                
                response_data = {
                    'lookup_id': str(lookup._id),
                    'status': lookup.status
                }
                
                if ioc:
                    response_data['ioc'] = ioc.to_dict()
                
                return response_data, 200
                
            except Exception as e:
                current_app.logger.error(f"Lookup execution failed: {str(e)}")
                lookup_ns.abort(500, f'Lookup failed: {str(e)}')
                
        except Exception as e:
            current_app.logger.error(f"Lookup request failed: {str(e)}")
            lookup_ns.abort(500, f'Request processing failed: {str(e)}')


@lookup_ns.route('/<string:lookup_id>')
class LookupStatus(Resource):
    @lookup_ns.marshal_with(lookup_status_model)
    def get(self, lookup_id):
        """Get lookup status and result"""
        try:
            lookup = Lookup.find_by_id(lookup_id)
            if not lookup:
                lookup_ns.abort(404, 'Lookup not found')
            
            # Check if user owns this lookup or is admin (for anonymous, allow access)
            current_user = get_current_user()
            if (current_user and 
                lookup.user_id != str(current_user._id) and 
                lookup.user_id != 'anonymous' and
                not current_user.has_permission('admin')):
                lookup_ns.abort(403, 'Access denied')
            
            response = lookup.to_dict()
            
            # If lookup is done and has result, include IOC data
            if lookup.status == 'done' and lookup.result_indicator_id:
                try:
                    from iocs.models import IOC
                    ioc = IOC.find_by_id(lookup.result_indicator_id)
                    if ioc:
                        response['ioc'] = ioc.to_dict()
                except Exception as e:
                    current_app.logger.error(f"Error fetching IOC for lookup {lookup_id}: {e}")
                    # Don't fail the request, just log the error
            
            return response, 200
            
        except Exception as e:
            current_app.logger.error(f"Error getting lookup status {lookup_id}: {e}")
            lookup_ns.abort(500, f'Failed to get lookup status: {str(e)}')
