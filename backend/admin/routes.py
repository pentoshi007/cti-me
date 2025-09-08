"""
Admin API routes - Temporary blueprint stub
"""
from flask import Blueprint, jsonify

admin_bp = Blueprint('admin', __name__)

@admin_bp.route('/system/stats', methods=['GET'])
def get_system_stats():
    """Temporary stub"""
    return jsonify({"message": "Admin API under maintenance - please try again later"}), 503

@admin_bp.route('/ingest/run', methods=['POST'])
def trigger_ingest():
    """Temporary stub"""
    return jsonify({"message": "Admin API under maintenance - please try again later"}), 503
