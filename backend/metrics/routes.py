"""
Metrics API routes - Temporary blueprint stub
"""
from flask import Blueprint, jsonify

metrics_bp = Blueprint('metrics', __name__)

@metrics_bp.route('/overview', methods=['GET'])
def get_overview():
    """Temporary stub"""
    return jsonify({"message": "Metrics API under maintenance - please try again later"}), 503

@metrics_bp.route('/timeseries', methods=['GET'])
def get_timeseries():
    """Temporary stub"""
    return jsonify({"message": "Metrics API under maintenance - please try again later"}), 503
