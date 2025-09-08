"""
Lookup API routes - Temporary blueprint stub
"""
from flask import Blueprint, jsonify

lookup_bp = Blueprint('lookup', __name__)

@lookup_bp.route('/', methods=['POST'])
def perform_lookup():
    """Temporary stub"""
    return jsonify({"message": "Lookup API under maintenance - please try again later"}), 503

@lookup_bp.route('/history', methods=['GET'])
def lookup_history():
    """Temporary stub"""
    return jsonify({"message": "Lookup API under maintenance - please try again later"}), 503
