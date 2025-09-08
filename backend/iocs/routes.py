"""
IOC API routes - Temporary blueprint stub
"""
from flask import Blueprint, jsonify

iocs_bp = Blueprint('iocs', __name__)

@iocs_bp.route('/', methods=['GET'])
def list_iocs():
    """Temporary stub - IOCs functionality coming soon"""
    return jsonify({"message": "IOCs API under maintenance - please try again later"}), 503

@iocs_bp.route('/<ioc_id>', methods=['GET'])
def get_ioc(ioc_id):
    """Temporary stub"""
    return jsonify({"message": "IOCs API under maintenance - please try again later"}), 503

@iocs_bp.route('/', methods=['POST'])
def create_ioc():
    """Temporary stub"""
    return jsonify({"message": "IOCs API under maintenance - please try again later"}), 503
