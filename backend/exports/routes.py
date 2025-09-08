"""
Exports API routes - Temporary blueprint stub
"""
from flask import Blueprint, jsonify

exports_bp = Blueprint('exports', __name__)

@exports_bp.route('/', methods=['GET'])
def list_exports():
    """Temporary stub"""
    return jsonify({"message": "Exports API under maintenance - please try again later"}), 503

@exports_bp.route('/', methods=['POST'])
def create_export():
    """Temporary stub"""
    return jsonify({"message": "Exports API under maintenance - please try again later"}), 503
