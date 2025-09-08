"""
Tags API routes - Temporary blueprint stub
"""
from flask import Blueprint, jsonify

tags_bp = Blueprint('tags', __name__)

@tags_bp.route('/', methods=['GET'])
def list_tags():
    """Temporary stub"""
    return jsonify({"message": "Tags API under maintenance - please try again later"}), 503

@tags_bp.route('/', methods=['POST'])
def create_tag():
    """Temporary stub"""
    return jsonify({"message": "Tags API under maintenance - please try again later"}), 503
