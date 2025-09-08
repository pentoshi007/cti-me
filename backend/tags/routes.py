"""
Tags API routes
"""
from flask import request
from flask_restx import Resource, Namespace, fields
from flask_jwt_extended import jwt_required

from tags.models import Tag
from utils.decorators import require_permission, get_current_user

tags_ns = Namespace('tags', description='Tag management operations')

# API Models
tag_model = tags_ns.model('Tag', {
    'id': fields.String(description='Tag ID'),
    'name': fields.String(description='Tag name'),
    'color': fields.String(description='Tag color (hex code)'),
    'description': fields.String(description='Tag description'),
    'created_by': fields.String(description='Creator user ID'),
    'created_at': fields.String(description='Creation timestamp')
})

tag_create_model = tags_ns.model('TagCreate', {
    'name': fields.String(required=True, description='Tag name'),
    'color': fields.String(description='Tag color (hex code)'),
    'description': fields.String(description='Tag description')
})

tag_stats_model = tags_ns.model('TagStats', {
    'tag_usage': fields.Raw(description='Tag usage statistics')
})


@tags_ns.route('')
class TagList(Resource):
    @tags_ns.marshal_list_with(tag_model)
    @tags_ns.doc(params={
        'q': 'Search query for tag name or description',
        'sort': 'Sort field (name, created_at)'
    })
    def get(self):
        """Get list of all tags"""
        query = request.args.get('q', '').strip()
        sort_by = request.args.get('sort', 'name')
        
        if sort_by not in ['name', 'created_at']:
            sort_by = 'name'
        
        if query:
            tags = Tag.search(query)
        else:
            tags = Tag.list_all(sort_by)
        
        return [tag.to_dict() for tag in tags]
    
    @jwt_required()
    @require_permission('tag')
    @tags_ns.expect(tag_create_model)
    @tags_ns.marshal_with(tag_model)
    def post(self):
        """Create a new tag"""
        data = request.get_json()
        name = data.get('name', '').strip()
        color = data.get('color', '').strip()
        description = data.get('description', '').strip()
        
        if not name:
            tags_ns.abort(400, 'Tag name is required')
        
        # Check if tag already exists
        existing_tag = Tag.find_by_name(name)
        if existing_tag:
            tags_ns.abort(409, 'Tag already exists')
        
        # Validate color format (basic hex validation)
        if color and not color.startswith('#'):
            color = f"#{color}"
        
        # Get current user
        current_user = get_current_user()
        
        # Create tag
        tag = Tag(
            name=name,
            color=color or '#6B7280',
            description=description,
            created_by=str(current_user._id) if current_user else None
        )
        tag.save()
        
        return tag.to_dict()


@tags_ns.route('/<string:tag_id>')
class TagDetail(Resource):
    @jwt_required()
    @require_permission('read')
    @tags_ns.marshal_with(tag_model)
    def get(self, tag_id):
        """Get tag by ID"""
        tag = Tag.find_by_id(tag_id)
        if not tag:
            tags_ns.abort(404, 'Tag not found')
        
        return tag.to_dict()
    
    @jwt_required()
    @require_permission('admin')
    @tags_ns.expect(tag_create_model)
    @tags_ns.marshal_with(tag_model)
    def patch(self, tag_id):
        """Update tag"""
        tag = Tag.find_by_id(tag_id)
        if not tag:
            tags_ns.abort(404, 'Tag not found')
        
        data = request.get_json()
        
        # Update fields if provided
        if 'name' in data:
            name = data['name'].strip()
            if name and name != tag.name:
                # Check if new name already exists
                existing_tag = Tag.find_by_name(name)
                if existing_tag and str(existing_tag._id) != tag_id:
                    tags_ns.abort(409, 'Tag name already exists')
                tag.name = name
        
        if 'color' in data:
            color = data['color'].strip()
            if color and not color.startswith('#'):
                color = f"#{color}"
            tag.color = color
        
        if 'description' in data:
            tag.description = data['description'].strip()
        
        tag.save()
        return tag.to_dict()
    
    @jwt_required()
    @require_permission('admin')
    def delete(self, tag_id):
        """Delete tag"""
        tag = Tag.find_by_id(tag_id)
        if not tag:
            tags_ns.abort(404, 'Tag not found')
        
        # Remove tag from all IOCs first
        from database import MongoDB
        indicators = MongoDB.get_collection('indicators')
        indicators.update_many(
            {'tags': tag.name},
            {'$pull': {'tags': tag.name}}
        )
        
        # Delete the tag
        if tag.delete():
            return {'message': f'Tag "{tag.name}" deleted successfully'}
        else:
            tags_ns.abort(500, 'Failed to delete tag')


@tags_ns.route('/stats')
class TagStats(Resource):
    @tags_ns.marshal_with(tag_stats_model)
    def get(self):
        """Get tag usage statistics"""
        stats = Tag.get_tag_usage_stats()
        return {'tag_usage': stats}
