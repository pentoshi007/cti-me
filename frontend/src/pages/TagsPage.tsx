import { useState, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { 
  PlusIcon, 
  TagIcon, 
  TrashIcon, 
  PencilIcon,
  XMarkIcon,
  MagnifyingGlassIcon,
  ChartBarIcon,
  HashtagIcon,
  ExclamationTriangleIcon,
  CheckCircleIcon,
  SwatchIcon,
  ClockIcon,
  ArrowTrendingUpIcon,
  InformationCircleIcon
} from '@heroicons/react/24/outline'
import { api } from '../api'
import { useAuthStore } from '../stores/authStore'
import toast from 'react-hot-toast'
import clsx from 'clsx'

const TagsPage = () => {
  const [isCreating, setIsCreating] = useState(false)
  const [editingTag, setEditingTag] = useState<any>(null)
  const [searchQuery, setSearchQuery] = useState('')
  const [showStats, setShowStats] = useState(false)
  const [newTag, setNewTag] = useState({ name: '', description: '', color: '#3b82f6' })
  const [sortBy, setSortBy] = useState('name')
  const [showPreview, setShowPreview] = useState(false)
  const queryClient = useQueryClient()
  const { hasPermission, user } = useAuthStore()

  // Predefined color palette for better UX
  const colorPalette = [
    '#ef4444', '#f97316', '#f59e0b', '#eab308',
    '#84cc16', '#22c55e', '#10b981', '#14b8a6',
    '#06b6d4', '#0ea5e9', '#3b82f6', '#6366f1',
    '#8b5cf6', '#a855f7', '#d946ef', '#ec4899',
    '#f43f5e', '#64748b', '#475569', '#374151'
  ]

  const { data: tags, isLoading, error } = useQuery({
    queryKey: ['tags', searchQuery, sortBy],
    queryFn: () => api.tags.list({ q: searchQuery, sort: sortBy }).then(res => {
      console.log('Tags API response:', res.data)
      return res.data
    }),
    retry: 3,
    retryDelay: 1000,
  })

  const { data: tagStats } = useQuery({
    queryKey: ['tags', 'stats'],
    queryFn: () => api.tags.stats().then(res => res.data),
    enabled: showStats,
  })

  const createMutation = useMutation({
    mutationFn: (tag: any) => {
      console.log('Creating tag:', tag)
      return api.tags.create(tag)
    },
    onSuccess: (response) => {
      console.log('Tag created successfully:', response)
      console.log('Invalidating queries with keys:', ['tags'])
      // Force refresh of tags query
      queryClient.invalidateQueries({ queryKey: ['tags'] })
      queryClient.refetchQueries({ queryKey: ['tags'] })
      setIsCreating(false)
      setNewTag({ name: '', description: '', color: '#3b82f6' })
      setShowPreview(false)
      toast.success('Tag created successfully')
    },
    onError: (error: any) => {
      console.error('Tag creation failed:', error)
      const message = error.response?.data?.message || error.message || 'Failed to create tag'
      toast.error(message)
      console.error('Full error details:', {
        status: error.response?.status,
        data: error.response?.data,
        headers: error.response?.headers
      })
    }
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string, data: any }) => api.tags.update?.(id, data) || Promise.reject('Update not supported'),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['tags'] })
      setEditingTag(null)
      toast.success('Tag updated successfully')
    },
    onError: (error: any) => {
      const message = error.response?.data?.message || 'Failed to update tag'
      toast.error(message)
    }
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.tags.delete(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['tags'] })
      toast.success('Tag deleted successfully')
    },
    onError: (error: any) => {
      const message = error.response?.data?.message || 'Failed to delete tag'
      toast.error(message)
    }
  })

  const handleCreateTag = (e: React.FormEvent) => {
    e.preventDefault()
    if (!newTag.name.trim()) {
      toast.error('Tag name is required')
      return
    }
    if (newTag.name.trim().length < 2) {
      toast.error('Tag name must be at least 2 characters')
      return
    }
    if (newTag.name.trim().length > 50) {
      toast.error('Tag name must be less than 50 characters')
      return
    }
    
    // Clean the tag data
    const tagData = {
      name: newTag.name.trim(),
      description: newTag.description.trim(),
      color: newTag.color
    }
    
    console.log('Submitting tag data:', tagData)
    createMutation.mutate(tagData)
  }

  const handleEditTag = (tag: any) => {
    setEditingTag(tag)
  }

  const handleDeleteTag = (id: string) => {
    if (window.confirm('Are you sure you want to delete this tag? This action cannot be undone.')) {
      deleteMutation.mutate(id)
    }
  }

  const resetForm = () => {
    setNewTag({ name: '', description: '', color: '#3b82f6' })
    setIsCreating(false)
    setEditingTag(null)
    setShowPreview(false)
  }

  // Color selection handler
  const handleColorSelect = (color: string) => {
    setNewTag(prev => ({ ...prev, color }))
  }

  // Validation helper
  const validateTagName = (name: string) => {
    if (!name.trim()) return 'Tag name is required'
    if (name.trim().length < 2) return 'Tag name must be at least 2 characters'
    if (name.trim().length > 50) return 'Tag name must be less than 50 characters'
    if (!/^[a-zA-Z0-9\s\-_]+$/.test(name)) return 'Tag name can only contain letters, numbers, spaces, hyphens, and underscores'
    return null
  }

  const filteredTags = (Array.isArray(tags) ? tags : tags?.tags || []).filter((tag: any) => 
    tag.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
    tag.description?.toLowerCase().includes(searchQuery.toLowerCase())
  )

  // Debug logging
  console.log('Tags data:', tags)
  console.log('Filtered tags:', filteredTags)
  console.log('Is loading:', isLoading)
  console.log('Error:', error)
  console.log('Array.isArray(tags):', Array.isArray(tags))
  console.log('tags?.tags:', tags?.tags)

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold text-white flex items-center gap-3">
            <div className="p-2 bg-gradient-to-br from-green-500/20 to-blue-600/20 rounded-xl border border-green-500/30">
              <TagIcon className="w-8 h-8 text-green-400" />
            </div>
            Tags Management
          </h1>
          <p className="text-white/60 mt-1">Organize and categorize your threat intelligence</p>
        </div>
        
        <div className="flex flex-col sm:flex-row items-start sm:items-center gap-3">
          {/* Search and Sort */}
          <div className="relative">
            <input
              type="text"
              placeholder="Search tags..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-10 pr-4 py-2 bg-white/10 border border-white/20 rounded-lg text-white placeholder-white/50 focus:outline-none focus:ring-2 focus:ring-green-500 w-64"
            />
            <MagnifyingGlassIcon className="w-5 h-5 text-white/50 absolute left-3 top-1/2 transform -translate-y-1/2" />
          </div>
          
          {/* Sort Dropdown */}
          <select
            value={sortBy}
            onChange={(e) => setSortBy(e.target.value)}
            className="px-3 py-2 bg-white/10 border border-white/20 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-green-500"
          >
            <option value="name">Sort by Name</option>
            <option value="created_at">Sort by Date</option>
          </select>
          
          {/* Actions */}
          <div className="flex items-center gap-2">
            <button
              onClick={() => setShowStats(!showStats)}
              className={clsx(
                'px-4 py-2 rounded-lg transition-colors flex items-center space-x-2',
                showStats 
                  ? 'bg-blue-500 hover:bg-blue-600 text-white' 
                  : 'bg-white/10 hover:bg-white/20 text-white/80'
              )}
            >
              <ChartBarIcon className="w-4 h-4" />
              <span>Stats</span>
            </button>
            
            <button
              onClick={() => setIsCreating(true)}
              className="px-4 py-2 bg-green-500 hover:bg-green-600 text-white rounded-lg transition-colors flex items-center space-x-2"
            >
              <PlusIcon className="w-4 h-4" />
              <span>New Tag</span>
            </button>
          </div>
        </div>
      </div>

      {/* Quick Stats */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="glass-bg rounded-xl p-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-green-500/20 rounded-lg">
              <HashtagIcon className="w-5 h-5 text-green-400" />
            </div>
            <div>
              <div className="text-white font-bold text-lg">{Array.isArray(tags) ? tags.length : tags?.tags?.length || 0}</div>
              <div className="text-white/60 text-sm">Total Tags</div>
            </div>
          </div>
        </div>
        
        <div className="glass-bg rounded-xl p-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-blue-500/20 rounded-lg">
              <CheckCircleIcon className="w-5 h-5 text-blue-400" />
            </div>
            <div>
              <div className="text-white font-bold text-lg">{filteredTags.length}</div>
              <div className="text-white/60 text-sm">Visible Tags</div>
            </div>
          </div>
        </div>
        
        <div className="glass-bg rounded-xl p-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-purple-500/20 rounded-lg">
              <TagIcon className="w-5 h-5 text-purple-400" />
            </div>
            <div>
              <div className="text-white font-bold text-lg">
                {Object.keys(tagStats?.tag_usage || {}).length}
              </div>
              <div className="text-white/60 text-sm">Used Tags</div>
            </div>
          </div>
        </div>
      </div>

      {isCreating && (
        <div className="glass-bg rounded-2xl p-3 sm:p-4 lg:p-6 border border-green-500/30">
          <div className="flex items-center justify-between mb-4 sm:mb-6">
            <h2 className="text-lg sm:text-xl font-semibold text-white flex items-center gap-2">
              <PlusIcon className="w-5 h-5 text-green-400" />
              Create New Tag
            </h2>
            <button
              onClick={resetForm}
              className="p-2 text-white/50 hover:text-white transition-colors rounded-lg hover:bg-white/10"
            >
              <XMarkIcon className="w-5 h-5" />
            </button>
          </div>
          
          <form onSubmit={handleCreateTag} className="space-y-6">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div className="space-y-4">
                <div>
                  <label className="block text-white font-medium mb-2">Tag Name *</label>
                  <input
                    type="text"
                    value={newTag.name}
                    onChange={(e) => {
                      const value = e.target.value
                      setNewTag(prev => ({ ...prev, name: value }))
                    }}
                    className={clsx(
                      'w-full px-4 py-3 bg-white/10 border rounded-xl text-white placeholder-white/50 focus:outline-none focus:ring-2 focus:border-transparent transition-colors',
                      validateTagName(newTag.name) 
                        ? 'border-red-500/50 focus:ring-red-500' 
                        : 'border-white/20 focus:ring-green-500'
                    )}
                    placeholder="Enter tag name (e.g., malware, phishing)"
                    required
                  />
                  {newTag.name && validateTagName(newTag.name) && (
                    <p className="text-red-400 text-sm mt-1 flex items-center gap-1">
                      <ExclamationTriangleIcon className="w-4 h-4" />
                      {validateTagName(newTag.name)}
                    </p>
                  )}
                  <p className="text-white/60 text-xs mt-1">
                    Use descriptive names like "malware", "phishing", "apt-group"
                  </p>
                </div>
                
                <div>
                  <label className="block text-white font-medium mb-2">Description</label>
                  <textarea
                    value={newTag.description}
                    onChange={(e) => setNewTag(prev => ({ ...prev, description: e.target.value }))}
                    className="w-full px-4 py-3 bg-white/10 border border-white/20 rounded-xl text-white placeholder-white/50 focus:outline-none focus:ring-2 focus:ring-green-500 focus:border-transparent resize-none"
                    placeholder="Enter tag description (optional)"
                    rows={3}
                  />
                </div>
              </div>
              
              <div className="space-y-4">
                <div>
                  <label className="block text-white font-medium mb-2">Color</label>
                  <div className="space-y-3">
                    <div className="flex items-center gap-4">
                      <input
                        type="color"
                        value={newTag.color}
                        onChange={(e) => setNewTag(prev => ({ ...prev, color: e.target.value }))}
                        className="w-16 h-12 bg-white/10 border border-white/20 rounded-lg cursor-pointer"
                      />
                      <div className="flex-1">
                        <input
                          type="text"
                          value={newTag.color}
                          onChange={(e) => setNewTag(prev => ({ ...prev, color: e.target.value }))}
                          className="w-full px-3 py-2 bg-white/10 border border-white/20 rounded-lg text-white placeholder-white/50 focus:outline-none focus:ring-2 focus:ring-green-500"
                          placeholder="#3b82f6"
                        />
                      </div>
                    </div>
                    
                    {/* Color Palette */}
                    <div>
                      <p className="text-white/70 text-sm mb-2">Quick Colors:</p>
                      <div className="grid grid-cols-10 gap-2">
                        {colorPalette.map((color) => (
                          <button
                            key={color}
                            type="button"
                            onClick={() => handleColorSelect(color)}
                            className={clsx(
                              'w-6 h-6 rounded-full border-2 transition-all hover:scale-110',
                              newTag.color === color 
                                ? 'border-white shadow-lg scale-110' 
                                : 'border-white/30 hover:border-white/60'
                            )}
                            style={{ backgroundColor: color }}
                            title={color}
                          />
                        ))}
                      </div>
                    </div>
                  </div>
                </div>
                
                <div className="bg-white/5 rounded-lg p-4 border border-white/10">
                  <h4 className="text-white font-medium mb-2">Preview</h4>
                  <div className="flex items-center gap-2">
                    <div
                      className="w-4 h-4 rounded-full"
                      style={{ backgroundColor: newTag.color }}
                    ></div>
                    <span className="text-white/80 font-medium">#{newTag.name || 'tag-name'}</span>
                  </div>
                  {newTag.description && (
                    <p className="text-white/60 text-sm mt-2">{newTag.description}</p>
                  )}
                </div>
              </div>
            </div>
            
            <div className="flex items-center justify-end space-x-3 pt-4 border-t border-white/10">
              <button
                type="button"
                onClick={resetForm}
                className="px-6 py-2 bg-white/10 hover:bg-white/20 text-white rounded-xl transition-colors"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={createMutation.isPending || !newTag.name.trim()}
                className="px-6 py-2 bg-green-500 hover:bg-green-600 disabled:opacity-50 disabled:cursor-not-allowed text-white rounded-xl transition-colors flex items-center space-x-2"
              >
                {createMutation.isPending ? (
                  <>
                    <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                    <span>Creating...</span>
                  </>
                ) : (
                  <>
                    <PlusIcon className="w-4 h-4" />
                    <span>Create Tag</span>
                  </>
                )}
              </button>
            </div>
          </form>
        </div>
      )}

      <div className="glass-bg rounded-2xl overflow-hidden">
        <div className="p-3 sm:p-4 lg:p-6 border-b border-white/10">
          <div className="flex items-center justify-between">
            <h2 className="text-lg sm:text-xl font-semibold text-white flex items-center gap-2">
              <TagIcon className="w-5 h-5 text-green-400" />
              All Tags ({filteredTags.length})
            </h2>
            {searchQuery && (
              <div className="text-white/60 text-sm">
                Showing {filteredTags.length} of {Array.isArray(tags) ? tags.length : tags?.tags?.length || 0} tags
              </div>
            )}
          </div>
        </div>
        
        <div className="p-3 sm:p-4 lg:p-6">
          {isLoading ? (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {[...Array(6)].map((_, i) => (
                <div key={i} className="p-4 bg-white/5 rounded-xl animate-pulse border border-white/10">
                  <div className="flex items-center justify-between mb-3">
                    <div className="flex items-center space-x-2">
                      <div className="w-4 h-4 bg-white/20 rounded-full"></div>
                      <div className="h-4 bg-white/20 rounded w-20"></div>
                    </div>
                    <div className="w-8 h-8 bg-white/20 rounded"></div>
                  </div>
                  <div className="h-3 bg-white/20 rounded w-2/3"></div>
                </div>
              ))}
            </div>
          ) : filteredTags.length === 0 ? (
            <div className="text-center py-12">
              <div className="w-16 h-16 bg-white/10 rounded-full flex items-center justify-center mx-auto mb-4">
                <ExclamationTriangleIcon className="w-8 h-8 text-white/40" />
              </div>
              <h3 className="text-white font-medium mb-2">
                {searchQuery ? 'No tags found' : 'No tags created yet'}
              </h3>
              <p className="text-white/60 text-sm mb-4">
                {searchQuery 
                  ? `No tags match "${searchQuery}". Try adjusting your search.`
                  : 'Create your first tag to start organizing your IOCs.'
                }
              </p>
              {!searchQuery && (
                <button
                  onClick={() => setIsCreating(true)}
                  className="px-4 py-2 bg-green-500 hover:bg-green-600 text-white rounded-lg transition-colors inline-flex items-center space-x-2"
                >
                  <PlusIcon className="w-4 h-4" />
                  <span>Create First Tag</span>
                </button>
              )}
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {filteredTags.map((tag: any) => (
                <div key={tag.id} className="group p-4 bg-white/5 rounded-xl border border-white/10 hover:bg-white/10 hover:border-white/20 transition-all duration-200">
                  <div className="flex items-center justify-between mb-3">
                    <div className="flex items-center space-x-2 flex-1 min-w-0">
                      <div
                        className="w-4 h-4 rounded-full flex-shrink-0"
                        style={{ backgroundColor: tag.color }}
                      ></div>
                      <span className="text-white font-medium truncate">#{tag.name}</span>
                    </div>
                    
                    <div className="flex items-center space-x-1 opacity-0 group-hover:opacity-100 transition-opacity">
                      <button
                        onClick={() => handleEditTag(tag)}
                        className="p-1.5 text-blue-400 hover:text-blue-300 hover:bg-blue-500/20 rounded-lg transition-colors"
                        title="Edit tag"
                      >
                        <PencilIcon className="w-4 h-4" />
                      </button>
                      
                      {hasPermission('admin') && (
                        <button
                          onClick={() => handleDeleteTag(tag.id)}
                          className="p-1.5 text-red-400 hover:text-red-300 hover:bg-red-500/20 rounded-lg transition-colors"
                          title="Delete tag"
                        >
                          <TrashIcon className="w-4 h-4" />
                        </button>
                      )}
                    </div>
                  </div>
                  
                  {tag.description && (
                    <p className="text-white/60 text-sm mb-3 line-clamp-2">{tag.description}</p>
                  )}
                  
                  <div className="flex items-center justify-between text-xs text-white/50">
                    <span>Usage: {tagStats?.tag_usage?.[tag.name] || 0} IOCs</span>
                    <span>Created: {new Date(tag.created_at).toLocaleDateString()}</span>
                  </div>
                  
                  {/* Usage bar */}
                  <div className="mt-3 bg-white/10 rounded-full h-1.5">
                    <div 
                      className="h-1.5 rounded-full transition-all"
                      style={{ 
                        backgroundColor: tag.color,
                        width: (() => {
                          const usage = tagStats?.tag_usage || {}
                          const maxUsage = Math.max(1, ...Object.values(usage).filter(v => typeof v === 'number'))
                          const currentUsage = usage[tag.name] || 0
                          return `${Math.min(100, (currentUsage / maxUsage) * 100)}%`
                        })(),
                        opacity: 0.7
                      }}
                    ></div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

export default TagsPage
