import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Link, useSearchParams } from 'react-router-dom'
import { useState, useEffect } from 'react'
import {
  MagnifyingGlassIcon,
  ArrowDownTrayIcon,
  TagIcon,
  EyeIcon,
  XMarkIcon,
  PlusIcon,
  DocumentArrowDownIcon,
  TrophyIcon,
  ShieldCheckIcon,
  FireIcon,
  ChartBarIcon,
  GlobeAltIcon,
  LinkIcon,
  DocumentTextIcon,
  ExclamationTriangleIcon,
} from '@heroicons/react/24/outline'
import { api } from '../lib/api.ts'
import { useAuthStore } from '../stores/authStore'
import PermissionCheck from '../components/PermissionCheck'
import toast from 'react-hot-toast'
import clsx from 'clsx'

const IOCsPage = () => {
  const queryClient = useQueryClient()
  const { user } = useAuthStore()
  const [searchParams] = useSearchParams()
  
  const [filters, setFilters] = useState({
    q: '',
    type: '',
    severity: '',
    tags: '',
    threat_category: '',
    malware_family: '',
    score_min: '',
    score_max: '',
    vt_positives_min: '',
    has_vt_data: '',
    has_abuseipdb_data: '',
    from: '',
    to: '',
  })

  // Handle URL parameters from dashboard navigation
  useEffect(() => {
    const urlFilters = {
      q: searchParams.get('q') || '',
      type: searchParams.get('type') || '',
      severity: searchParams.get('severity') || '', 
      tags: searchParams.get('tags') || '',
      threat_category: searchParams.get('threat_category') || '',
      malware_family: searchParams.get('malware_family') || '',
      score_min: searchParams.get('score_min') || '',
      score_max: searchParams.get('score_max') || '',
      vt_positives_min: searchParams.get('vt_positives_min') || '',
      has_vt_data: searchParams.get('has_vt_data') || '',
      has_abuseipdb_data: searchParams.get('has_abuseipdb_data') || '',
      from: searchParams.get('from') || '',
      to: searchParams.get('to') || '',
    }
    
    // Only update if there are actual URL params
    if (Object.values(urlFilters).some(v => v !== '')) {
      setFilters(urlFilters)
      // Show a toast to indicate filters were applied
      const activeFilters = Object.entries(urlFilters).filter(([_, v]) => v !== '')
      if (activeFilters.length > 0) {
        toast.success(`Applied ${activeFilters.length} CTI filter(s) from dashboard`)
      }
    }
  }, [searchParams])
  const [pagination, setPagination] = useState({
    page: 1,
    per_page: 25,
  })
  const [selectedIOCs, setSelectedIOCs] = useState<string[]>([])
  const [showTagModal, setShowTagModal] = useState(false)
  const [showExportModal, setShowExportModal] = useState(false)
  const [newTag, setNewTag] = useState('')
  const [exportFormat, setExportFormat] = useState('csv')
  const [viewMode, setViewMode] = useState<'table' | 'cards'>('cards')

  // Fetch IOCs
  const { data: iocsData, isLoading } = useQuery({
    queryKey: ['iocs', filters, pagination],
    queryFn: () => api.iocs.list({ ...filters, ...pagination }).then(res => res.data),
  })

  // Fetch available tags
  const { data: tagsData } = useQuery({
    queryKey: ['tags'],
    queryFn: () => api.tags.list().then(res => res.data),
  })

  // Tag IOCs mutation with improved error handling
  const tagIOCsMutation = useMutation({
    mutationFn: (data: { ioc_ids: string[], tags: string[] }) => 
      api.iocs.bulkTag(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['iocs'] })
      setSelectedIOCs([])
      setShowTagModal(false)
      setNewTag('')
      toast.success(`Successfully tagged ${selectedIOCs.length} IOCs with "${newTag}"`)
    },
    onError: (error: any) => {
      const message = error.response?.data?.message || 'Failed to tag IOCs'
      toast.error(message)
      console.error('Tag operation failed:', error)
    }
  })

  // Export mutation  
  const exportMutation = useMutation({
    mutationFn: async (data: any) => {
      const response = await fetch('/api/exports', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${useAuthStore.getState().accessToken}`
        },
        body: JSON.stringify(data)
      })
      
      if (!response.ok) {
        throw new Error(`Export failed: ${response.statusText}`)
      }
      
      // Get filename from Content-Disposition header
      const contentDisposition = response.headers.get('content-disposition')
      const filename = contentDisposition
        ? contentDisposition.split('filename=')[1]?.replace(/"/g, '')
        : `iocs_export_${new Date().toISOString().slice(0, 10)}.${data.format}`
      
      // Create blob and download
      const blob = await response.blob()
      const url = window.URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = filename
      document.body.appendChild(a)
      a.click()
      window.URL.revokeObjectURL(url)
      document.body.removeChild(a)
      
      return { success: true }
    },
    onSuccess: () => {
      setShowExportModal(false)
      toast.success('Export downloaded successfully!')
    },
    onError: (error: any) => {
      toast.error(error.message || 'Failed to export data')
    }
  })

  const severityColors = {
    critical: 'text-red-400 bg-red-500/10 border-red-500/20',
    high: 'text-orange-400 bg-orange-500/10 border-orange-500/20',
    medium: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/20',
    low: 'text-green-400 bg-green-500/10 border-green-500/20',
    info: 'text-blue-400 bg-blue-500/10 border-blue-500/20',
  }

  const typeIcons = {
    ip: GlobeAltIcon,
    domain: LinkIcon,
    url: DocumentTextIcon,
    sha256: ShieldCheckIcon,
    md5: ShieldCheckIcon,
    sha1: ShieldCheckIcon,
  }

  const handleFilterChange = (key: string, value: string) => {
    setFilters(prev => ({ ...prev, [key]: value }))
    setPagination(prev => ({ ...prev, page: 1 }))
  }

  const handleSelectIOC = (iocId: string) => {
    setSelectedIOCs(prev =>
      prev.includes(iocId)
        ? prev.filter(id => id !== iocId)
        : [...prev, iocId]
    )
  }

  const handleSelectAll = () => {
    if (selectedIOCs.length === iocsData?.iocs?.length) {
      setSelectedIOCs([])
    } else {
      setSelectedIOCs(iocsData?.iocs?.map((ioc: any) => ioc.id) || [])
    }
  }

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    })
  }

  const handleTagIOCs = () => {
    if (selectedIOCs.length === 0) {
      toast.error('Please select IOCs to tag')
      return
    }
    setShowTagModal(true)
  }

  const handleExport = () => {
    setShowExportModal(true)
  }

  const submitTagging = () => {
    if (!newTag.trim()) {
      toast.error('Please enter a tag name')
      return
    }
    
    tagIOCsMutation.mutate({
      ioc_ids: selectedIOCs,
      tags: [newTag.trim()]
    })
  }

  const submitExport = () => {
    const exportData = {
      format: exportFormat,
      filters: {
        q: filters.q || '',
        type: filters.type || '',
        severity: filters.severity || '',
        tags: filters.tags || '',
        from: filters.from || '',
        to: filters.to || '',
        // If specific IOCs are selected, we could add them as a filter
        // but the current backend doesn't support ioc_ids filter
      }
    }
    exportMutation.mutate(exportData)
  }

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 sm:gap-4">
        <div className="min-w-0 flex-1">
          <h1 className="text-2xl sm:text-3xl font-bold text-white truncate">Indicators of Compromise</h1>
          <p className="text-white/60 mt-1 text-sm sm:text-base">Browse and analyze threat indicators</p>
        </div>
        <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2 sm:gap-3">
          {/* View Toggle */}
          <div className="flex items-center bg-white/10 rounded-xl p-1 self-start">
            <button
              onClick={() => setViewMode('cards')}
              className={clsx(
                'px-2 sm:px-3 py-2 rounded-lg text-sm font-medium transition-colors flex items-center justify-center',
                viewMode === 'cards' 
                  ? 'bg-blue-500 text-white' 
                  : 'text-white/70 hover:text-white hover:bg-white/5'
              )}
            >
              <ChartBarIcon className="w-4 h-4" />
            </button>
            <button
              onClick={() => setViewMode('table')}
              className={clsx(
                'px-2 sm:px-3 py-2 rounded-lg text-sm font-medium transition-colors flex items-center justify-center',
                viewMode === 'table' 
                  ? 'bg-blue-500 text-white' 
                  : 'text-white/70 hover:text-white hover:bg-white/5'
              )}
            >
              ☰
            </button>
          </div>
          <PermissionCheck 
            requireAuth={true}
            fallback={
              <div className="text-white/60 text-sm">
                <Link to="/login" className="text-blue-400 hover:text-blue-300">Login</Link> to access export and tagging features
              </div>
            }
          >
            <div className="flex items-center gap-3">
              <PermissionCheck permission="export">
                <button 
                  onClick={handleExport}
                  className="px-4 py-2 bg-blue-500 hover:bg-blue-600 text-white rounded-xl transition-colors flex items-center space-x-2"
                >
                  <ArrowDownTrayIcon className="w-4 h-4" />
                  <span>Export</span>
                </button>
              </PermissionCheck>
              
              <Link
                to="/tags"
                className="px-4 py-2 bg-green-500 hover:bg-green-600 text-white rounded-xl transition-colors flex items-center space-x-2"
              >
                <TagIcon className="w-4 h-4" />
                <span>Manage Tags</span>
              </Link>
            </div>
          </PermissionCheck>
        </div>
      </div>

          {/* Quick CTI Filters */}
          <div className="glass-bg rounded-2xl p-4">
            <div className="flex items-center space-x-2 mb-3">
              <FireIcon className="w-5 h-5 text-orange-400" />
              <h3 className="text-white font-medium">Quick Threat Categories</h3>
            </div>
            <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-8 gap-2">
              {[
                { label: 'Malware', value: 'threat:malware', color: 'bg-red-500/20 text-red-400 border-red-500/30' },
                { label: 'Botnet', value: 'threat:botnet', color: 'bg-purple-500/20 text-purple-400 border-purple-500/30' },
                { label: 'Phishing', value: 'threat:phishing', color: 'bg-orange-500/20 text-orange-400 border-orange-500/30' },
                { label: 'C&C', value: 'threat:c2', color: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30' },
                { label: 'Exploit', value: 'threat:exploit', color: 'bg-blue-500/20 text-blue-400 border-blue-500/30' },
                { label: 'Ransomware', value: 'threat:ransomware', color: 'bg-pink-500/20 text-pink-400 border-pink-500/30' },
                { label: 'High Score (70+)', value: 'score_min:70', color: 'bg-red-500/20 text-red-400 border-red-500/30' },
                { label: 'VT Positive (5+)', value: 'vt_positives_min:5', color: 'bg-orange-500/20 text-orange-400 border-orange-500/30' },
              ].map((category) => (
                <button
                  key={category.value}
                  onClick={() => {
                    if (category.value.startsWith('score_min:')) {
                      handleFilterChange('score_min', category.value.split(':')[1])
                    } else if (category.value.startsWith('vt_positives_min:')) {
                      handleFilterChange('vt_positives_min', category.value.split(':')[1])
                    } else {
                      handleFilterChange('tags', category.value)
                    }
                  }}
                  className={clsx(
                    'px-2 sm:px-3 py-1.5 rounded-lg text-xs sm:text-sm font-medium transition-colors border hover:opacity-80',
                    category.color
                  )}
                >
                  {category.label}
                </button>
              ))}
            </div>
          </div>
      <div className="glass-bg rounded-2xl p-3 sm:p-4 lg:p-6">
        <div className="space-y-3 sm:space-y-4">
          {/* Primary Filters Row */}
          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3 sm:gap-4">
            {/* Search */}
            <div className="sm:col-span-2 md:col-span-2">
              <div className="relative">
                <MagnifyingGlassIcon className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 sm:w-5 sm:h-5 text-white/50" />
                <input
                  type="text"
                  placeholder="Search IOCs..."
                  value={filters.q}
                  onChange={(e) => handleFilterChange('q', e.target.value)}
                  className="w-full pl-8 sm:pl-10 pr-3 sm:pr-4 py-2 bg-white/10 border border-white/20 rounded-xl text-white placeholder-white/50 focus:outline-none focus:ring-2 focus:ring-blue-500 text-sm"
                />
              </div>
            </div>

            {/* Type Filter */}
            <select
              value={filters.type}
              onChange={(e) => handleFilterChange('type', e.target.value)}
              className="w-full px-2 sm:px-3 py-2 bg-white/10 border border-white/20 rounded-xl text-white focus:outline-none focus:ring-2 focus:ring-blue-500 text-sm"
            >
              <option value="">All Types</option>
              <option value="ip">IP Address</option>
              <option value="domain">Domain</option>
              <option value="url">URL</option>
              <option value="sha256">SHA256</option>
              <option value="md5">MD5</option>
              <option value="sha1">SHA1</option>
            </select>

            {/* Severity Filter */}
            <select
              value={filters.severity}
              onChange={(e) => handleFilterChange('severity', e.target.value)}
              className="w-full px-2 sm:px-3 py-2 bg-white/10 border border-white/20 rounded-xl text-white focus:outline-none focus:ring-2 focus:ring-blue-500 text-sm"
            >
              <option value="">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
              <option value="info">Info</option>
            </select>

            {/* Tags Filter */}
            <input
              type="text"
              placeholder="Tags"
              value={filters.tags}
              onChange={(e) => handleFilterChange('tags', e.target.value)}
              className="w-full px-2 sm:px-3 py-2 bg-white/10 border border-white/20 rounded-xl text-white placeholder-white/50 focus:outline-none focus:ring-2 focus:ring-blue-500 text-sm"
            />

            {/* Date Range */}
            <input
              type="date"
              value={filters.from}
              onChange={(e) => handleFilterChange('from', e.target.value)}
              className="w-full px-2 sm:px-3 py-2 bg-white/10 border border-white/20 rounded-xl text-white focus:outline-none focus:ring-2 focus:ring-blue-500 text-sm"
            />
          </div>

          {/* Advanced CTI Filters Row */}
          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3 sm:gap-4 border-t border-white/10 pt-3 sm:pt-4">
            <div className="col-span-full mb-2">
              <h4 className="text-white/80 text-sm font-medium flex items-center space-x-2">
                <FireIcon className="w-4 h-4 text-orange-400" />
                <span>Threat Intelligence Filters</span>
              </h4>
            </div>
            
            {/* Threat Category */}
            <select
              value={filters.threat_category}
              onChange={(e) => handleFilterChange('threat_category', e.target.value)}
              className="w-full px-2 sm:px-3 py-2 bg-white/10 border border-white/20 rounded-xl text-white text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              <option value="">All Categories</option>
              <option value="malware">Malware</option>
              <option value="phishing">Phishing</option>
              <option value="botnet">Botnet</option>
              <option value="c2">C&C Infrastructure</option>
              <option value="exploit">Exploit Kit</option>
              <option value="ransomware">Ransomware</option>
              <option value="trojan">Trojan</option>
              <option value="backdoor">Backdoor</option>
            </select>

            {/* Malware Family */}
            <select
              value={filters.malware_family}
              onChange={(e) => handleFilterChange('malware_family', e.target.value)}
              className="w-full px-2 sm:px-3 py-2 bg-white/10 border border-white/20 rounded-xl text-white text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              <option value="">All Families</option>
              <option value="mozi">Mozi</option>
              <option value="mirai">Mirai</option>
              <option value="emotet">Emotet</option>
              <option value="trickbot">TrickBot</option>
              <option value="qakbot">QakBot</option>
              <option value="zeus">Zeus</option>
              <option value="dridex">Dridex</option>
              <option value="ryuk">Ryuk</option>
              <option value="conti">Conti</option>
            </select>

            {/* Threat Score Range */}
            <div className="flex space-x-1 sm:space-x-2">
              <input
                type="number"
                placeholder="Min"
                value={filters.score_min}
                onChange={(e) => handleFilterChange('score_min', e.target.value)}
                min="0"
                max="100"
                className="flex-1 px-2 sm:px-3 py-2 bg-white/10 border border-white/20 rounded-xl text-white placeholder-white/50 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
              <input
                type="number"
                placeholder="Max"
                value={filters.score_max}
                onChange={(e) => handleFilterChange('score_max', e.target.value)}
                min="0"
                max="100"
                className="flex-1 px-2 sm:px-3 py-2 bg-white/10 border border-white/20 rounded-xl text-white placeholder-white/50 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
            </div>

            {/* VirusTotal Detections */}
            <input
              type="number"
              placeholder="Min VT+"
              value={filters.vt_positives_min}
              onChange={(e) => handleFilterChange('vt_positives_min', e.target.value)}
              min="0"
              className="w-full px-2 sm:px-3 py-2 bg-white/10 border border-white/20 rounded-xl text-white placeholder-white/50 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
            />

            {/* Intelligence Sources */}
            <select
              value={filters.has_vt_data}
              onChange={(e) => handleFilterChange('has_vt_data', e.target.value)}
              className="w-full px-2 sm:px-3 py-2 bg-white/10 border border-white/20 rounded-xl text-white text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              <option value="">VT Data</option>
              <option value="true">Has VT Data</option>
              <option value="false">No VT Data</option>
            </select>

            {/* AbuseIPDB Filter */}
            <select
              value={filters.has_abuseipdb_data}
              onChange={(e) => handleFilterChange('has_abuseipdb_data', e.target.value)}
              className="w-full px-2 sm:px-3 py-2 bg-white/10 border border-white/20 rounded-xl text-white text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              <option value="">AbuseIPDB</option>
              <option value="true">Has AbuseIPDB</option>
              <option value="false">No AbuseIPDB</option>
            </select>
          </div>

          {/* Active Filters Display */}
          {Object.entries(filters).some(([key, value]) => value !== '' && key !== 'q') && (
            <div className="border-t border-white/10 pt-4">
              <div className="flex items-center space-x-2 mb-2">
                <span className="text-white/60 text-sm font-medium">Active Filters:</span>
                <button
                  onClick={() => setFilters({
                    q: filters.q, // Keep search query
                    type: '',
                    severity: '',
                    tags: '',
                    threat_category: '',
                    malware_family: '',
                    score_min: '',
                    score_max: '',
                    vt_positives_min: '',
                    has_vt_data: '',
                    has_abuseipdb_data: '',
                    from: '',
                    to: '',
                  })}
                  className="text-blue-400 hover:text-blue-300 text-sm underline"
                >
                  Clear All
                </button>
              </div>
              <div className="flex flex-wrap gap-2">
                {Object.entries(filters).map(([key, value]) => {
                  if (value === '' || key === 'q') return null
                  
                  const labels: Record<string, string> = {
                    type: 'Type',
                    severity: 'Severity', 
                    tags: 'Tags',
                    threat_category: 'Category',
                    malware_family: 'Family',
                    score_min: 'Min Score',
                    score_max: 'Max Score',
                    vt_positives_min: 'Min VT+',
                    has_vt_data: 'VT Data',
                    has_abuseipdb_data: 'AbuseIPDB',
                    from: 'From',
                    to: 'To'
                  }
                  
                  return (
                    <span
                      key={key}
                      className="inline-flex items-center space-x-1 px-2 py-1 bg-blue-500/20 text-blue-400 rounded-lg text-xs border border-blue-500/30"
                    >
                      <span>{labels[key] || key}: {value}</span>
                      <button
                        onClick={() => handleFilterChange(key, '')}
                        className="hover:bg-blue-500/30 rounded-full p-0.5"
                      >
                        <XMarkIcon className="w-3 h-3" />
                      </button>
                    </span>
                  )
                })}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Results */}
      <div className="glass-bg rounded-2xl overflow-hidden">
        {/* Table Header */}
        <div className="p-6 border-b border-white/10">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-4">
              {user && (
                <input
                  type="checkbox"
                  checked={selectedIOCs.length === iocsData?.iocs?.length && iocsData?.iocs?.length > 0}
                  onChange={handleSelectAll}
                  className="w-4 h-4 rounded border-white/20 bg-white/10 text-blue-500 focus:ring-blue-500 focus:ring-offset-0"
                />
              )}
              <span className="text-white/70 text-sm">
                {user && selectedIOCs.length > 0 && `${selectedIOCs.length} selected`}
                {iocsData?.total && ` ${iocsData.total} total IOCs`}
              </span>
            </div>
            {user && selectedIOCs.length > 0 && (
              <div className="flex items-center space-x-2">
                <button 
                  onClick={handleTagIOCs}
                  className="px-3 py-1 bg-blue-500 hover:bg-blue-600 text-white rounded-lg text-sm transition-colors flex items-center space-x-1"
                >
                  <TagIcon className="w-4 h-4" />
                  <span>Tag Selected</span>
                </button>
                <PermissionCheck permission="export">
                  <button 
                    onClick={handleExport}
                    className="px-3 py-1 bg-green-500 hover:bg-green-600 text-white rounded-lg text-sm transition-colors flex items-center space-x-1"
                  >
                    <DocumentArrowDownIcon className="w-4 h-4" />
                    <span>Export Selected</span>
                  </button>
                </PermissionCheck>
              </div>
            )}
          </div>
        </div>

        {/* IOC Display */}
        {viewMode === 'cards' ? (
          // Card View
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 sm:gap-4 lg:gap-6 p-3 sm:p-4 lg:p-6">
            {isLoading ? (
              [...Array(6)].map((_, i) => (
                <div key={i} className="glass-bg rounded-2xl p-3 sm:p-4 lg:p-6 animate-pulse">
                  <div className="flex items-center justify-between mb-3 sm:mb-4">
                    <div className="h-4 sm:h-6 bg-white/10 rounded w-1/3"></div>
                    <div className="h-4 sm:h-6 bg-white/10 rounded-full w-12 sm:w-16"></div>
                  </div>
                  <div className="h-3 sm:h-4 bg-white/10 rounded w-full mb-2"></div>
                  <div className="h-3 sm:h-4 bg-white/10 rounded w-2/3 mb-3 sm:mb-4"></div>
                  <div className="flex justify-between">
                    <div className="h-6 sm:h-8 bg-white/10 rounded w-12 sm:w-16"></div>
                    <div className="h-6 sm:h-8 bg-white/10 rounded w-16 sm:w-20"></div>
                  </div>
                </div>
              ))
            ) : (
              iocsData?.iocs?.map((ioc: any) => {
                const IconComponent = typeIcons[ioc.type as keyof typeof typeIcons] || DocumentTextIcon
                return (
                  <div key={ioc.id} className="glass-bg rounded-2xl p-3 sm:p-4 lg:p-6 hover:bg-white/10 transition-all duration-300 group border border-white/10 hover:border-white/20">
                    {/* Header */}
                    <div className="flex items-start justify-between mb-3 sm:mb-4">
                      <div className="flex items-center gap-2 sm:gap-3 min-w-0 flex-1">
                        {user && (
                          <input
                            type="checkbox"
                            checked={selectedIOCs.includes(ioc.id)}
                            onChange={() => handleSelectIOC(ioc.id)}
                            className="w-3 h-3 sm:w-4 sm:h-4 rounded border-white/20 bg-white/10 text-blue-500 focus:ring-blue-500 flex-shrink-0"
                          />
                        )}
                        <div className={`p-1.5 sm:p-2 rounded-lg flex-shrink-0 ${
                          ioc.severity === 'critical' ? 'bg-red-500/20 text-red-400' :
                          ioc.severity === 'high' ? 'bg-orange-500/20 text-orange-400' :
                          ioc.severity === 'medium' ? 'bg-yellow-500/20 text-yellow-400' :
                          'bg-green-500/20 text-green-400'
                        }`}>
                          <IconComponent className="w-3 h-3 sm:w-4 sm:h-4 lg:w-5 lg:h-5" />
                        </div>
                        <div className="min-w-0 flex-1">
                          <div className="text-white/70 text-xs uppercase font-medium tracking-wide truncate">
                            {ioc.type}
                          </div>
                          <div className={clsx(
                            'text-xs font-medium px-1.5 sm:px-2 py-0.5 sm:py-1 rounded-full mt-1 inline-block',
                            severityColors[ioc.severity as keyof typeof severityColors]
                          )}>
                            {ioc.severity}
                          </div>
                        </div>
                      </div>
                      <div className="flex items-center gap-1 sm:gap-2 flex-shrink-0">
                        <div className="text-right">
                          <div className="text-white font-bold text-sm sm:text-base lg:text-lg">{ioc.score}</div>
                          <div className="text-white/50 text-xs">Score</div>
                        </div>
                        {ioc.score >= 70 && <TrophyIcon className="w-3 h-3 sm:w-4 sm:h-4 lg:w-5 lg:h-5 text-yellow-400" />}
                      </div>
                    </div>

                    {/* IOC Value */}
                    <div className="mb-3 sm:mb-4">
                      <div className="text-white font-mono text-xs sm:text-sm break-all bg-black/20 rounded-lg p-2 sm:p-3 border border-white/10 overflow-hidden">
                        <div className="max-w-full overflow-hidden text-ellipsis">
                          {ioc.value}
                        </div>
                      </div>
                    </div>

                    {/* Tags */}
                    <div className="mb-3 sm:mb-4">
                      <div className="flex flex-wrap gap-1 sm:gap-2">
                        {ioc.tags?.slice(0, 3).map((tag: string) => {
                          const isThreatCategory = tag.startsWith('threat:')
                          const isMalwareFamily = ['mozi', 'mirai', 'emotet', 'trickbot', 'qakbot', 'zeus', 'dridex', 'ryuk', 'conti'].some(family => tag.toLowerCase().includes(family))
                          const isTechnical = ['32-bit', '64-bit', 'elf', 'pe', 'mips', 'x86', 'arm'].some(tech => tag.toLowerCase().includes(tech))
                          
                          return (
                            <span
                              key={tag}
                              onClick={() => handleFilterChange('tags', tag)}
                              className={clsx(
                                'px-1.5 sm:px-2 py-0.5 sm:py-1 rounded-lg text-xs font-medium transition-colors cursor-pointer border truncate max-w-full',
                                isThreatCategory ? 'bg-red-500/20 text-red-300 border-red-500/30 hover:bg-red-500/30' :
                                isMalwareFamily ? 'bg-purple-500/20 text-purple-300 border-purple-500/30 hover:bg-purple-500/30' :
                                isTechnical ? 'bg-blue-500/20 text-blue-300 border-blue-500/30 hover:bg-blue-500/30' :
                                'bg-gray-500/20 text-gray-300 border-gray-500/30 hover:bg-gray-500/30'
                              )}
                              title={`Filter by tag: ${tag}`}
                            >
                              #{tag}
                            </span>
                          )
                        })}
                        {ioc.tags?.length > 3 && (
                          <span className="px-1.5 sm:px-2 py-0.5 sm:py-1 bg-white/10 text-white/70 rounded-lg text-xs">
                            +{ioc.tags.length - 3} more
                          </span>
                        )}
                      </div>
                    </div>

                    {/* Threat Intelligence Context */}
                    <div className="mb-3 sm:mb-4 space-y-1 sm:space-y-2">
                      {/* VirusTotal Context */}
                      {ioc.vt && typeof ioc.vt === 'object' && (ioc.vt.positives !== undefined || ioc.vt.last_fetched_at) && (
                        <div className="flex items-center justify-between p-1.5 sm:p-2 bg-white/5 rounded-lg border border-white/10">
                          <div className="flex items-center space-x-1 sm:space-x-2 min-w-0 flex-1">
                            <ShieldCheckIcon className="w-3 h-3 sm:w-4 sm:h-4 text-blue-400 flex-shrink-0" />
                            <span className="text-white/70 text-xs">VT:</span>
                            <span className={clsx(
                              'text-xs font-medium truncate',
                              (ioc.vt.positives || 0) >= 10 ? 'text-red-400' :
                              (ioc.vt.positives || 0) >= 5 ? 'text-orange-400' :
                              (ioc.vt.positives || 0) >= 1 ? 'text-yellow-400' :
                              'text-green-400'
                            )}>
                              {ioc.vt.positives || 0}/{ioc.vt.total || 0}
                            </span>
                          </div>
                          <div className="text-white/60 text-xs flex-shrink-0">
                            Rep: {ioc.vt.reputation !== undefined ? ioc.vt.reputation : 'N/A'}
                          </div>
                        </div>
                      )}
                      
                      {/* AbuseIPDB Context */}
                      {ioc.abuseipdb && typeof ioc.abuseipdb === 'object' && (ioc.abuseipdb.abuse_confidence !== undefined || ioc.abuseipdb.last_fetched_at) && (
                        <div className="flex items-center justify-between p-1.5 sm:p-2 bg-white/5 rounded-lg border border-white/10">
                          <div className="flex items-center space-x-1 sm:space-x-2 min-w-0 flex-1">
                            <ExclamationTriangleIcon className="w-3 h-3 sm:w-4 sm:h-4 text-orange-400 flex-shrink-0" />
                            <span className="text-white/70 text-xs">Abuse:</span>
                            <span className={clsx(
                              'text-xs font-medium truncate',
                              (ioc.abuseipdb.abuse_confidence || 0) >= 75 ? 'text-red-400' :
                              (ioc.abuseipdb.abuse_confidence || 0) >= 50 ? 'text-orange-400' :
                              (ioc.abuseipdb.abuse_confidence || 0) >= 25 ? 'text-yellow-400' :
                              'text-green-400'
                            )}>
                              {ioc.abuseipdb.abuse_confidence || 0}%
                            </span>
                          </div>
                          <div className="text-white/60 text-xs flex-shrink-0">
                            {ioc.abuseipdb.total_reports || 0} reports
                          </div>
                        </div>
                      )}
                      
                      {/* Sources Context */}
                      {ioc.sources && ioc.sources.length > 0 && (
                        <div className="flex items-center justify-between p-1.5 sm:p-2 bg-white/5 rounded-lg border border-white/10">
                          <div className="flex items-center space-x-1 sm:space-x-2 min-w-0 flex-1">
                            <GlobeAltIcon className="w-3 h-3 sm:w-4 sm:h-4 text-green-400 flex-shrink-0" />
                            <span className="text-white/70 text-xs">Sources:</span>
                            <div className="flex space-x-1 min-w-0 flex-1">
                              {ioc.sources.slice(0, 2).map((source: any, index: number) => (
                                <span key={index} className="px-1 sm:px-1.5 py-0.5 bg-green-500/20 text-green-400 rounded text-xs truncate">
                                  {source.name}
                                </span>
                              ))}
                              {ioc.sources.length > 2 && (
                                <span className="text-white/60 text-xs flex-shrink-0">+{ioc.sources.length - 2}</span>
                              )}
                            </div>
                          </div>
                        </div>
                      )}
                    </div>

                    {/* Footer */}
                    <div className="flex items-center justify-between pt-3 sm:pt-4 border-t border-white/10">
                      <div className="text-white/60 text-xs min-w-0 flex-1 truncate">
                        Last seen: {formatDate(ioc.last_seen)}
                      </div>
                      <Link
                        to={`/iocs/${ioc.id}`}
                        className="inline-flex items-center gap-1 sm:gap-2 px-2 sm:px-3 py-1.5 sm:py-2 bg-blue-500/20 hover:bg-blue-500/30 text-blue-300 rounded-lg text-xs sm:text-sm transition-colors group-hover:bg-blue-500/40 flex-shrink-0"
                      >
                        <EyeIcon className="w-3 h-3 sm:w-4 sm:h-4" />
                        <span className="hidden sm:inline">Analyze</span>
                        <span className="sm:hidden">View</span>
                      </Link>
                    </div>
                  </div>
                )
              })
            )}
          </div>
        ) : (
          // Table View
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="border-b border-white/10">
              <tr className="text-left">
                <th className="px-6 py-4 text-white/70 font-medium text-sm">IOC</th>
                <th className="px-6 py-4 text-white/70 font-medium text-sm">Type</th>
                <th className="px-6 py-4 text-white/70 font-medium text-sm">Severity</th>
                <th className="px-6 py-4 text-white/70 font-medium text-sm">Score</th>
                <th className="px-6 py-4 text-white/70 font-medium text-sm">Tags</th>
                <th className="px-6 py-4 text-white/70 font-medium text-sm">Last Seen</th>
                <th className="px-6 py-4 text-white/70 font-medium text-sm">Actions</th>
              </tr>
            </thead>
            <tbody>
              {isLoading ? (
                [...Array(5)].map((_, i) => (
                  <tr key={i} className="border-b border-white/5">
                    <td className="px-6 py-4">
                      <div className="h-4 bg-white/10 rounded animate-pulse"></div>
                    </td>
                    <td className="px-6 py-4">
                      <div className="h-4 bg-white/10 rounded animate-pulse w-16"></div>
                    </td>
                    <td className="px-6 py-4">
                      <div className="h-6 bg-white/10 rounded-full animate-pulse w-20"></div>
                    </td>
                    <td className="px-6 py-4">
                      <div className="h-4 bg-white/10 rounded animate-pulse w-12"></div>
                    </td>
                    <td className="px-6 py-4">
                      <div className="h-4 bg-white/10 rounded animate-pulse w-24"></div>
                    </td>
                    <td className="px-6 py-4">
                      <div className="h-4 bg-white/10 rounded animate-pulse w-20"></div>
                    </td>
                    <td className="px-6 py-4">
                      <div className="h-6 bg-white/10 rounded animate-pulse w-16"></div>
                    </td>
                  </tr>
                ))
              ) : (
                iocsData?.iocs?.map((ioc: any) => (
                  <tr key={ioc.id} className="border-b border-white/5 hover:bg-white/5 transition-colors">
                    <td className="px-6 py-4">
                      <div className="flex items-center space-x-3">
                        {user && (
                          <input
                            type="checkbox"
                            checked={selectedIOCs.includes(ioc.id)}
                            onChange={() => handleSelectIOC(ioc.id)}
                            className="w-4 h-4 rounded border-white/20 bg-white/10 text-blue-500 focus:ring-blue-500"
                          />
                        )}
                        <div>
                          <div className="flex items-center space-x-2">
                            {(() => {
                              const IconComponent = typeIcons[ioc.type as keyof typeof typeIcons] || DocumentTextIcon
                              return <IconComponent className="w-5 h-5 text-blue-400" />
                            })()}
                            <span className="text-white font-mono text-sm truncate max-w-xs">
                              {ioc.value}
                            </span>
                          </div>
                        </div>
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <span className="text-white/70 text-sm uppercase font-medium">
                        {ioc.type}
                      </span>
                    </td>
                    <td className="px-6 py-4">
                      <span className={clsx(
                        'px-3 py-1 rounded-full text-xs font-medium border',
                        severityColors[ioc.severity as keyof typeof severityColors]
                      )}>
                        {ioc.severity}
                      </span>
                    </td>
                    <td className="px-6 py-4">
                      <span className="text-white font-medium">{ioc.score}</span>
                    </td>
                    <td className="px-6 py-4">
                      <div className="flex flex-wrap gap-1">
                        {ioc.tags?.slice(0, 2).map((tag: string) => {
                          const isThreatCategory = tag.startsWith('threat:')
                          const isMalwareFamily = ['mozi', 'mirai', 'emotet', 'trickbot', 'qakbot', 'zeus', 'dridex', 'ryuk', 'conti'].some(family => tag.toLowerCase().includes(family))
                          const isTechnical = ['32-bit', '64-bit', 'elf', 'pe', 'mips', 'x86', 'arm'].some(tech => tag.toLowerCase().includes(tech))
                          
                          return (
                            <span
                              key={tag}
                              onClick={() => handleFilterChange('tags', tag)}
                              className={clsx(
                                'px-2 py-1 rounded text-xs cursor-pointer transition-colors border',
                                isThreatCategory ? 'bg-red-500/20 text-red-300 border-red-500/30 hover:bg-red-500/30' :
                                isMalwareFamily ? 'bg-purple-500/20 text-purple-300 border-purple-500/30 hover:bg-purple-500/30' :
                                isTechnical ? 'bg-blue-500/20 text-blue-300 border-blue-500/30 hover:bg-blue-500/30' :
                                'bg-gray-500/20 text-gray-300 border-gray-500/30 hover:bg-gray-500/30'
                              )}
                              title={`Filter by tag: ${tag}`}
                            >
                              {tag}
                            </span>
                          )
                        })}
                        {ioc.tags?.length > 2 && (
                          <span className="px-2 py-1 bg-white/10 text-white/70 rounded text-xs">
                            +{ioc.tags.length - 2}
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <span className="text-white/70 text-sm">
                        {formatDate(ioc.last_seen)}
                      </span>
                    </td>
                    <td className="px-6 py-4">
                      <Link
                        to={`/iocs/${ioc.id}`}
                        className="inline-flex items-center space-x-1 px-3 py-1 bg-white/10 hover:bg-white/20 text-white rounded-lg text-sm transition-colors"
                      >
                        <EyeIcon className="w-4 h-4" />
                        <span>View</span>
                      </Link>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
        )}

        {/* Pagination */}
        {iocsData?.pages && iocsData.pages > 1 && (
          <div className="p-6 border-t border-white/10 flex items-center justify-between">
            <div className="text-white/70 text-sm">
              Page {iocsData.page} of {iocsData.pages}
            </div>
            <div className="flex items-center space-x-2">
              <button
                onClick={() => setPagination(prev => ({ ...prev, page: Math.max(1, prev.page - 1) }))}
                disabled={iocsData.page <= 1}
                className="px-3 py-1 bg-white/10 hover:bg-white/20 disabled:opacity-50 disabled:cursor-not-allowed text-white rounded-lg text-sm transition-colors"
              >
                Previous
              </button>
              <button
                onClick={() => setPagination(prev => ({ ...prev, page: Math.min(iocsData.pages, prev.page + 1) }))}
                disabled={iocsData.page >= iocsData.pages}
                className="px-3 py-1 bg-white/10 hover:bg-white/20 disabled:opacity-50 disabled:cursor-not-allowed text-white rounded-lg text-sm transition-colors"
              >
                Next
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Tag Modal */}
      {showTagModal && (
        <div className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50 p-3 sm:p-4">
          <div className="glass-bg rounded-2xl p-4 sm:p-6 w-full max-w-md max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg sm:text-xl font-semibold text-white">Tag IOCs</h3>
              <button
                onClick={() => setShowTagModal(false)}
                className="p-2 hover:bg-white/10 rounded-lg transition-colors"
              >
                <XMarkIcon className="w-4 h-4 sm:w-5 sm:h-5 text-white" />
              </button>
            </div>
            
            <div className="space-y-4">
              <div>
                <p className="text-white/70 text-sm mb-2">
                  Adding tags to {selectedIOCs.length} selected IOCs
                </p>
                
                <div className="space-y-3">
                  <div>
                    <label className="block text-white text-sm font-medium mb-2">
                      Add New Tag
                    </label>
                    <div className="flex space-x-2">
                      <input
                        type="text"
                        value={newTag}
                        onChange={(e) => setNewTag(e.target.value)}
                        placeholder="Enter tag name..."
                        className="flex-1 px-3 py-2 bg-white/10 border border-white/20 rounded-lg text-white placeholder-white/50 focus:outline-none focus:ring-2 focus:ring-blue-500"
                        onKeyPress={(e) => e.key === 'Enter' && submitTagging()}
                      />
                      <button
                        onClick={submitTagging}
                        disabled={tagIOCsMutation.isPending || !newTag.trim()}
                        className="px-4 py-2 bg-blue-500 hover:bg-blue-600 disabled:opacity-50 disabled:cursor-not-allowed text-white rounded-lg transition-colors flex items-center space-x-1"
                      >
                        <PlusIcon className="w-4 h-4" />
                        <span>Add</span>
                      </button>
                    </div>
                  </div>
                  
                  {tagsData?.tags && tagsData.tags.length > 0 && (
                    <div>
                      <label className="block text-white text-sm font-medium mb-2">
                        Quick Tags
                      </label>
                      <div className="flex flex-wrap gap-2">
                        {tagsData.tags.slice(0, 6).map((tag: any) => (
                          <button
                            key={tag.id}
                            onClick={() => setNewTag(tag.name)}
                            className="px-3 py-1 bg-white/10 hover:bg-white/20 text-white/80 hover:text-white rounded-lg text-sm transition-colors"
                          >
                            {tag.name}
                          </button>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </div>
              
              <div className="flex space-x-3 pt-4">
                <button
                  onClick={() => setShowTagModal(false)}
                  className="flex-1 px-4 py-2 bg-white/10 hover:bg-white/20 text-white rounded-lg transition-colors"
                >
                  Cancel
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Export Modal */}
      {showExportModal && (
        <div className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50 p-3 sm:p-4">
          <div className="glass-bg rounded-2xl p-4 sm:p-6 w-full max-w-md max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg sm:text-xl font-semibold text-white">Export IOCs</h3>
              <button
                onClick={() => setShowExportModal(false)}
                className="p-2 hover:bg-white/10 rounded-lg transition-colors"
              >
                <XMarkIcon className="w-4 h-4 sm:w-5 sm:h-5 text-white" />
              </button>
            </div>
            
            <div className="space-y-4">
              <div>
                <p className="text-white/70 text-sm mb-4">
                  {selectedIOCs.length > 0 
                    ? `Exporting ${selectedIOCs.length} selected IOCs`
                    : 'Exporting all IOCs matching current filters'
                  }
                </p>
                
                <div className="space-y-3">
                  <div>
                    <label className="block text-white text-sm font-medium mb-2">
                      Export Format
                    </label>
                    <select
                      value={exportFormat}
                      onChange={(e) => setExportFormat(e.target.value)}
                      className="w-full px-3 py-2 bg-white/10 border border-white/20 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                    >
                      <option value="csv">CSV</option>
                      <option value="json">JSON</option>
                      <option value="xlsx">Excel (XLSX)</option>
                    </select>
                  </div>
                  
                  <div className="bg-white/5 rounded-lg p-3">
                    <h4 className="text-white font-medium text-sm mb-2">Export will include:</h4>
                    <ul className="text-white/70 text-sm space-y-1">
                      <li>• IOC value and type</li>
                      <li>• Threat score and severity</li>
                      <li>• Tags and sources</li>
                      <li>• Timestamps</li>
                      <li>• External intelligence data</li>
                    </ul>
                  </div>
                </div>
              </div>
              
              <div className="flex space-x-3 pt-4">
                <button
                  onClick={() => setShowExportModal(false)}
                  className="flex-1 px-4 py-2 bg-white/10 hover:bg-white/20 text-white rounded-lg transition-colors"
                >
                  Cancel
                </button>
                <button
                  onClick={submitExport}
                  disabled={exportMutation.isPending}
                  className="flex-1 px-4 py-2 bg-blue-500 hover:bg-blue-600 disabled:opacity-50 disabled:cursor-not-allowed text-white rounded-lg transition-colors flex items-center justify-center space-x-2"
                >
                  {exportMutation.isPending ? (
                    <>
                      <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                      <span>Exporting...</span>
                    </>
                  ) : (
                    <>
                      <DocumentArrowDownIcon className="w-4 h-4" />
                      <span>Start Export</span>
                    </>
                  )}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default IOCsPage
