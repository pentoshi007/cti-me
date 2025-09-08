import { useState } from 'react'
import { useParams, useNavigate, Link } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  ShieldCheckIcon,
  ExclamationTriangleIcon,
  ClockIcon,
  TagIcon,
  GlobeAltIcon,
  LinkIcon,
  DocumentTextIcon,
  FireIcon,
  TrophyIcon,
  ArrowLeftIcon,
  ShareIcon,
  DocumentArrowDownIcon,
  MagnifyingGlassIcon,
  EyeIcon,
  ChartBarIcon,
  ExclamationCircleIcon,
  CheckCircleIcon,
  InformationCircleIcon,
  PlusIcon,
  XMarkIcon,
  ArrowTopRightOnSquareIcon,
  CalendarDaysIcon,
  MapPinIcon,
  CpuChipIcon,
  ServerIcon,
  UserGroupIcon,
  BugAntIcon,
} from '@heroicons/react/24/outline'
import { api } from '../api'
import { useAuthStore } from '../stores/authStore'
import PermissionCheck from '../components/PermissionCheck'
import toast from 'react-hot-toast'
import clsx from 'clsx'

const IOCDetailPage = () => {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const { hasPermission } = useAuthStore()
  
  const [showAddTagModal, setShowAddTagModal] = useState(false)
  const [newTag, setNewTag] = useState('')
  const [activeTab, setActiveTab] = useState<'overview' | 'sources' | 'enrichment' | 'timeline'>('overview')

  const { data: ioc, isLoading } = useQuery({
    queryKey: ['ioc', id],
    queryFn: () => api.iocs.get(id!).then(res => res.data),
    enabled: !!id,
  })

  // Add tag mutation
  const addTagMutation = useMutation({
    mutationFn: (tag: string) => api.iocs.update(id!, { action: 'add', tag }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ioc', id] })
      toast.success('Tag added successfully')
      setNewTag('')
      setShowAddTagModal(false)
    },
    onError: (error: any) => {
      toast.error(error.response?.data?.message || 'Failed to add tag')
    }
  })

  // Remove tag mutation
  const removeTagMutation = useMutation({
    mutationFn: (tag: string) => api.iocs.update(id!, { action: 'remove', tag }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ioc', id] })
      toast.success('Tag removed successfully')
    },
    onError: (error: any) => {
      toast.error(error.response?.data?.message || 'Failed to remove tag')
    }
  })

  if (isLoading) {
    return (
      <div className="space-y-6">
        {/* Loading Header */}
        <div className="glass-bg rounded-2xl p-6 animate-pulse">
          <div className="flex items-center gap-4 mb-6">
            <div className="h-12 w-12 bg-white/20 rounded-xl"></div>
            <div className="flex-1">
              <div className="h-8 bg-white/20 rounded mb-2 w-1/3"></div>
              <div className="h-4 bg-white/20 rounded w-2/3"></div>
            </div>
            <div className="h-6 bg-white/20 rounded-full w-20"></div>
          </div>
        </div>
        
        {/* Loading Content */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-2 space-y-6">
            {[...Array(3)].map((_, i) => (
              <div key={i} className="glass-bg rounded-2xl p-6 animate-pulse">
                <div className="h-6 bg-white/20 rounded mb-4 w-1/4"></div>
                <div className="space-y-3">
                  <div className="h-4 bg-white/20 rounded w-full"></div>
                  <div className="h-4 bg-white/20 rounded w-3/4"></div>
                  <div className="h-4 bg-white/20 rounded w-1/2"></div>
                </div>
              </div>
            ))}
          </div>
          <div className="space-y-6">
            <div className="glass-bg rounded-2xl p-6 animate-pulse">
              <div className="h-6 bg-white/20 rounded mb-4 w-1/3"></div>
              <div className="space-y-2">
                {[...Array(4)].map((_, i) => (
                  <div key={i} className="h-8 bg-white/20 rounded"></div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </div>
    )
  }

  if (!ioc) {
    return (
      <div className="glass-bg rounded-2xl p-6 text-center">
        <ExclamationCircleIcon className="w-16 h-16 text-red-400 mx-auto mb-4" />
        <h1 className="text-2xl font-bold text-white mb-2">IOC Not Found</h1>
        <p className="text-white/60 mb-6">The requested indicator could not be found or may have been removed.</p>
        <button
          onClick={() => navigate('/iocs')}
          className="px-4 py-2 bg-blue-500 hover:bg-blue-600 text-white rounded-xl transition-colors"
        >
          Back to IOCs
        </button>
      </div>
    )
  }

  const typeIcons = {
    ip: GlobeAltIcon,
    domain: LinkIcon,
    url: DocumentTextIcon,
    sha256: ShieldCheckIcon,
    md5: ShieldCheckIcon,
    sha1: ShieldCheckIcon,
  }

  const severityConfig = {
    critical: { color: 'text-red-400', bg: 'bg-red-500/20', border: 'border-red-500/30', icon: FireIcon },
    high: { color: 'text-orange-400', bg: 'bg-orange-500/20', border: 'border-orange-500/30', icon: ExclamationTriangleIcon },
    medium: { color: 'text-yellow-400', bg: 'bg-yellow-500/20', border: 'border-yellow-500/30', icon: ExclamationCircleIcon },
    low: { color: 'text-green-400', bg: 'bg-green-500/20', border: 'border-green-500/30', icon: CheckCircleIcon },
    info: { color: 'text-blue-400', bg: 'bg-blue-500/20', border: 'border-blue-500/30', icon: InformationCircleIcon },
  }

  const IconComponent = typeIcons[ioc.type as keyof typeof typeIcons] || DocumentTextIcon
  const severityInfo = severityConfig[ioc.severity as keyof typeof severityConfig] || severityConfig.info
  const SeverityIcon = severityInfo.icon

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      timeZoneName: 'short'
    })
  }

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text)
    toast.success('Copied to clipboard')
  }

  const handleAddTag = () => {
    if (!newTag.trim()) {
      toast.error('Please enter a tag name')
      return
    }
    addTagMutation.mutate(newTag.trim())
  }

  const handleRemoveTag = (tag: string) => {
    removeTagMutation.mutate(tag)
  }

  const getScoreColor = (score: number) => {
    if (score >= 80) return 'text-red-400'
    if (score >= 60) return 'text-orange-400'
    if (score >= 40) return 'text-yellow-400'
    return 'text-green-400'
  }

  const tabs = [
    { id: 'overview', label: 'Overview', icon: EyeIcon },
    { id: 'sources', label: 'Sources', icon: ServerIcon },
    { id: 'enrichment', label: 'Enrichment', icon: CpuChipIcon },
    { id: 'timeline', label: 'Timeline', icon: ClockIcon },
  ]

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="glass-bg rounded-2xl p-3 sm:p-4 lg:p-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between mb-4 sm:mb-6 gap-4">
          <div className="flex items-center gap-3 sm:gap-4 min-w-0 flex-1">
            <button
              onClick={() => navigate('/iocs')}
              className="p-2 bg-white/10 hover:bg-white/20 text-white rounded-xl transition-colors"
              title="Back to IOCs"
              aria-label="Back to IOCs"
            >
              <ArrowLeftIcon className="w-5 h-5" />
            </button>
            <div className={`p-3 rounded-xl ${severityInfo.bg} ${severityInfo.border} border`}>
              <IconComponent className={`w-8 h-8 ${severityInfo.color}`} />
            </div>
            <div className="flex-1">
              <div className="flex items-center gap-2 mb-1">
                <h1 className="text-xl sm:text-2xl font-bold text-white">IOC Analysis</h1>
                {ioc.score >= 70 && <TrophyIcon className="w-6 h-6 text-yellow-400" />}
              </div>
              <p className="text-white/60 text-sm sm:text-base">Detailed threat intelligence analysis</p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <div className={`px-2 sm:px-3 py-1 rounded-full text-xs sm:text-sm font-medium ${severityInfo.bg} ${severityInfo.color} border ${severityInfo.border}`}>
              <SeverityIcon className="w-4 h-4 inline mr-1" />
              {ioc.severity.toUpperCase()}
            </div>
            <div className={`text-lg sm:text-2xl font-bold ${getScoreColor(ioc.score)}`}>
              {ioc.score}/100
            </div>
            <button
              onClick={() => copyToClipboard(window.location.href)}
              className="p-2 bg-white/10 hover:bg-white/20 text-white rounded-xl transition-colors"
              title="Share IOC"
            >
              <ShareIcon className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* IOC Value Display */}
        <div className="bg-black/30 rounded-xl p-3 sm:p-4 border border-white/10">
          <div className="flex items-center justify-between">
            <div className="flex-1">
              <div className="text-white/60 text-sm mb-1 uppercase tracking-wide font-medium">
                {ioc.type} Indicator
              </div>
              <div className="text-white font-mono text-sm sm:text-lg break-all select-all">
                {ioc.value}
              </div>
            </div>
            <button
              onClick={() => copyToClipboard(ioc.value)}
              className="p-2 bg-white/10 hover:bg-white/20 text-white rounded-lg transition-colors ml-2 sm:ml-4 flex-shrink-0"
              title="Copy IOC"
            >
              <DocumentTextIcon className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Tabs */}
        <div className="mt-4 sm:mt-6">
          <div className="flex flex-wrap sm:flex-nowrap space-x-1 bg-white/5 rounded-xl p-1">
            {tabs.map((tab) => {
              const TabIcon = tab.icon
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id as any)}
                  className={clsx(
                    'flex-1 flex items-center justify-center gap-1 sm:gap-2 px-2 sm:px-4 py-2 rounded-lg text-xs sm:text-sm font-medium transition-colors min-w-0',
                    activeTab === tab.id
                      ? 'bg-blue-500 text-white'
                      : 'text-white/70 hover:text-white hover:bg-white/5'
                  )}
                >
                  <TabIcon className="w-4 h-4" />
                  {tab.label}
                </button>
              )
            })}
          </div>
        </div>
      </div>

      {/* Main Content */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column - Main Content */}
        <div className="lg:col-span-2 space-y-6">
          {activeTab === 'overview' && (
            <>
              {/* Key Metrics */}
              <div className="glass-bg rounded-2xl p-3 sm:p-4 lg:p-6">
                <h3 className="text-xl font-semibold text-white mb-4 flex items-center gap-2">
                  <ChartBarIcon className="w-6 h-6 text-blue-400" />
                  Key Metrics
                </h3>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3 sm:gap-4">
                  <div className="bg-white/5 rounded-xl p-4 text-center border border-white/10">
                    <div className={`text-xl sm:text-2xl font-bold ${getScoreColor(ioc.score)}`}>{ioc.score}</div>
                    <div className="text-white/60 text-sm">Threat Score</div>
                  </div>
                  <div className="bg-white/5 rounded-xl p-4 text-center border border-white/10">
                    <div className="text-white text-xl sm:text-2xl font-bold">{ioc.sources?.length || 0}</div>
                    <div className="text-white/60 text-sm">Sources</div>
                  </div>
                  <div className="bg-white/5 rounded-xl p-4 text-center border border-white/10">
                    <div className="text-white text-xl sm:text-2xl font-bold">{ioc.tags?.length || 0}</div>
                    <div className="text-white/60 text-sm">Tags</div>
                  </div>
                  <div className="bg-white/5 rounded-xl p-4 text-center border border-white/10">
                    <div className="text-white text-xl sm:text-2xl font-bold">
                      {Math.floor((new Date().getTime() - new Date(ioc.first_seen).getTime()) / (1000 * 60 * 60 * 24))}
                    </div>
                    <div className="text-white/60 text-sm">Days Active</div>
                  </div>
                </div>
              </div>

              {/* Basic Information */}
              <div className="glass-bg rounded-2xl p-3 sm:p-4 lg:p-6">
                <h3 className="text-xl font-semibold text-white mb-4 flex items-center gap-2">
                  <InformationCircleIcon className="w-6 h-6 text-blue-400" />
                  Basic Information
                </h3>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 sm:gap-6">
                  <div className="space-y-4">
                    <div className="flex justify-between items-center p-3 bg-white/5 rounded-lg border border-white/10">
                      <span className="text-white/70 font-medium text-sm sm:text-base">Type</span>
                      <span className="text-white uppercase font-semibold text-sm sm:text-base">{ioc.type}</span>
                    </div>
                    <div className="flex justify-between items-center p-3 bg-white/5 rounded-lg border border-white/10">
                      <span className="text-white/70 font-medium text-sm sm:text-base">Severity</span>
                      <span className={`font-semibold capitalize text-sm sm:text-base ${severityInfo.color}`}>{ioc.severity}</span>
                    </div>
                    <div className="flex justify-between items-center p-3 bg-white/5 rounded-lg border border-white/10">
                      <span className="text-white/70 font-medium text-sm sm:text-base">Threat Score</span>
                      <span className={`font-bold text-sm sm:text-base ${getScoreColor(ioc.score)}`}>{ioc.score}/100</span>
                    </div>
                  </div>
                  <div className="space-y-4">
                    <div className="flex justify-between items-center p-3 bg-white/5 rounded-lg border border-white/10">
                      <span className="text-white/70 font-medium text-sm sm:text-base">First Seen</span>
                      <span className="text-white text-sm">{formatDate(ioc.first_seen)}</span>
                    </div>
                    <div className="flex justify-between items-center p-3 bg-white/5 rounded-lg border border-white/10">
                      <span className="text-white/70 font-medium text-sm sm:text-base">Last Seen</span>
                      <span className="text-white text-sm">{formatDate(ioc.last_seen)}</span>
                    </div>
                    <div className="flex justify-between items-center p-3 bg-white/5 rounded-lg border border-white/10">
                      <span className="text-white/70 font-medium text-sm sm:text-base">Updated</span>
                      <span className="text-white text-sm">{formatDate(ioc.updated_at)}</span>
                    </div>
                  </div>
                </div>
              </div>
            </>
          )}

          {activeTab === 'sources' && (
            <div className="glass-bg rounded-2xl p-6">
              <h3 className="text-xl font-semibold text-white mb-4 flex items-center gap-2">
                <ServerIcon className="w-6 h-6 text-blue-400" />
                Intelligence Sources
              </h3>
              {ioc.sources && ioc.sources.length > 0 ? (
                <div className="space-y-4">
                  {ioc.sources.map((source: any, index: number) => (
                    <div key={index} className="bg-white/5 rounded-xl p-4 border border-white/10">
                      <div className="flex items-center justify-between mb-3">
                        <div className="flex items-center gap-3">
                          <div className="p-2 bg-blue-500/20 rounded-lg">
                            <ServerIcon className="w-5 h-5 text-blue-400" />
                          </div>
                          <div>
                            <div className="text-white font-semibold capitalize">{source.name}</div>
                            <div className="text-white/60 text-sm">Intelligence Source</div>
                          </div>
                        </div>
                        {source.ref && (
                          <a
                            href={source.ref}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="p-2 bg-white/10 hover:bg-white/20 text-white rounded-lg transition-colors"
                            title={`View source: ${source.name}`}
                            aria-label={`View source: ${source.name}`}
                          >
                            <ArrowTopRightOnSquareIcon className="w-4 h-4" />
                          </a>
                        )}
                      </div>
                      <div className="grid grid-cols-2 gap-4 text-sm">
                        <div>
                          <span className="text-white/60">First Reported:</span>
                          <div className="text-white font-mono">{formatDate(source.first_seen)}</div>
                        </div>
                        <div>
                          <span className="text-white/60">Last Updated:</span>
                          <div className="text-white font-mono">{formatDate(source.last_seen)}</div>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-center py-8 text-white/60">
                  <ServerIcon className="w-12 h-12 mx-auto mb-4 opacity-50" />
                  <p>No source information available</p>
                </div>
              )}
            </div>
          )}

          {activeTab === 'enrichment' && (
            <div className="glass-bg rounded-2xl p-6">
              <h3 className="text-xl font-semibold text-white mb-4 flex items-center gap-2">
                <CpuChipIcon className="w-6 h-6 text-blue-400" />
                Threat Intelligence Enrichment
              </h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                {/* VirusTotal */}
                <div className="bg-white/5 rounded-xl p-4 border border-white/10">
                  <div className="flex items-center gap-3 mb-4">
                    <div className="p-2 bg-green-500/20 rounded-lg">
                      <ShieldCheckIcon className="w-5 h-5 text-green-400" />
                    </div>
                    <div>
                      <div className="text-white font-semibold">VirusTotal</div>
                      <div className="text-white/60 text-sm">Malware Detection</div>
                    </div>
                  </div>
                  {ioc.vt && typeof ioc.vt === 'object' && (ioc.vt.positives !== undefined || ioc.vt.last_fetched_at) ? (
                    <div className="space-y-3">
                      {/* Detection Summary */}
                      <div className="flex justify-between items-center">
                        <span className="text-white/70">Detection Ratio:</span>
                        <span className={`text-sm font-semibold ${
                          ioc.vt.positives > 0 ? 'text-red-400' : 'text-green-400'
                        }`}>
                          {ioc.vt.positives || 0}/{ioc.vt.total || 0}
                        </span>
                      </div>

                      {/* Reputation Score */}
                      {ioc.vt.reputation !== undefined && (
                        <div className="flex justify-between items-center">
                          <span className="text-white/70">Reputation:</span>
                          <span className={`text-sm font-semibold ${
                            ioc.vt.reputation < -10 ? 'text-red-400' : 
                            ioc.vt.reputation < 0 ? 'text-orange-400' : 'text-green-400'
                          }`}>
                            {ioc.vt.reputation}
                          </span>
                        </div>
                      )}

                      {/* Country */}
                      {ioc.vt.country && (
                        <div className="flex justify-between items-center">
                          <span className="text-white/70">Country:</span>
                          <span className="text-white text-sm">{ioc.vt.country}</span>
                        </div>
                      )}

                      {/* ASN */}
                      {ioc.vt.asn && (
                        <div className="flex justify-between items-center">
                          <span className="text-white/70">ASN:</span>
                          <span className="text-white text-sm">{ioc.vt.asn}</span>
                        </div>
                      )}

                      {/* Last Analysis */}
                      <div className="flex justify-between items-center">
                        <span className="text-white/70">Last Analysis:</span>
                        <span className="text-white/60 text-sm">
                          {ioc.vt.last_fetched_at ? new Date(ioc.vt.last_fetched_at).toLocaleString() : 'N/A'}
                        </span>
                      </div>

                      {/* VirusTotal Link */}
                      {ioc.vt.permalink && (
                        <div className="pt-2">
                          <a 
                            href={ioc.vt.permalink} 
                            target="_blank" 
                            rel="noopener noreferrer"
                            className="text-blue-400 hover:text-blue-300 text-sm underline"
                          >
                            View on VirusTotal →
                          </a>
                        </div>
                      )}

                      {/* Error Message */}
                      {ioc.vt.error && (
                        <div className="text-red-400 text-sm">
                          Error: {ioc.vt.error}
                        </div>
                      )}
                    </div>
                  ) : (
                    <p className="text-white/60 text-sm">No VirusTotal data available</p>
                  )}
                </div>

                {/* AbuseIPDB */}
                <div className="bg-white/5 rounded-xl p-4 border border-white/10">
                  <div className="flex items-center gap-3 mb-4">
                    <div className="p-2 bg-red-500/20 rounded-lg">
                      <ExclamationTriangleIcon className="w-5 h-5 text-red-400" />
                    </div>
          <div>
                      <div className="text-white font-semibold">AbuseIPDB</div>
                      <div className="text-white/60 text-sm">Abuse Reports</div>
                    </div>
                  </div>
                  {ioc.abuseipdb && typeof ioc.abuseipdb === 'object' && (ioc.abuseipdb.abuse_confidence !== undefined || ioc.abuseipdb.last_fetched_at) ? (
                    <div className="space-y-3">
                      {/* Abuse Confidence */}
                      <div className="flex justify-between items-center">
                        <span className="text-white/70">Abuse Confidence:</span>
                        <span className={`text-sm font-semibold ${
                          ioc.abuseipdb.abuse_confidence >= 75 ? 'text-red-400' :
                          ioc.abuseipdb.abuse_confidence >= 50 ? 'text-orange-400' :
                          ioc.abuseipdb.abuse_confidence >= 25 ? 'text-yellow-400' :
                          'text-green-400'
                        }`}>
                          {ioc.abuseipdb.abuse_confidence || 0}%
                        </span>
                      </div>

                      {/* Total Reports */}
                      <div className="flex justify-between items-center">
                        <span className="text-white/70">Total Reports:</span>
                        <span className="text-white text-sm">{ioc.abuseipdb.total_reports || 0}</span>
                      </div>

                      {/* Country */}
                      {ioc.abuseipdb.country_name && (
                        <div className="flex justify-between items-center">
                          <span className="text-white/70">Country:</span>
                          <span className="text-white text-sm">
                            {ioc.abuseipdb.country_name} ({ioc.abuseipdb.country_code})
                          </span>
                        </div>
                      )}

                      {/* ISP */}
                      {ioc.abuseipdb.isp && (
                        <div className="flex justify-between items-center">
                          <span className="text-white/70">ISP:</span>
                          <span className="text-white text-sm">{ioc.abuseipdb.isp}</span>
                        </div>
                      )}

                      {/* Usage Type */}
                      {ioc.abuseipdb.usage_type && (
                        <div className="flex justify-between items-center">
                          <span className="text-white/70">Usage Type:</span>
                          <span className="text-white text-sm">{ioc.abuseipdb.usage_type}</span>
                        </div>
                      )}

                      {/* Is Whitelisted */}
                      <div className="flex justify-between items-center">
                        <span className="text-white/70">Whitelisted:</span>
                        <span className={`text-sm font-semibold ${
                          ioc.abuseipdb.is_whitelisted ? 'text-green-400' : 'text-white/60'
                        }`}>
                          {ioc.abuseipdb.is_whitelisted ? 'Yes' : 'No'}
                        </span>
                      </div>

                      {/* Last Analysis */}
                      <div className="flex justify-between items-center">
                        <span className="text-white/70">Last Checked:</span>
                        <span className="text-white/60 text-sm">
                          {ioc.abuseipdb.last_fetched_at ? new Date(ioc.abuseipdb.last_fetched_at).toLocaleString() : 'N/A'}
                        </span>
                      </div>

                      {/* Error Message */}
                      {ioc.abuseipdb.error && (
                        <div className="text-red-400 text-sm">
                          Error: {ioc.abuseipdb.error}
                        </div>
                      )}
                    </div>
                  ) : (
                    ioc.type === 'ip' ? (
                      <p className="text-white/60 text-sm">No AbuseIPDB data available</p>
                    ) : (
                      <p className="text-white/60 text-sm">AbuseIPDB only available for IP addresses</p>
                    )
                  )}
                </div>
              </div>
            </div>
          )}

          {activeTab === 'timeline' && (
            <div className="glass-bg rounded-2xl p-6">
              <h3 className="text-xl font-semibold text-white mb-4 flex items-center gap-2">
                <ClockIcon className="w-6 h-6 text-blue-400" />
                Activity Timeline
              </h3>
              <div className="space-y-4">
                {/* Timeline events */}
                <div className="flex items-start gap-4">
                  <div className="flex-shrink-0 w-3 h-3 bg-green-400 rounded-full mt-2"></div>
                  <div className="flex-1">
                    <div className="text-white font-medium">IOC Created</div>
                    <div className="text-white/60 text-sm">{formatDate(ioc.created_at)}</div>
                  </div>
                </div>
                <div className="flex items-start gap-4">
                  <div className="flex-shrink-0 w-3 h-3 bg-blue-400 rounded-full mt-2"></div>
                  <div className="flex-1">
                    <div className="text-white font-medium">First Observed</div>
                    <div className="text-white/60 text-sm">{formatDate(ioc.first_seen)}</div>
                  </div>
                </div>
                <div className="flex items-start gap-4">
                  <div className="flex-shrink-0 w-3 h-3 bg-yellow-400 rounded-full mt-2"></div>
                  <div className="flex-1">
                    <div className="text-white font-medium">Last Activity</div>
                    <div className="text-white/60 text-sm">{formatDate(ioc.last_seen)}</div>
                  </div>
                </div>
                <div className="flex items-start gap-4">
                  <div className="flex-shrink-0 w-3 h-3 bg-purple-400 rounded-full mt-2"></div>
                  <div className="flex-1">
                    <div className="text-white font-medium">Last Updated</div>
                    <div className="text-white/60 text-sm">{formatDate(ioc.updated_at)}</div>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Right Sidebar */}
        <div className="space-y-6">
          {/* Quick Actions */}
          <div className="glass-bg rounded-2xl p-6">
            <h3 className="text-lg font-semibold text-white mb-4">Quick Actions</h3>
            <div className="space-y-3">
              <button
                onClick={() => copyToClipboard(ioc.value)}
                className="w-full flex items-center gap-3 p-3 bg-white/5 hover:bg-white/10 text-white rounded-xl transition-colors"
              >
                <DocumentTextIcon className="w-5 h-5 text-blue-400" />
                Copy IOC Value
              </button>
              <Link
                to={`/lookup?indicator=${encodeURIComponent(ioc.value)}`}
                className="w-full flex items-center gap-3 p-3 bg-white/5 hover:bg-white/10 text-white rounded-xl transition-colors"
              >
                <MagnifyingGlassIcon className="w-5 h-5 text-green-400" />
                Lookup in External Sources
              </Link>
              <Link
                to={`/iocs?q=${encodeURIComponent(ioc.value)}`}
                className="w-full flex items-center gap-3 p-3 bg-white/5 hover:bg-white/10 text-white rounded-xl transition-colors"
              >
                <EyeIcon className="w-5 h-5 text-purple-400" />
                Find Related IOCs
              </Link>
            </div>
          </div>

          {/* Tags Management */}
          <div className="glass-bg rounded-2xl p-6">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold text-white flex items-center gap-2">
                <TagIcon className="w-5 h-5 text-blue-400" />
                Tags
              </h3>
              <PermissionCheck requireAuth={true}>
                <button
                  onClick={() => setShowAddTagModal(true)}
                  className="p-2 bg-blue-500/20 hover:bg-blue-500/30 text-blue-400 rounded-lg transition-colors"
                  title="Add new tag"
                  aria-label="Add new tag"
                >
                  <PlusIcon className="w-4 h-4" />
                </button>
              </PermissionCheck>
            </div>
            
            <div className="space-y-2">
              {ioc.tags && ioc.tags.length > 0 ? (
                ioc.tags.map((tag: string) => (
                  <div
                    key={tag}
                    className="flex items-center justify-between p-2 bg-white/5 rounded-lg border border-white/10"
                  >
                    <span className="text-white text-sm">#{tag}</span>
                    <PermissionCheck requireAuth={true}>
                      <button
                        onClick={() => handleRemoveTag(tag)}
                        className="p-1 text-white/50 hover:text-red-400 transition-colors"
                        title={`Remove tag: ${tag}`}
                        aria-label={`Remove tag: ${tag}`}
                      >
                        <XMarkIcon className="w-4 h-4" />
                      </button>
                    </PermissionCheck>
                  </div>
                ))
              ) : (
                <p className="text-white/60 text-sm italic">No tags assigned</p>
              )}
            </div>
          </div>

          {/* Risk Assessment */}
          <div className="glass-bg rounded-2xl p-6">
            <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
              <ShieldCheckIcon className="w-5 h-5 text-blue-400" />
              Risk Assessment
            </h3>
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <span className="text-white/70">Threat Level</span>
                <div className={`w-16 h-16 rounded-full flex items-center justify-center text-white font-bold text-lg ${severityInfo.bg} border ${severityInfo.border}`}>
                  {ioc.score}
                </div>
              </div>
              <div className="w-full bg-white/10 rounded-full h-3 relative overflow-hidden">
                <div
                  className={`h-3 rounded-full transition-all duration-500 ${
                    ioc.score >= 80 ? 'bg-red-500' :
                    ioc.score >= 60 ? 'bg-orange-500' :
                    ioc.score >= 40 ? 'bg-yellow-500' :
                    'bg-green-500'
                  } ${
                    ioc.score >= 90 ? 'w-[90%]' :
                    ioc.score >= 80 ? 'w-[80%]' :
                    ioc.score >= 70 ? 'w-[70%]' :
                    ioc.score >= 60 ? 'w-[60%]' :
                    ioc.score >= 50 ? 'w-[50%]' :
                    ioc.score >= 40 ? 'w-[40%]' :
                    ioc.score >= 30 ? 'w-[30%]' :
                    ioc.score >= 20 ? 'w-[20%]' :
                    ioc.score >= 10 ? 'w-[10%]' :
                    'w-[5%]'
                  }`}
                ></div>
              </div>
              <div className="text-center">
                <div className={`text-sm font-medium ${severityInfo.color}`}>
                  {ioc.severity.toUpperCase()} RISK
                </div>
                {ioc.score >= 70 && (
                  <div className="text-yellow-400 text-xs mt-1 flex items-center justify-center gap-1">
                    <TrophyIcon className="w-3 h-3" />
                    High Priority Threat
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Add Tag Modal */}
      {showAddTagModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="glass-bg rounded-2xl p-6 w-full max-w-md">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold text-white">Add Tag</h3>
              <button
                onClick={() => setShowAddTagModal(false)}
                className="p-2 text-white/50 hover:text-white transition-colors"
                title="Close modal"
                aria-label="Close modal"
              >
                <XMarkIcon className="w-5 h-5" />
              </button>
            </div>
            <div className="space-y-4">
              <input
                type="text"
                value={newTag}
                onChange={(e) => setNewTag(e.target.value)}
                placeholder="Enter tag name..."
                className="w-full px-4 py-2 bg-white/10 border border-white/20 rounded-xl text-white placeholder-white/50 focus:outline-none focus:ring-2 focus:ring-blue-500"
                onKeyPress={(e) => e.key === 'Enter' && handleAddTag()}
              />
              <div className="flex gap-3">
                <button
                  onClick={handleAddTag}
                  disabled={addTagMutation.isPending}
                  className="flex-1 px-4 py-2 bg-blue-500 hover:bg-blue-600 disabled:opacity-50 text-white rounded-xl transition-colors"
                >
                  {addTagMutation.isPending ? 'Adding...' : 'Add Tag'}
                </button>
                <button
                  onClick={() => setShowAddTagModal(false)}
                  className="px-4 py-2 bg-white/10 hover:bg-white/20 text-white rounded-xl transition-colors"
                >
                  Cancel
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default IOCDetailPage
