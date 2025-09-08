import { useState } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { 
  MagnifyingGlassIcon,
  ExclamationTriangleIcon,
  ShieldCheckIcon,
  ClockIcon,
  TagIcon,
  LinkIcon,
  EyeIcon,
  ChartBarIcon,
  InformationCircleIcon,
  ExclamationCircleIcon,
  CheckCircleIcon,
  XCircleIcon,
  ServerIcon,
  GlobeAltIcon,
  DocumentTextIcon,
  CalendarIcon,
  ArrowTopRightOnSquareIcon
} from '@heroicons/react/24/outline'
import { api } from '../api'
import toast from 'react-hot-toast'
import clsx from 'clsx'

interface LookupResult {
  lookup_id: string
  ioc: {
    id: string
    type: string
    value: string
    sources: Array<{
      name: string
      first_seen: string
      last_seen: string
      ref: string
    }>
    score: number
    severity: string
    vt?: {
      last_fetched_at: string
      positives: number
      total: number
      categories: string[]
      reputation: number
      title: string
      final_url: string | null
      permalink: string
      last_analysis_stats: {
        malicious: number
        suspicious: number
        undetected: number
        harmless: number
        timeout: number
      }
    }
    abuseipdb?: {
      abuse_confidence: number
      country_code: string
      usage_type: string
      isp: string
      domain: string
      total_reports: number
      num_distinct_users: number
    }
    tags: string[]
    first_seen: string
    last_seen: string
    created_at: string
    updated_at: string
  }
  status: string
  error: string | null
}

const LookupPage = () => {
  const [indicator, setIndicator] = useState('')
  const [result, setResult] = useState<LookupResult | null>(null)
  const [selectedTags, setSelectedTags] = useState<string[]>([])
  const [showRawData, setShowRawData] = useState(false)

  // Fetch available tags for tagging
  const { data: availableTags } = useQuery({
    queryKey: ['tags'],
    queryFn: () => api.tags.list().then(res => res.data)
  })

  const lookupMutation = useMutation({
    mutationFn: (indicator: string) => api.lookup.perform(indicator),
    onSuccess: (response) => {
      setResult(response.data)
      setSelectedTags([]) // Reset selected tags
      toast.success('Threat intelligence lookup completed')
    },
    onError: (error: any) => {
      toast.error(error.response?.data?.message || 'Lookup failed')
    },
  })

  // Tag IOC mutation
  const tagMutation = useMutation({
    mutationFn: ({ iocId, tags }: { iocId: string, tags: string[] }) => 
      api.iocs.bulkTag({ ioc_ids: [iocId], tag_names: tags }),
    onSuccess: () => {
      toast.success('Tags applied successfully')
      // Refresh the lookup result to show updated tags
      if (result) {
        lookupMutation.mutate(indicator)
      }
    },
    onError: (error: any) => {
      toast.error(error.response?.data?.message || 'Failed to apply tags')
    }
  })

  const handleLookup = (e: React.FormEvent) => {
    e.preventDefault()
    if (indicator.trim()) {
      setResult(null) // Clear previous results
      lookupMutation.mutate(indicator.trim())
    }
  }

  const handleApplyTags = () => {
    if (result && selectedTags.length > 0) {
      tagMutation.mutate({ iocId: result.ioc.id, tags: selectedTags })
    }
  }

  const getSeverityColor = (severity: string) => {
    switch (severity?.toLowerCase()) {
      case 'critical':
        return 'bg-red-500/20 text-red-400 border-red-500/30'
      case 'high':
        return 'bg-orange-500/20 text-orange-400 border-orange-500/30'
      case 'medium':
        return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30'
      case 'low':
        return 'bg-green-500/20 text-green-400 border-green-500/30'
      default:
        return 'bg-gray-500/20 text-gray-400 border-gray-500/30'
    }
  }

  const getSeverityIcon = (severity: string) => {
    switch (severity?.toLowerCase()) {
      case 'critical':
        return <ExclamationCircleIcon className="w-5 h-5" />
      case 'high':
        return <ExclamationTriangleIcon className="w-5 h-5" />
      case 'medium':
        return <InformationCircleIcon className="w-5 h-5" />
      case 'low':
        return <CheckCircleIcon className="w-5 h-5" />
      default:
        return <InformationCircleIcon className="w-5 h-5" />
    }
  }

  const getTypeIcon = (type: string) => {
    switch (type?.toLowerCase()) {
      case 'url':
        return <LinkIcon className="w-5 h-5" />
      case 'domain':
        return <GlobeAltIcon className="w-5 h-5" />
      case 'ip':
        return <ServerIcon className="w-5 h-5" />
      case 'hash':
        return <DocumentTextIcon className="w-5 h-5" />
      default:
        return <EyeIcon className="w-5 h-5" />
    }
  }

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    })
  }

  const getVTScoreColor = (malicious: number, total: number) => {
    const ratio = malicious / total
    if (ratio >= 0.7) return 'text-red-400'
    if (ratio >= 0.4) return 'text-orange-400'
    if (ratio >= 0.1) return 'text-yellow-400'
    return 'text-green-400'
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold text-white">Threat Intelligence Lookup</h1>
        <p className="text-white/60 mt-1">Comprehensive IOC analysis and enrichment</p>
      </div>

      {/* Search Form */}
      <div className="glass-bg rounded-2xl p-3 sm:p-4 lg:p-6">
        <form onSubmit={handleLookup} className="space-y-3 sm:space-y-4">
          <div>
            <label className="block text-white font-medium mb-2 text-sm sm:text-base">
              Indicator of Compromise (IOC)
            </label>
            <div className="relative">
              <input
                type="text"
                value={indicator}
                onChange={(e) => setIndicator(e.target.value)}
                placeholder="Enter IP, domain, URL, or hash..."
                className="w-full px-3 sm:px-4 py-2 sm:py-3 pr-10 sm:pr-12 bg-white/10 border border-white/20 rounded-xl text-white placeholder-white/50 focus:outline-none focus:ring-2 focus:ring-blue-500 text-sm sm:text-base"
              />
              <MagnifyingGlassIcon className="absolute right-3 sm:right-4 top-1/2 transform -translate-y-1/2 w-4 h-4 sm:w-5 sm:h-5 text-white/50" />
            </div>
            <p className="text-white/40 text-xs sm:text-sm mt-2">
              Supports IPv4, IPv6, domains, URLs, MD5, SHA1, SHA256 hashes
            </p>
          </div>
          <button
            type="submit"
            disabled={lookupMutation.isPending || !indicator.trim()}
            className="w-full sm:w-auto px-4 sm:px-6 py-2 sm:py-3 bg-blue-500 hover:bg-blue-600 disabled:opacity-50 disabled:cursor-not-allowed text-white rounded-xl transition-colors font-medium text-sm sm:text-base"
          >
            {lookupMutation.isPending ? (
              <>
                <ClockIcon className="w-4 h-4 sm:w-5 sm:h-5 animate-spin inline mr-2" />
                <span className="hidden sm:inline">Analyzing Threat...</span>
                <span className="sm:hidden">Analyzing...</span>
              </>
            ) : (
              <>
                <MagnifyingGlassIcon className="w-4 h-4 sm:w-5 sm:h-5 inline mr-2" />
                <span className="hidden sm:inline">Analyze Threat</span>
                <span className="sm:hidden">Analyze</span>
              </>
            )}
          </button>
        </form>
      </div>

      {/* Enhanced Results Display */}
      {result && (
        <div className="space-y-6">
          {/* Threat Overview */}
          <div className="glass-bg rounded-2xl p-4 sm:p-6">
            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 mb-6">
              <h2 className="text-xl sm:text-2xl font-bold text-white">Threat Analysis Results</h2>
              <div className="flex flex-col sm:flex-row items-start sm:items-center gap-3">
                <button
                  onClick={() => setShowRawData(!showRawData)}
                  className="px-3 py-1 bg-white/10 hover:bg-white/20 text-white text-sm rounded-lg transition-colors"
                >
                  {showRawData ? 'Hide Raw Data' : 'Show Raw Data'}
                </button>
                <div className={clsx(
                  'flex items-center space-x-2 px-3 sm:px-4 py-2 rounded-xl border font-medium',
                  getSeverityColor(result.ioc.severity)
                )}>
                  {getSeverityIcon(result.ioc.severity)}
                  <span className="capitalize">{result.ioc.severity} Risk</span>
                  <span className="text-sm opacity-75">({result.ioc.score}/100)</span>
                </div>
              </div>
            </div>

            {/* IOC Summary */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 sm:gap-6 mb-6">
              <div className="lg:col-span-2">
                <div className="bg-white/5 rounded-xl p-3 sm:p-4">
                  <div className="flex items-center space-x-3 mb-3">
                    {getTypeIcon(result.ioc.type)}
                    <div className="min-w-0 flex-1">
                      <h3 className="text-sm sm:text-base lg:text-lg font-semibold text-white capitalize truncate">{result.ioc.type} Indicator</h3>
                      <p className="text-white/60 text-xs sm:text-sm">Malicious {result.ioc.type.toUpperCase()} detected</p>
                    </div>
                  </div>
                  <div className="bg-black/30 rounded-lg p-2 sm:p-3 mb-4">
                    <code className="text-green-400 text-xs sm:text-sm break-all font-mono">{result.ioc.value}</code>
                  </div>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 sm:gap-4 text-sm">
                    <div className="min-w-0">
                      <span className="text-white/60 text-xs sm:text-sm">First Seen:</span>
                      <div className="text-white font-medium text-xs sm:text-sm truncate">{formatDate(result.ioc.first_seen)}</div>
                    </div>
                    <div className="min-w-0">
                      <span className="text-white/60 text-xs sm:text-sm">Last Seen:</span>
                      <div className="text-white font-medium text-xs sm:text-sm truncate">{formatDate(result.ioc.last_seen)}</div>
                    </div>
                  </div>
                </div>
              </div>

              <div className="space-y-4">
                <div className="bg-white/5 rounded-xl p-4">
                  <h4 className="text-white font-semibold mb-3">Threat Score</h4>
                  <div className="relative">
                    <div className="w-full bg-gray-700 rounded-full h-3">
                      <div 
                        className={clsx(
                          'h-3 rounded-full transition-all duration-1000',
                          result.ioc.score >= 70 ? 'bg-red-500' :
                          result.ioc.score >= 40 ? 'bg-orange-500' :
                          result.ioc.score >= 20 ? 'bg-yellow-500' : 'bg-green-500'
                        )}
                        style={{ width: `${result.ioc.score}%` }}
                      ></div>
                    </div>
                    <div className="text-center mt-2">
                      <span className="text-xl sm:text-2xl font-bold text-white">{result.ioc.score}</span>
                      <span className="text-white/60">/100</span>
                    </div>
                  </div>
                </div>

                <div className="bg-white/5 rounded-xl p-4">
                  <h4 className="text-white font-semibold mb-3">Data Sources</h4>
                  <div className="space-y-2">
                    {result.ioc.sources.map((source, index) => (
                      <div key={index} className="flex items-center justify-between text-sm">
                        <span className="text-white capitalize">{source.name}</span>
                        <a 
                          href={source.ref} 
                          target="_blank" 
                          rel="noopener noreferrer"
                          className="text-blue-400 hover:text-blue-300 transition-colors"
                        >
                          <ArrowTopRightOnSquareIcon className="w-4 h-4" />
                        </a>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* VirusTotal Analysis */}
          {result.ioc.vt && (
            <div className="glass-bg rounded-2xl p-4 sm:p-6">
              <div className="flex flex-col sm:flex-row sm:items-center space-y-3 sm:space-y-0 sm:space-x-3 mb-6">
                <ShieldCheckIcon className="w-6 h-6 text-blue-400" />
                <h3 className="text-lg sm:text-xl font-semibold text-white">VirusTotal Analysis</h3>
                <a 
                  href={result.ioc.vt.permalink} 
                  target="_blank" 
                  rel="noopener noreferrer"
                  className="text-blue-400 hover:text-blue-300 transition-colors ml-auto"
                >
                  <ArrowTopRightOnSquareIcon className="w-5 h-5" />
                </a>
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 sm:gap-6">
                <div className="space-y-4">
                  <div className="bg-white/5 rounded-xl p-4">
                    <h4 className="text-white font-semibold mb-3">Detection Results</h4>
                    <div className="space-y-3">
                      <div className="flex items-center justify-between">
                        <span className="text-red-400 font-medium text-sm sm:text-base">
                          {result.ioc.vt.positives} / {result.ioc.vt.total} Engines
                        </span>
                        <span className={clsx(
                          'font-bold text-lg',
                          getVTScoreColor(result.ioc.vt.positives, result.ioc.vt.total)
                        )}>
                          {((result.ioc.vt.positives / result.ioc.vt.total) * 100).toFixed(1)}%
                        </span>
                      </div>
                      
                      <div className="grid grid-cols-2 gap-2 text-sm">
                        <div className="bg-red-500/20 rounded-lg p-2 text-center">
                          <div className="text-red-400 font-bold">{result.ioc.vt.last_analysis_stats.malicious}</div>
                          <div className="text-red-300 text-xs">Malicious</div>
                        </div>
                        <div className="bg-orange-500/20 rounded-lg p-2 text-center">
                          <div className="text-orange-400 font-bold">{result.ioc.vt.last_analysis_stats.suspicious}</div>
                          <div className="text-orange-300 text-xs">Suspicious</div>
                        </div>
                        <div className="bg-green-500/20 rounded-lg p-2 text-center">
                          <div className="text-green-400 font-bold">{result.ioc.vt.last_analysis_stats.harmless}</div>
                          <div className="text-green-300 text-xs">Harmless</div>
                        </div>
                        <div className="bg-gray-500/20 rounded-lg p-2 text-center">
                          <div className="text-gray-400 font-bold">{result.ioc.vt.last_analysis_stats.undetected}</div>
                          <div className="text-gray-300 text-xs">Undetected</div>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>

                <div className="space-y-4">
                  <div className="bg-white/5 rounded-xl p-4">
                    <h4 className="text-white font-semibold mb-3">Additional Info</h4>
                    <div className="space-y-2 text-sm">
                      <div className="flex justify-between">
                        <span className="text-white/60">Reputation Score:</span>
                        <span className={clsx(
                          'font-medium',
                          result.ioc.vt.reputation < -10 ? 'text-red-400' :
                          result.ioc.vt.reputation < 0 ? 'text-orange-400' :
                          'text-green-400'
                        )}>
                          {result.ioc.vt.reputation}
                        </span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-white/60">Last Analysis:</span>
                        <span className="text-white">{formatDate(result.ioc.vt.last_fetched_at)}</span>
                      </div>
                      {result.ioc.vt.categories.length > 0 && (
                        <div>
                          <span className="text-white/60">Categories:</span>
                          <div className="flex flex-wrap gap-1 mt-1">
                            {result.ioc.vt.categories.map((category, index) => (
                              <span 
                                key={index}
                                className="px-2 py-1 bg-blue-500/20 text-blue-400 text-xs rounded-full"
                              >
                                {category}
                              </span>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* AbuseIPDB Analysis */}
          {result.ioc.abuseipdb && Object.keys(result.ioc.abuseipdb).length > 0 && (
            <div className="glass-bg rounded-2xl p-4 sm:p-6">
              <div className="flex items-center space-x-3 mb-6">
                <ExclamationTriangleIcon className="w-6 h-6 text-orange-400" />
                <h3 className="text-lg sm:text-xl font-semibold text-white">AbuseIPDB Intelligence</h3>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
                <div className="bg-white/5 rounded-xl p-4">
                  <h4 className="text-white font-semibold mb-2">Abuse Confidence</h4>
                  <div className="text-xl sm:text-2xl font-bold text-orange-400">
                    {result.ioc.abuseipdb.abuse_confidence}%
                  </div>
                </div>
                <div className="bg-white/5 rounded-xl p-4">
                  <h4 className="text-white font-semibold mb-2">Location</h4>
                  <div className="text-white">{result.ioc.abuseipdb.country_code}</div>
                  <div className="text-white/60 text-sm">{result.ioc.abuseipdb.usage_type}</div>
                </div>
                <div className="bg-white/5 rounded-xl p-4">
                  <h4 className="text-white font-semibold mb-2">Reports</h4>
                  <div className="text-white">{result.ioc.abuseipdb.total_reports} total</div>
                  <div className="text-white/60 text-sm">{result.ioc.abuseipdb.num_distinct_users} reporters</div>
                </div>
              </div>
            </div>
          )}

          {/* Tags and Classification */}
          <div className="glass-bg rounded-2xl p-3 sm:p-4 lg:p-6">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between mb-4 sm:mb-6">
              <div className="flex items-center space-x-2 sm:space-x-3">
                <TagIcon className="w-5 h-5 sm:w-6 sm:h-6 text-purple-400" />
                <h3 className="text-base sm:text-lg lg:text-xl font-semibold text-white">Threat Classification</h3>
              </div>
            </div>

            {/* Current Tags */}
            <div className="mb-4 sm:mb-6">
              <h4 className="text-white font-medium mb-2 sm:mb-3 text-sm sm:text-base">Current Tags:</h4>
              <div className="flex flex-wrap gap-1 sm:gap-2">
                {result.ioc.tags.length > 0 ? (
                  result.ioc.tags.map((tag, index) => {
                    const isThreatCategory = tag.startsWith('threat:')
                    const isTechnical = ['32-bit', '64-bit', 'elf', 'pe', 'mips', 'x86'].some(tech => tag.toLowerCase().includes(tech))
                    const isMalwareFamily = ['mozi', 'mirai', 'botnet'].some(family => tag.toLowerCase().includes(family))
                    
                    return (
                      <span 
                        key={index}
                        className={clsx(
                          'px-2 sm:px-3 py-1 rounded-full text-xs sm:text-sm font-medium border truncate max-w-full',
                          isThreatCategory ? 'bg-red-500/20 text-red-400 border-red-500/30' :
                          isMalwareFamily ? 'bg-purple-500/20 text-purple-400 border-purple-500/30' :
                          isTechnical ? 'bg-blue-500/20 text-blue-400 border-blue-500/30' :
                          'bg-gray-500/20 text-gray-400 border-gray-500/30'
                        )}
                      >
                        {tag}
                      </span>
                    )
                  })
                ) : (
                  <span className="text-white/60 italic text-sm">No tags assigned</span>
                )}
              </div>
            </div>

            {/* Tag Management */}
            {availableTags && availableTags.length > 0 && (
              <div className="border-t border-white/10 pt-6">
                <h4 className="text-white font-medium mb-3">Apply Additional Tags:</h4>
                <div className="space-y-4">
                  <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-2 max-h-40 overflow-y-auto">
                    {Array.isArray(availableTags) ? availableTags.filter((tag: any) => 
                      !result.ioc.tags.includes(tag.name)
                    ).map((tag: any) => (
                      <label key={tag.id} className="flex items-center space-x-2 cursor-pointer">
                        <input
                          type="checkbox"
                          checked={selectedTags.includes(tag.name)}
                          onChange={(e) => {
                            if (e.target.checked) {
                              setSelectedTags([...selectedTags, tag.name])
                            } else {
                              setSelectedTags(selectedTags.filter(t => t !== tag.name))
                            }
                          }}
                          className="rounded border-white/20 bg-white/10 text-blue-500 focus:ring-2 focus:ring-blue-500"
                        />
                        <span 
                          className="px-2 py-1 rounded text-xs border"
                          style={{ 
                            backgroundColor: `${tag.color}20`,
                            borderColor: `${tag.color}40`,
                            color: tag.color 
                          }}
                        >
                          {tag.name}
                        </span>
                      </label>
                    )) : (
                      (availableTags as any)?.tags?.filter((tag: any) => 
                        !result.ioc.tags.includes(tag.name)
                      ).map((tag: any) => (
                        <label key={tag.id} className="flex items-center space-x-2 cursor-pointer">
                          <input
                            type="checkbox"
                            checked={selectedTags.includes(tag.name)}
                            onChange={(e) => {
                              if (e.target.checked) {
                                setSelectedTags([...selectedTags, tag.name])
                              } else {
                                setSelectedTags(selectedTags.filter(t => t !== tag.name))
                              }
                            }}
                            className="rounded border-white/20 bg-white/10 text-blue-500 focus:ring-2 focus:ring-blue-500"
                          />
                          <span 
                            className="px-2 py-1 rounded text-xs border"
                            style={{ 
                              backgroundColor: `${tag.color}20`,
                              borderColor: `${tag.color}40`,
                              color: tag.color 
                            }}
                          >
                            {tag.name}
                          </span>
                        </label>
                      ))
                    )}
                  </div>
                  
                  {selectedTags.length > 0 && (
                    <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between pt-4 border-t border-white/10 gap-4">
                      <div className="flex flex-wrap gap-1">
                        {selectedTags.map((tag, index) => (
                          <span key={index} className="px-2 py-1 bg-blue-500/20 text-blue-400 text-xs rounded-full">
                            {tag}
                          </span>
                        ))}
                      </div>
                      <button
                        onClick={handleApplyTags}
                        disabled={tagMutation.isPending}
                        className="px-4 py-2 bg-purple-500 hover:bg-purple-600 disabled:opacity-50 text-white rounded-lg transition-colors whitespace-nowrap"
                      >
                        {tagMutation.isPending ? 'Applying...' : `Apply ${selectedTags.length} Tags`}
                      </button>
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>

          {/* Raw Data Toggle */}
          {showRawData && (
            <div className="glass-bg rounded-2xl p-3 sm:p-4 lg:p-6">
              <h3 className="text-lg sm:text-xl font-semibold text-white mb-3 sm:mb-4">Raw API Response</h3>
              <div className="bg-black/30 rounded-lg p-3 sm:p-4 overflow-auto max-h-96">
                <pre className="text-white/80 text-xs sm:text-sm whitespace-pre-wrap break-words">
                  {JSON.stringify(result, null, 2)}
                </pre>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

export default LookupPage