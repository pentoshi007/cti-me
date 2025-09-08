import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useState, useEffect } from 'react'
import { 
  PlayIcon, 
  ArrowPathIcon, 
  ServerIcon, 
  ChartBarIcon,
  ClockIcon,
  UserGroupIcon,
  ExclamationTriangleIcon,
  CheckCircleIcon,
  XCircleIcon
} from '@heroicons/react/24/outline'
import { api } from '../lib/api'
import UserManagement from '../components/UserManagement'
import toast from 'react-hot-toast'

const AdminPage = () => {
  const queryClient = useQueryClient()
  const [refreshInterval] = useState(30000) // 30 seconds
  const [lastRefresh, setLastRefresh] = useState(new Date())

  const { data: systemStats } = useQuery({
    queryKey: ['admin', 'stats'],
    queryFn: () => api.admin.getSystemStats().then(res => res.data),
    refetchInterval: refreshInterval,
  })

  const { data: ingestRuns, isLoading: runsLoading } = useQuery({
    queryKey: ['admin', 'ingest-runs'],
    queryFn: () => api.admin.getIngestRuns().then(res => res.data),
    refetchInterval: refreshInterval,
  })

  // Use new combined runs endpoint
  const { data: allRuns, isLoading: allRunsLoading } = useQuery({
    queryKey: ['admin', 'all-runs'],
    queryFn: () => api.admin.getAllRuns().then(res => res.data),
    refetchInterval: refreshInterval,
  })

  // Auto-run check
  const { data: autoRunStatus } = useQuery({
    queryKey: ['admin', 'auto-run-check'],
    queryFn: () => api.admin.checkAutoRun().then(res => res.data),
    refetchInterval: 60000, // Check every minute
  })

  const { data: users } = useQuery({
    queryKey: ['admin', 'users'],
    queryFn: () => api.admin.getUsers().then(res => res.data),
    refetchInterval: 60000, // 1 minute
  })

  // Update last refresh time
  useEffect(() => {
    const interval = setInterval(() => {
      setLastRefresh(new Date())
    }, 1000)
    return () => clearInterval(interval)
  }, [])

  const triggerIngestMutation = useMutation({
    mutationFn: (source: string = 'urlhaus') => api.admin.triggerIngest(source),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['admin', 'ingest-runs'] })
      queryClient.invalidateQueries({ queryKey: ['admin', 'stats'] })
      toast.success('URLHaus ingestion started successfully')
      // Show ingestion stats if available
      if (data?.data?.stats) {
        setTimeout(() => {
          toast.success(`Ingested ${data.data.stats.new_count} new IOCs, updated ${data.data.stats.updated_count} existing`)
        }, 2000)
      }
    },
    onError: (error: any) => {
      toast.error(error.response?.data?.message || 'Failed to trigger ingestion')
    }
  })

  const triggerEnrichmentMutation = useMutation({
    mutationFn: () => api.admin.triggerEnrichment(),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['admin', 'stats'] })
      toast.success('Bulk enrichment started successfully')
      toast('Check the logs for enrichment progress', { 
        duration: 5000,
        icon: 'ℹ️'
      })
    },
    onError: (error: any) => {
      toast.error(error.response?.data?.message || 'Failed to trigger enrichment')
    }
  })

  const formatBytes = (bytes: number) => {
    if (bytes === 0) return '0 Bytes'
    const k = 1024
    const sizes = ['Bytes', 'KB', 'MB', 'GB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'completed':
        return 'bg-green-500/20 text-green-400 border-green-500/30'
      case 'running':
        return 'bg-blue-500/20 text-blue-400 border-blue-500/30'
      case 'failed':
        return 'bg-red-500/20 text-red-400 border-red-500/30'
      default:
        return 'bg-gray-500/20 text-gray-400 border-gray-500/30'
    }
  }

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'completed':
        return <CheckCircleIcon className="w-4 h-4" />
      case 'running':
        return <ClockIcon className="w-4 h-4 animate-spin" />
      case 'failed':
        return <XCircleIcon className="w-4 h-4" />
      default:
        return <ClockIcon className="w-4 h-4" />
    }
  }

  return (
    <div className="space-y-6">
      {/* Header with live status */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white">Administration</h1>
          <p className="text-white/60 mt-1">System management and monitoring</p>
        </div>
        <div className="text-right">
          <div className="flex items-center space-x-2 text-white/60 text-sm">
            <div className="w-2 h-2 bg-green-400 rounded-full animate-pulse"></div>
            <span>Live updates every {refreshInterval / 1000}s</span>
          </div>
          <div className="text-white/40 text-xs mt-1">
            Last refresh: {lastRefresh.toLocaleTimeString()}
          </div>
        </div>
      </div>

      {/* System Health Overview */}
      <div className="glass-bg rounded-2xl p-6">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-xl font-semibold text-white">System Health</h2>
          <div className="flex items-center space-x-2">
            <div className="w-3 h-3 bg-green-400 rounded-full animate-pulse"></div>
            <span className="text-green-400 text-sm font-medium">Operational</span>
          </div>
        </div>
        
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="bg-white/5 rounded-xl p-4">
            <div className="flex items-center space-x-3">
              <ServerIcon className="w-6 h-6 text-blue-400" />
              <div>
                <p className="text-white/60 text-sm">Database Size</p>
                <p className="text-lg font-bold text-white">
                  {formatBytes(systemStats?.database_stats?.dataSize || 0)}
                </p>
              </div>
            </div>
          </div>

          <div className="bg-white/5 rounded-xl p-4">
            <div className="flex items-center space-x-3">
              <ChartBarIcon className="w-6 h-6 text-green-400" />
              <div>
                <p className="text-white/60 text-sm">Total IOCs</p>
                <p className="text-lg font-bold text-white">
                  {systemStats?.collection_counts?.indicators || 0}
                </p>
              </div>
            </div>
          </div>

          <div className="bg-white/5 rounded-xl p-4">
            <div className="flex items-center space-x-3">
              <UserGroupIcon className="w-6 h-6 text-purple-400" />
              <div>
                <p className="text-white/60 text-sm">Active Users</p>
                <p className="text-lg font-bold text-white">
                  {users?.length || 0}
                </p>
              </div>
            </div>
          </div>

          <div className="bg-white/5 rounded-xl p-4">
            <div className="flex items-center space-x-3">
              <ClockIcon className="w-6 h-6 text-yellow-400" />
              <div>
                <p className="text-white/60 text-sm">Recent Activity</p>
                <p className="text-lg font-bold text-white">
                  {systemStats?.recent_activity?.lookups || 0}
                </p>
                <p className="text-xs text-white/40">lookups (24h)</p>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Manual Operations */}
      <div className="glass-bg rounded-2xl p-6">
        <h2 className="text-xl font-semibold text-white mb-6">Manual Operations</h2>
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="space-y-4">
            <button
              onClick={() => triggerIngestMutation.mutate('urlhaus')}
              disabled={triggerIngestMutation.isPending}
              className="w-full flex items-center space-x-4 p-6 bg-blue-500/20 hover:bg-blue-500/30 border border-blue-500/30 rounded-xl transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed group"
            >
              <div className="flex-shrink-0">
                <PlayIcon className={`w-6 h-6 text-blue-400 transition-transform ${
                  triggerIngestMutation.isPending ? 'animate-pulse' : 'group-hover:scale-110'
                }`} />
              </div>
              <div className="text-left flex-1">
                <div className="text-white font-semibold text-lg">URLHaus Data Ingestion</div>
                <div className="text-blue-200 text-sm mt-1">
                  {triggerIngestMutation.isPending 
                    ? 'Fetching latest threat indicators...' 
                    : 'Manually fetch latest malware URLs and threat data'
                  }
                </div>
                <div className="text-blue-300/60 text-xs mt-2">
                  ⚡ Typically processes 1000+ new IOCs
                </div>
              </div>
            </button>

            <button
              onClick={() => triggerEnrichmentMutation.mutate()}
              disabled={triggerEnrichmentMutation.isPending}
              className="w-full flex items-center space-x-4 p-6 bg-green-500/20 hover:bg-green-500/30 border border-green-500/30 rounded-xl transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed group"
            >
              <div className="flex-shrink-0">
                <ArrowPathIcon className={`w-6 h-6 text-green-400 transition-transform ${
                  triggerEnrichmentMutation.isPending ? 'animate-spin' : 'group-hover:scale-110'
                }`} />
              </div>
              <div className="text-left flex-1">
                <div className="text-white font-semibold text-lg">Bulk IOC Enrichment</div>
                <div className="text-green-200 text-sm mt-1">
                  {triggerEnrichmentMutation.isPending 
                    ? 'Enriching IOCs with external intelligence...' 
                    : 'Enrich recent IOCs with VirusTotal & AbuseIPDB data'
                  }
                </div>
                <div className="text-green-300/60 text-xs mt-2">
                  🎯 Updates threat scores and severity levels
                </div>
              </div>
            </button>
          </div>

          <div className="bg-white/5 rounded-xl p-6">
            <h3 className="text-white font-semibold mb-4">Operation Status</h3>
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-white/70 text-sm">URLHaus Ingestion</span>
                <div className="flex items-center space-x-2">
                  {triggerIngestMutation.isPending ? (
                    <>
                      <ClockIcon className="w-4 h-4 text-yellow-400 animate-spin" />
                      <span className="text-yellow-400 text-sm">Running</span>
                    </>
                  ) : (
                    <>
                      <CheckCircleIcon className="w-4 h-4 text-green-400" />
                      <span className="text-green-400 text-sm">Ready</span>
                    </>
                  )}
                </div>
              </div>
              
              <div className="flex items-center justify-between">
                <span className="text-white/70 text-sm">Bulk Enrichment</span>
                <div className="flex items-center space-x-2">
                  {triggerEnrichmentMutation.isPending ? (
                    <>
                      <ClockIcon className="w-4 h-4 text-yellow-400 animate-spin" />
                      <span className="text-yellow-400 text-sm">Running</span>
                    </>
                  ) : (
                    <>
                      <CheckCircleIcon className="w-4 h-4 text-green-400" />
                      <span className="text-green-400 text-sm">Ready</span>
                    </>
                  )}
                </div>
              </div>

              <div className="border-t border-white/10 pt-3 mt-4">
                <div className="text-white/60 text-xs">
                  Last ingestion: {ingestRuns?.[0]?.started_at 
                    ? new Date(ingestRuns[0].started_at).toLocaleString()
                    : 'Never'
                  }
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Collection Stats */}
      {systemStats?.collection_counts && (
        <div className="glass-bg rounded-2xl p-6">
          <h2 className="text-xl font-semibold text-white mb-4">Collection Statistics</h2>
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
            {Object.entries(systemStats.collection_counts).map(([collection, count]) => (
              <div key={collection} className="text-center">
                <div className="text-2xl font-bold text-white">{count as number}</div>
                <div className="text-white/60 text-sm capitalize">{collection}</div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Enhanced Ingestion History with Logs */}
      <div className="glass-bg rounded-2xl p-6">
        <div className="flex items-center justify-between mb-6">
          <h2 className="text-xl font-semibold text-white">Ingestion History & Logs</h2>
          <button
            onClick={() => {
              queryClient.invalidateQueries({ queryKey: ['admin', 'ingest-runs'] })
              toast.success('Refreshed ingestion logs')
            }}
            className="flex items-center space-x-2 px-3 py-1 bg-white/10 hover:bg-white/20 rounded-lg transition-colors"
          >
            <ArrowPathIcon className="w-4 h-4 text-white" />
            <span className="text-white text-sm">Refresh</span>
          </button>
        </div>
        
        {runsLoading ? (
          <div className="flex items-center justify-center py-8">
            <div className="animate-spin w-6 h-6 border-2 border-white/20 border-t-white rounded-full"></div>
            <span className="ml-3 text-white/60">Loading ingestion logs...</span>
          </div>
        ) : (
          <div className="space-y-4">
            {ingestRuns?.length > 0 ? (
              ingestRuns.map((run: any) => (
                <div key={run.id} className="bg-white/5 rounded-xl p-4 border border-white/10">
                  <div className="flex items-center justify-between mb-3">
                    <div className="flex items-center space-x-3">
                      <div className={`flex items-center space-x-2 px-3 py-1 rounded-full border ${getStatusColor(run.status)}`}>
                        {getStatusIcon(run.status)}
                        <span className="text-sm font-medium capitalize">{run.status}</span>
                      </div>
                      <span className="text-white font-semibold">{run.source}</span>
                    </div>
                    <div className="text-white/60 text-sm">
                      {new Date(run.started_at).toLocaleString()}
                    </div>
                  </div>
                  
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-3">
                    <div>
                      <span className="text-white/60 text-xs">New IOCs</span>
                      <div className="text-green-400 font-semibold">{run.new_count || 0}</div>
                    </div>
                    <div>
                      <span className="text-white/60 text-xs">Updated</span>
                      <div className="text-blue-400 font-semibold">{run.updated_count || 0}</div>
                    </div>
                    <div>
                      <span className="text-white/60 text-xs">Total Fetched</span>
                      <div className="text-white font-semibold">{run.fetched_count || 0}</div>
                    </div>
                    <div>
                      <span className="text-white/60 text-xs">Duration</span>
                      <div className="text-white font-semibold">
                        {run.finished_at && run.started_at 
                          ? `${Math.round((new Date(run.finished_at).getTime() - new Date(run.started_at).getTime()) / 1000)}s`
                          : run.status === 'running' ? 'Running...' : 'N/A'
                        }
                      </div>
                    </div>
                  </div>
                  
                  {run.error && (
                    <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-3 mt-3">
                      <div className="flex items-center space-x-2 mb-2">
                        <XCircleIcon className="w-4 h-4 text-red-400" />
                        <span className="text-red-400 font-medium text-sm">Error Details</span>
                      </div>
                      <pre className="text-red-300 text-xs font-mono">{run.error}</pre>
                    </div>
                  )}
                </div>
              ))
            ) : (
              <div className="text-center py-8">
                <ExclamationTriangleIcon className="w-12 h-12 text-white/40 mx-auto mb-3" />
                <p className="text-white/60">No ingestion runs found</p>
                <p className="text-white/40 text-sm">Start your first ingestion above</p>
              </div>
            )}
          </div>
        )}
      </div>

      {/* User Management Section */}
      <UserManagement />
    </div>
  )
}

export default AdminPage
