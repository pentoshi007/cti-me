import { useState, useEffect } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import {
  ShieldCheckIcon,
  ExclamationTriangleIcon,
  ClockIcon,
  TagIcon,
  ArrowTrendingUpIcon,
  ArrowTrendingDownIcon,
  EyeIcon,
  MagnifyingGlassIcon,
  FunnelIcon,
  GlobeAltIcon,
  UsersIcon,
  BellIcon,
  FireIcon,
  ChartBarIcon,
  PlayIcon,
  StopIcon,
  ArrowPathIcon,
  HashtagIcon,
  LinkIcon,
  DocumentTextIcon,
  CalendarDaysIcon,
  MapPinIcon,
  ExclamationCircleIcon,
  CheckCircleIcon,
  XMarkIcon,
  TrophyIcon
} from '@heroicons/react/24/outline'
import { api } from '../lib/api.ts'
import { PieChart, Pie, Cell, LineChart, Line, XAxis, YAxis, ResponsiveContainer, Tooltip, BarChart, Bar, Area, AreaChart } from 'recharts'
import toast from 'react-hot-toast'

const DashboardPage = () => {
  const navigate = useNavigate()
  
  // State for interactivity
  const [selectedSeverity, setSelectedSeverity] = useState<string | null>(null)
  const [selectedTag, setSelectedTag] = useState<string | null>(null)
  const [searchQuery, setSearchQuery] = useState('')
  const [activeFilters, setActiveFilters] = useState<string[]>([])
  const [alertsVisible, setAlertsVisible] = useState(true)
  const [refreshing, setRefreshing] = useState(false)

  // Fetch overview metrics (reduced frequency to avoid rate limiting)
  const { data: overviewData, isLoading: overviewLoading, refetch: refetchOverview } = useQuery({
    queryKey: ['metrics', 'overview'],
    queryFn: () => api.metrics.overview().then(res => res.data),
    refetchInterval: 120000, // Reduced to 2 minutes to avoid rate limiting
    retry: 2,
    retryDelay: 5000,
    // Add fallback data to prevent crashes
    placeholderData: { total_iocs: 0, severity_counts: {}, recent_iocs_24h: 0, top_tags: [] }
  })

  // Fetch time series data (reduced frequency to avoid rate limiting)
  const { data: timeseriesData, isLoading: timeseriesLoading } = useQuery({
    queryKey: ['metrics', 'timeseries'],
    queryFn: () => api.metrics.timeSeries().then(res => res.data),
    refetchInterval: 180000, // Reduced to 3 minutes to avoid rate limiting
    retry: 2,
    retryDelay: 5000,
    onError: (error) => {
      console.warn('Failed to fetch timeseries metrics:', error)
    }
  })

  // Fetch recent IOCs for activity feed (reduced frequency to avoid rate limiting)
  const { data: recentIOCs, isLoading: iocsLoading, error: iocsError } = useQuery({
    queryKey: ['iocs', 'recent'],
    queryFn: () => api.iocs.list({ per_page: 10, sort: 'created_at:desc' }).then(res => res.data),
    refetchInterval: 120000, // Reduced to 2 minutes to avoid issues
    retry: 1, // Reduce retry attempts 
    retryDelay: 10000, // Longer delay between retries
    // Add fallback data to prevent crashes
    placeholderData: { iocs: [], total: 0 }
  })

  // Fetch tags for tag cloud (reduced frequency)
  const { data: tagsData } = useQuery({
    queryKey: ['tags'],
    queryFn: () => api.tags.list().then(res => res.data),
    refetchInterval: 300000, // 5 minutes - tags don't change frequently
    retry: 2,
    retryDelay: 5000,
    staleTime: 180000, // Consider data fresh for 3 minutes
  })

  const severityColors = {
    critical: '#dc2626',
    high: '#ef4444',
    medium: '#f59e0b',
    low: '#10b981',
    info: '#3b82f6',
  }

  const formatNumber = (num: number) => {
    if (num >= 1000000) return `${(num / 1000000).toFixed(1)}M`
    if (num >= 1000) return `${(num / 1000).toFixed(1)}K`
    return num.toString()
  }

  const formatTimeAgo = (dateString: string) => {
    const date = new Date(dateString)
    const now = new Date()
    const diffMs = now.getTime() - date.getTime()
    const diffMins = Math.floor(diffMs / 60000)
    const diffHours = Math.floor(diffMins / 60)
    const diffDays = Math.floor(diffHours / 24)

    if (diffMins < 1) return 'Just now'
    if (diffMins < 60) return `${diffMins}m ago`
    if (diffHours < 24) return `${diffHours}h ago`
    return `${diffDays}d ago`
  }

  const handleRefresh = async () => {
    setRefreshing(true)
    try {
      await Promise.all([refetchOverview()])
      toast.success('Dashboard refreshed')
    } catch (error) {
      toast.error('Failed to refresh dashboard')
    } finally {
      setRefreshing(false)
    }
  }

  const handleTagClick = (tagName: string) => {
    navigate(`/iocs?tags=${encodeURIComponent(tagName)}`)
  }

  const handleSeverityClick = (severity: string) => {
    navigate(`/iocs?severity=${severity}`)
  }

  const handleIOCClick = (iocId: string) => {
    navigate(`/iocs/${iocId}`)
  }

  const handleQuickSearch = () => {
    if (searchQuery.trim()) {
      navigate(`/iocs?q=${encodeURIComponent(searchQuery)}`)
    }
  }

  const addFilter = (filter: string) => {
    if (!activeFilters.includes(filter)) {
      setActiveFilters([...activeFilters, filter])
    }
  }

  const removeFilter = (filter: string) => {
    setActiveFilters(activeFilters.filter(f => f !== filter))
  }

  // Interactive KPI Card with click actions
  const InteractiveKPICard = ({ 
    title, 
    value, 
    icon: Icon, 
    trend, 
    trendValue, 
    color = 'blue',
    onClick,
    subtitle
  }: any) => (
    <div 
      className={`glass-bg rounded-2xl p-3 sm:p-4 lg:p-6 glass-card transition-all duration-200 ${
        onClick ? 'cursor-pointer hover:scale-105 hover:shadow-xl hover:bg-white/5' : ''
      }`}
      onClick={onClick}
    >
      <div className="flex items-center justify-between">
        <div className="flex-1">
          <p className="text-white/60 text-sm font-medium">{title}</p>
          <p className="text-2xl font-bold text-white mt-1">{formatNumber(value || 0)}</p>
          {subtitle && (
            <p className="text-white/40 text-xs mt-1">{subtitle}</p>
          )}
          {trend && (
            <div className="flex items-center mt-2 text-sm">
              {trend === 'up' ? (
                <ArrowTrendingUpIcon className="w-4 h-4 text-green-400 mr-1" />
              ) : (
                <ArrowTrendingDownIcon className="w-4 h-4 text-red-400 mr-1" />
              )}
              <span className={trend === 'up' ? 'text-green-400' : 'text-red-400'}>
                {trendValue}% vs last week
              </span>
            </div>
          )}
        </div>
        <div className={`p-3 rounded-xl bg-${color}-500/20 ${onClick ? 'group-hover:bg-${color}-500/30' : ''}`}>
          <Icon className={`w-6 h-6 text-${color}-400`} />
        </div>
      </div>
    </div>
  )

  if (overviewLoading) {
    return (
      <div className="space-y-6">
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-6">
          {[...Array(5)].map((_, i) => (
            <div key={i} className="glass-bg rounded-2xl p-3 sm:p-4 lg:p-6 animate-pulse">
              <div className="h-4 bg-white/20 rounded mb-4"></div>
              <div className="h-8 bg-white/20 rounded mb-2"></div>
              <div className="h-3 bg-white/20 rounded w-24"></div>
            </div>
          ))}
        </div>
      </div>
    )
  }

  // Prepare charts data with interactivity
  const severityData = overviewData?.severity_counts ? 
    Object.entries(overviewData.severity_counts).map(([severity, count]) => ({
      name: severity,
      value: count,
      color: severityColors[severity as keyof typeof severityColors] || '#6b7280'
    })) : []

  const chartData = timeseriesData?.datasets?.[0]?.data?.map((value: number, index: number) => ({
    date: timeseriesData.labels[index],
    iocs: value
  })) || []

  return (
    <div className="space-y-6">
      {/* Modern Header with Search and Actions */}
      <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold text-white flex items-center gap-3">
            <div className="p-2 bg-gradient-to-br from-blue-500/20 to-purple-600/20 rounded-xl border border-blue-500/30">
              <ChartBarIcon className="w-8 h-8 text-blue-400" />
            </div>
            Threat Intelligence Dashboard
          </h1>
          <p className="text-white/60 mt-1">Real-time cybersecurity intelligence and analytics</p>
        </div>
        
        <div className="flex flex-col sm:flex-row items-start sm:items-center gap-3">
          {/* Quick Search */}
          <div className="flex items-center gap-2">
            <div className="relative">
              <input
                type="text"
                placeholder="Search IOCs, IPs, domains..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                onKeyPress={(e) => e.key === 'Enter' && handleQuickSearch()}
                className="pl-10 pr-4 py-2 bg-white/10 border border-white/20 rounded-lg text-white placeholder-white/50 focus:outline-none focus:ring-2 focus:ring-blue-500 w-64"
              />
              <MagnifyingGlassIcon className="w-5 h-5 text-white/50 absolute left-3 top-1/2 transform -translate-y-1/2" />
            </div>
            <button
              onClick={handleQuickSearch}
              className="px-4 py-2 bg-blue-500 hover:bg-blue-600 text-white rounded-lg transition-colors"
            >
              Search
            </button>
          </div>
          
          {/* Refresh Button */}
          <button
            onClick={handleRefresh}
            disabled={refreshing}
            className="flex items-center gap-2 px-4 py-2 glass-bg rounded-lg text-white/80 hover:text-white transition-colors disabled:opacity-50"
          >
            <ArrowPathIcon className={`w-4 h-4 ${refreshing ? 'animate-spin' : ''}`} />
            Refresh
          </button>
          
          {/* Live Status */}
          <div className="flex items-center gap-2 px-3 py-2 glass-bg rounded-lg">
            <div className="w-2 h-2 bg-green-400 rounded-full animate-pulse"></div>
            <span className="text-white/80 text-sm">Live</span>
          </div>
        </div>
      </div>

      {/* Active Filters */}
      {activeFilters.length > 0 && (
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-white/60 text-sm">Active Filters:</span>
          {activeFilters.map((filter) => (
            <div key={filter} className="flex items-center gap-1 px-3 py-1 bg-blue-500/20 text-blue-300 rounded-full text-sm">
              {filter}
              <button onClick={() => removeFilter(filter)}>
                <XMarkIcon className="w-4 h-4" />
              </button>
            </div>
          ))}
        </div>
      )}

      {/* Interactive KPI Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
        <InteractiveKPICard
          title="Total IOCs"
          value={overviewData?.total_iocs}
          subtitle="All indicators"
          icon={ShieldCheckIcon}
          color="blue"
          onClick={() => navigate('/iocs')}
        />
        <InteractiveKPICard
          title="Critical Threats"
          value={overviewData?.severity_counts?.critical}
          subtitle="Immediate action"
          icon={ExclamationTriangleIcon}
          color="red"
          onClick={() => handleSeverityClick('critical')}
        />
        <InteractiveKPICard
          title="Last 24 Hours"
          value={overviewData?.recent_iocs_24h}
          subtitle="New indicators"
          icon={ClockIcon}
          trend="up"
          trendValue="12"
          color="green"
          onClick={() => navigate('/iocs?timeframe=24h')}
        />
        <InteractiveKPICard
          title="Active Tags"
          value={overviewData?.top_tags?.length}
          subtitle="Categories"
          icon={TagIcon}
          color="purple"
          onClick={() => navigate('/tags')}
        />
        <InteractiveKPICard
          title="Threat Actors"
          value={15}
          subtitle="Known groups"
          icon={UsersIcon}
          color="yellow"
          onClick={() => addFilter('threat-actors')}
        />
      </div>

      {/* Dynamic Real-time Alerts */}
      {alertsVisible && (() => {
        // Calculate critical IOCs in last hour dynamically
        const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000)
        const recentCriticalIOCs = recentIOCs?.iocs?.filter((ioc: any) => 
          ioc.severity === 'critical' && new Date(ioc.created_at) > oneHourAgo
        ) || []
        
        const criticalCount = recentCriticalIOCs.length
        
        // Only show alert if there are actual critical IOCs
        return criticalCount > 0 ? (
          <div className="glass-bg rounded-2xl p-4 border-l-4 border-red-500">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="p-2 bg-red-500/20 rounded-lg">
                  <ExclamationCircleIcon className="w-5 h-5 text-red-400" />
                </div>
                <div>
                  <h3 className="text-white font-semibold">High Priority Alert</h3>
                  <p className="text-white/60 text-sm">
                    {criticalCount} critical IOC{criticalCount !== 1 ? 's' : ''} detected in the last hour
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <button 
                  onClick={() => navigate('/iocs?severity=critical')}
                  className="px-3 py-1 bg-red-500 hover:bg-red-600 text-white rounded-lg text-sm transition-colors"
                >
                  Investigate ({criticalCount})
                </button>
                <button onClick={() => setAlertsVisible(false)}>
                  <XMarkIcon className="w-5 h-5 text-white/50 hover:text-white/70" />
                </button>
              </div>
            </div>
          </div>
        ) : null
      })()}

      {/* Main Dashboard Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column - Charts */}
        <div className="lg:col-span-2 space-y-6">
          {/* Interactive Severity Chart */}
        <div className="glass-bg rounded-2xl p-6">
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-xl font-semibold text-white">Threat Severity Distribution</h2>
              <div className="flex items-center gap-2">
                <FunnelIcon className="w-5 h-5 text-white/60" />
                <span className="text-white/60 text-sm">Click to filter</span>
              </div>
            </div>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={severityData}
                  cx="50%"
                  cy="50%"
                  innerRadius={50}
                  outerRadius={90}
                  paddingAngle={2}
                  dataKey="value"
                    onClick={(data) => handleSeverityClick(data.name)}
                    className="cursor-pointer"
                >
                  {severityData.map((entry, index) => (
                      <Cell 
                        key={`cell-${index}`} 
                        fill={entry.color}
                        className="hover:opacity-80 transition-opacity"
                      />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{
                    backgroundColor: 'rgba(0, 0, 0, 0.9)',
                    border: '1px solid rgba(255, 255, 255, 0.2)',
                    borderRadius: '12px',
                    color: 'white',
                    boxShadow: '0 10px 40px rgba(0, 0, 0, 0.5)'
                  }}
                  labelStyle={{
                    color: 'white'
                  }}
                  itemStyle={{
                    color: 'white'
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
          <div className="mt-4 grid grid-cols-2 gap-2">
            {severityData.map((item) => (
                <button
                  key={item.name}
                  onClick={() => handleSeverityClick(item.name)}
                  className="flex items-center space-x-2 p-2 rounded-lg hover:bg-white/5 transition-colors text-left"
                >
                <div
                  className="w-3 h-3 rounded-full"
                  style={{ backgroundColor: item.color }}
                ></div>
                  <span className="text-sm text-white/70 capitalize flex-1">
                  {item.name}: {item.value}
                </span>
                  <EyeIcon className="w-4 h-4 text-white/50" />
                </button>
            ))}
          </div>
        </div>

          {/* Activity Trends */}
        <div className="glass-bg rounded-2xl p-6">
            <h2 className="text-xl font-semibold text-white mb-6">IOC Activity Trends</h2>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={chartData}>
                  <defs>
                    <linearGradient id="colorIOCs" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3}/>
                      <stop offset="95%" stopColor="#3b82f6" stopOpacity={0}/>
                    </linearGradient>
                  </defs>
                <XAxis 
                  dataKey="date" 
                  axisLine={false}
                  tickLine={false}
                  tick={{ fill: 'rgba(255, 255, 255, 0.6)', fontSize: 12 }}
                />
                <YAxis 
                  axisLine={false}
                  tickLine={false}
                  tick={{ fill: 'rgba(255, 255, 255, 0.6)', fontSize: 12 }}
                />
                <Tooltip
                  contentStyle={{
                      backgroundColor: 'rgba(0, 0, 0, 0.9)',
                    border: '1px solid rgba(255, 255, 255, 0.2)',
                      borderRadius: '12px',
                    color: 'white'
                  }}
                />
                  <Area
                  type="monotone"
                  dataKey="iocs"
                  stroke="#3b82f6"
                  strokeWidth={2}
                    fillOpacity={1}
                    fill="url(#colorIOCs)"
                />
                </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

        {/* Right Column - Activity Feed */}
        <div className="space-y-6">
          {/* Live Activity & Top IOCs */}
        <div className="glass-bg rounded-2xl p-6">
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-xl font-semibold text-white">Live Activity & Top IOCs</h2>
              <div className="flex items-center gap-2">
                <div className="w-2 h-2 bg-green-400 rounded-full animate-pulse"></div>
                <span className="text-green-400 text-sm">Real-time</span>
              </div>
            </div>
            
            {/* Top Threat IOCs Section */}
            <div className="mb-6">
              <h4 className="text-white/80 text-sm font-semibold mb-3 flex items-center gap-2">
                <TrophyIcon className="w-4 h-4 text-yellow-400" />
                Top Threat IOCs
              </h4>
              <div className="grid grid-cols-1 gap-2">
                {(() => {
                  const topIOCs = recentIOCs?.iocs
                    ?.filter((ioc: any) => ioc.score >= 70)
                    ?.sort((a: any, b: any) => b.score - a.score)
                    ?.slice(0, 3) || []
                  
                  if (topIOCs.length === 0) {
                    return (
                      <div className="text-white/50 text-sm italic py-2">No high-threat IOCs currently</div>
                    )
                  }
                  
                  return topIOCs.map((ioc: any, index: number) => (
                    <div 
                      key={ioc.id}
                      onClick={() => handleIOCClick(ioc.id)}
                      className="flex items-center gap-3 p-3 bg-gradient-to-r from-red-500/20 to-orange-500/20 rounded-lg hover:from-red-500/30 hover:to-orange-500/30 transition-all cursor-pointer group border border-red-500/30"
                    >
                      <div className="flex items-center gap-2">
                        <div className="text-yellow-400 font-bold text-sm">#{index + 1}</div>
                        <div className={`w-2 h-2 rounded-full ${
                          ioc.severity === 'critical' ? 'bg-red-500' :
                          ioc.severity === 'high' ? 'bg-orange-500' :
                          'bg-yellow-500'
                        }`}></div>
                      </div>
                      <div className="flex-1">
                        <div className="text-white text-sm font-medium group-hover:text-red-300 transition-colors truncate">
                          {ioc.type?.toUpperCase()}: {ioc.value?.length > 30 ? ioc.value.substring(0, 30) + '...' : ioc.value}
                        </div>
                        <div className="text-white/60 text-xs flex items-center gap-2">
                          <span>Score: {ioc.score}</span>
                          <span>•</span>
                          <span className={`${
                            ioc.severity === 'critical' ? 'text-red-400' :
                            ioc.severity === 'high' ? 'text-orange-400' :
                            'text-yellow-400'
                          }`}>
                            {ioc.severity?.toUpperCase()}
                          </span>
                        </div>
                      </div>
                      <ExclamationTriangleIcon className="w-4 h-4 text-red-400 group-hover:text-red-300" />
                    </div>
                  ))
                })()}
              </div>
            </div>

              {/* Recent Activity */}
            <div>
              <h4 className="text-white/80 text-sm font-semibold mb-3 flex items-center gap-2">
                <ClockIcon className="w-4 h-4 text-blue-400" />
                Recent Activity
              </h4>
              <div className="space-y-2 max-h-80 overflow-y-auto">
                {iocsLoading ? (
                  <div className="text-center py-4">
                    <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-white mx-auto"></div>
                    <p className="text-white/60 text-sm mt-2">Loading recent activity...</p>
                  </div>
                ) : iocsError ? (
                  <div className="text-center py-4">
                    <p className="text-white/60 text-sm">Unable to load recent activity</p>
                    <button 
                      onClick={() => window.location.reload()}
                      className="text-blue-400 hover:text-blue-300 text-sm mt-2"
                    >
                      Refresh page
                    </button>
                  </div>
                ) : (!recentIOCs?.iocs || recentIOCs.iocs.length === 0) ? (
                  <div className="text-center py-4">
                    <p className="text-white/60 text-sm">No recent activity</p>
                  </div>
                ) : recentIOCs.iocs.slice(0, 6).map((ioc: any) => (
                  <div 
                    key={ioc.id}
                    onClick={() => handleIOCClick(ioc.id)}
                    className="flex items-center gap-3 p-3 bg-white/5 rounded-lg hover:bg-white/10 transition-colors cursor-pointer group"
                  >
                    <div className={`w-3 h-3 rounded-full ${
                      ioc.severity === 'critical' ? 'bg-red-500' :
                      ioc.severity === 'high' ? 'bg-orange-500' :
                      ioc.severity === 'medium' ? 'bg-yellow-500' :
                      'bg-green-500'
                    }`}></div>
                    <div className="flex-1">
                      <div className="text-white text-sm font-medium group-hover:text-blue-300 transition-colors truncate">
                        {ioc.type?.toUpperCase()}: {ioc.value?.length > 35 ? ioc.value.substring(0, 35) + '...' : ioc.value}
                      </div>
                      <div className="text-white/60 text-xs">
                        {formatTimeAgo(ioc.created_at)} • Score: {ioc.score}
                      </div>
                </div>
                    <EyeIcon className="w-4 h-4 text-white/40 group-hover:text-white/60" />
              </div>
            ))}
          </div>
        </div>

            <div className="mt-4 pt-4 border-t border-white/10">
              <button 
                onClick={() => navigate('/iocs')}
                className="w-full py-2 text-blue-400 hover:text-blue-300 text-sm font-medium transition-colors"
              >
                View All Activity →
              </button>
            </div>
          </div>

          {/* Quick Actions */}
          <div className="glass-bg rounded-2xl p-6">
            <h3 className="text-lg font-semibold text-white mb-4">Quick Actions</h3>
            <div className="grid grid-cols-2 gap-3">
              <button 
                onClick={() => navigate('/lookup')}
                className="p-3 bg-blue-500/20 hover:bg-blue-500/30 text-blue-300 rounded-lg transition-colors text-sm font-medium"
              >
                <MagnifyingGlassIcon className="w-5 h-5 mx-auto mb-1" />
                Lookup IOC
              </button>
              <button 
                onClick={() => navigate('/iocs?severity=critical')}
                className="p-3 bg-red-500/20 hover:bg-red-500/30 text-red-300 rounded-lg transition-colors text-sm font-medium"
              >
                <FireIcon className="w-5 h-5 mx-auto mb-1" />
                Critical IOCs
              </button>
              <button 
                onClick={() => navigate('/tags')}
                className="p-3 bg-purple-500/20 hover:bg-purple-500/30 text-purple-300 rounded-lg transition-colors text-sm font-medium"
              >
                <HashtagIcon className="w-5 h-5 mx-auto mb-1" />
                Manage Tags
              </button>
              <button 
                onClick={() => navigate('/exports')}
                className="p-3 bg-green-500/20 hover:bg-green-500/30 text-green-300 rounded-lg transition-colors text-sm font-medium"
              >
                <DocumentTextIcon className="w-5 h-5 mx-auto mb-1" />
                Export Data
              </button>
          </div>
        </div>

          {/* Interactive Tag Cloud */}
        <div className="glass-bg rounded-2xl p-6">
            <h3 className="text-lg font-semibold text-white mb-4">Popular Tags</h3>
            <div className="flex flex-wrap gap-2">
              {overviewData?.top_tags?.slice(0, 10).map((tag: any) => (
                <button
                  key={tag.name}
                  onClick={() => handleTagClick(tag.name)}
                  className="px-3 py-1 bg-white/10 hover:bg-white/20 text-white/80 hover:text-white rounded-full text-sm transition-colors"
                >
                  #{tag.name} ({tag.count})
                </button>
              ))}
                  </div>
            <div className="mt-4 pt-4 border-t border-white/10">
              <button 
                onClick={() => navigate('/tags')}
                className="text-purple-400 hover:text-purple-300 text-sm font-medium transition-colors"
              >
                Manage All Tags →
              </button>
              </div>
          </div>
        </div>
      </div>
    </div>
  )
}

export default DashboardPage
