import { ReactNode, useState } from 'react'
import { Link, useLocation, useNavigate } from 'react-router-dom'
import {
  HomeIcon,
  ShieldCheckIcon,
  MagnifyingGlassIcon,
  TagIcon,
  CogIcon,
  UserCircleIcon,
  SunIcon,
  MoonIcon,
  Bars3Icon,
  XMarkIcon,
} from '@heroicons/react/24/outline'
import { useAuthStore } from '../stores/authStore'
import { useThemeStore } from '../stores/themeStore'
import clsx from 'clsx'

interface LayoutProps {
  children: ReactNode
}

const Layout = ({ children }: LayoutProps) => {
  const location = useLocation()
  const navigate = useNavigate()
  const { user, logout, hasPermission } = useAuthStore()
  const { isDark, toggleTheme } = useThemeStore()
  const [sidebarOpen, setSidebarOpen] = useState(false)

  const navigation = [
    { name: 'Dashboard', href: '/dashboard', icon: HomeIcon, public: true },
    { name: 'IOCs', href: '/iocs', icon: ShieldCheckIcon, public: true },
    { name: 'Lookup', href: '/lookup', icon: MagnifyingGlassIcon, public: true },
    { name: 'Tags', href: '/tags', icon: TagIcon, requireAuth: true },  // Changed to requireAuth instead of permission
    { name: 'Admin', href: '/admin', icon: CogIcon, permission: 'admin' },
  ]

  const handleLogout = () => {
    logout()
    navigate('/login')
  }

  const Sidebar = ({ mobile = false }) => (
    <div className="flex flex-col h-full">
      {/* Logo */}
      <div className="flex items-center justify-between p-4">
        <div className="flex items-center space-x-3">
          <div className="w-8 h-8 bg-gradient-to-br from-blue-500 to-purple-600 rounded-lg flex items-center justify-center">
            <ShieldCheckIcon className="w-5 h-5 text-white" />
          </div>
          <span className="text-xl font-bold text-white">CTI Dashboard</span>
        </div>
        {mobile && (
          <button
            onClick={() => setSidebarOpen(false)}
            className="p-2 rounded-lg text-white hover:bg-white/10 transition-colors"
          >
            <XMarkIcon className="w-6 h-6" />
          </button>
        )}
      </div>

      {/* Navigation */}
      <nav className="flex-1 px-4 space-y-2">
        {navigation.map((item) => {
          // Show public routes for everyone
          if (item.public) {
            // Show for everyone
          } else if (item.requireAuth) {
            // Show only for authenticated users
            if (!user) return null
          } else if (item.permission) {
            // Show only for users with specific permission
            if (!user || !hasPermission(item.permission)) return null
          }

          const isActive = location.pathname === item.href
          return (
            <Link
              key={item.name}
              to={item.href}
              onClick={() => mobile && setSidebarOpen(false)}
              className={clsx(
                'flex items-center space-x-3 px-4 py-3 rounded-xl transition-all duration-200',
                isActive
                  ? 'bg-white/20 text-white shadow-lg'
                  : 'text-white/70 hover:text-white hover:bg-white/10'
              )}
            >
              <item.icon className="w-5 h-5" />
              <span className="font-medium">{item.name}</span>
            </Link>
          )
        })}
      </nav>

      {/* User section */}
      <div className="p-4 border-t border-white/10">
        {user ? (
          // Authenticated user section
          <>
            <div className="flex items-center space-x-3 p-3 rounded-xl bg-white/5">
              <UserCircleIcon className="w-8 h-8 text-white/70" />
              <div className="flex-1 min-w-0">
                <p className="text-sm font-medium text-white truncate">
                  {user?.username}
                </p>
                <p className="text-xs text-white/50 uppercase">
                  {user?.role}
                </p>
              </div>
            </div>
            
            <div className="flex items-center justify-between mt-3">
              <button
                onClick={toggleTheme}
                className="p-2 rounded-lg text-white/70 hover:text-white hover:bg-white/10 transition-colors"
                title={isDark ? 'Switch to light mode' : 'Switch to dark mode'}
              >
                {isDark ? <SunIcon className="w-5 h-5" /> : <MoonIcon className="w-5 h-5" />}
              </button>
              
              <Link
                to="/profile"
                onClick={() => mobile && setSidebarOpen(false)}
                className="px-3 py-2 text-sm text-white/70 hover:text-white hover:bg-white/10 rounded-lg transition-colors"
              >
                Profile
              </Link>
              
              <button
                onClick={handleLogout}
                className="px-4 py-2 text-sm text-white/70 hover:text-white hover:bg-white/10 rounded-lg transition-colors"
              >
                Logout
              </button>
            </div>
          </>
        ) : (
          // Public user section
          <>
            <div className="flex items-center space-x-3 p-3 rounded-xl bg-white/5">
              <UserCircleIcon className="w-8 h-8 text-white/70" />
              <div className="flex-1 min-w-0">
                <p className="text-sm font-medium text-white">
                  Public Access
                </p>
                <p className="text-xs text-white/50">
                  View threat intelligence
                </p>
              </div>
            </div>
            
            <div className="flex items-center justify-between mt-3">
              <button
                onClick={toggleTheme}
                className="p-2 rounded-lg text-white/70 hover:text-white hover:bg-white/10 transition-colors"
                title={isDark ? 'Switch to light mode' : 'Switch to dark mode'}
              >
                {isDark ? <SunIcon className="w-5 h-5" /> : <MoonIcon className="w-5 h-5" />}
              </button>
              
              <Link
                to="/login"
                className="px-4 py-2 text-sm bg-blue-500 hover:bg-blue-600 text-white rounded-lg transition-colors"
              >
                Login
              </Link>
            </div>
          </>
        )}
      </div>
    </div>
  )

  return (
    <div className="h-screen flex">
      {/* Desktop Sidebar */}
      <div className="hidden lg:flex lg:w-64 lg:flex-col">
        <div className="glass-bg rounded-r-2xl m-4 ml-0">
          <Sidebar />
        </div>
      </div>

      {/* Mobile Sidebar */}
      {sidebarOpen && (
        <div className="lg:hidden fixed inset-0 z-50 flex">
          <div className="fixed inset-0 bg-black/20 backdrop-blur-sm" onClick={() => setSidebarOpen(false)} />
          <div className="relative w-64 glass-bg m-4 ml-0 rounded-r-2xl">
            <Sidebar mobile />
          </div>
        </div>
      )}

      {/* Main content */}
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Mobile header */}
        <div className="lg:hidden glass-bg m-4 mb-0 rounded-2xl">
          <div className="flex items-center justify-between p-4">
            <button
              onClick={() => setSidebarOpen(true)}
              className="p-2 rounded-lg text-white hover:bg-white/10 transition-colors"
            >
              <Bars3Icon className="w-6 h-6" />
            </button>
            
            <div className="flex items-center space-x-2">
              <div className="w-6 h-6 bg-gradient-to-br from-blue-500 to-purple-600 rounded-md flex items-center justify-center">
                <ShieldCheckIcon className="w-4 h-4 text-white" />
              </div>
              <span className="font-bold text-white">CTI Dashboard</span>
            </div>
            
            <div className="w-10" /> {/* Spacer */}
          </div>
        </div>

        {/* Page content */}
        <main className="flex-1 overflow-auto p-4">
          {children}
        </main>
      </div>
    </div>
  )
}

export default Layout
