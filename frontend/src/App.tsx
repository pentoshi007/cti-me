import { Routes, Route, Navigate } from 'react-router-dom'
import { useAuthStore } from './stores/authStore'
import { useThemeStore } from './stores/themeStore'
import { useEffect } from 'react'

// Components
import Layout from './components/Layout'
import LoginPage from './pages/auth/LoginPage'
import RegisterPage from './pages/auth/RegisterPage'
import ProfilePage from './pages/ProfilePage'
import DashboardPage from './pages/DashboardPage'
import IOCsPage from './pages/IOCsPage'
import IOCDetailPage from './pages/IOCDetailPage'
import LookupPage from './pages/LookupPage'
import TagsPage from './pages/TagsPage'
import AdminPage from './pages/AdminPage'

// Protected Route wrapper
import ProtectedRoute from './components/ProtectedRoute'

function App() {
  const { isAuthenticated, initialize } = useAuthStore()
  const { isDark } = useThemeStore()

  useEffect(() => {
    initialize()
  }, [initialize])

  useEffect(() => {
    // Apply dark mode class to document
    if (isDark) {
      document.documentElement.classList.add('dark')
    } else {
      document.documentElement.classList.remove('dark')
    }
  }, [isDark])

  return (
    <div className={`min-h-screen ${isDark ? 'gradient-bg-dark' : 'gradient-bg-light'}`}>
      <Layout>
        <Routes>
          <Route path="/" element={<Navigate to="/dashboard" replace />} />
          
          {/* PUBLIC ROUTES - No authentication required */}
          <Route path="/dashboard" element={<DashboardPage />} />
          <Route path="/iocs" element={<IOCsPage />} />
          <Route path="/iocs/:id" element={<IOCDetailPage />} />
          <Route path="/lookup" element={<LookupPage />} />
          
          {/* AUTHENTICATED ROUTES - Require login */}
          <Route 
            path="/tags" 
            element={
              <ProtectedRoute>
                <TagsPage />
              </ProtectedRoute>
            } 
          />
          <Route 
            path="/admin" 
            element={
              <ProtectedRoute permission="admin">
                <AdminPage />
              </ProtectedRoute>
            } 
          />
          
          {/* AUTH ROUTES */}
          <Route path="/login" element={<LoginPage />} />
          <Route path="/register" element={<RegisterPage />} />
          
          {/* USER PROFILE ROUTES - Require authentication */}
          <Route 
            path="/profile" 
            element={
              <ProtectedRoute>
                <ProfilePage />
              </ProtectedRoute>
            } 
          />
          
          <Route path="*" element={<Navigate to="/dashboard" replace />} />
        </Routes>
      </Layout>
    </div>
  )
}

export default App
