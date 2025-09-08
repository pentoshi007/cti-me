import { ReactNode } from 'react'
import { useAuthStore } from '../stores/authStore'

interface PermissionCheckProps {
  children: ReactNode
  permission?: string
  role?: string
  requireAuth?: boolean
  fallback?: ReactNode
}

/**
 * Component that conditionally renders children based on user permissions, role, or authentication status
 * 
 * @param children - Content to render if permission check passes
 * @param permission - Required permission (e.g., 'admin', 'tag', 'export')
 * @param role - Required role (e.g., 'admin', 'analyst', 'viewer')
 * @param requireAuth - If true, requires user to be authenticated
 * @param fallback - Content to render if permission check fails
 */
const PermissionCheck = ({ 
  children, 
  permission, 
  role, 
  requireAuth = false, 
  fallback = null 
}: PermissionCheckProps) => {
  const { user, isAuthenticated, hasPermission } = useAuthStore()

  // Check authentication requirement
  if (requireAuth && !isAuthenticated) {
    return <>{fallback}</>
  }

  // Check specific permission
  if (permission && !hasPermission(permission)) {
    return <>{fallback}</>
  }

  // Check specific role
  if (role && (!user || user.role !== role)) {
    return <>{fallback}</>
  }

  // All checks passed, render children
  return <>{children}</>
}

export default PermissionCheck