import { useState, useEffect } from 'react'
import { useForm } from 'react-hook-form'
import { UserCircleIcon, KeyIcon, EyeIcon, EyeSlashIcon } from '@heroicons/react/24/outline'
import { useAuthStore } from '../stores/authStore'
import { apiClient } from '../lib/api'
import toast from 'react-hot-toast'

interface ChangePasswordForm {
  currentPassword: string
  newPassword: string
  confirmPassword: string
}

const ProfilePage = () => {
  const { user, refreshAuth } = useAuthStore()
  const [showCurrentPassword, setShowCurrentPassword] = useState(false)
  const [showNewPassword, setShowNewPassword] = useState(false)
  const [showConfirmPassword, setShowConfirmPassword] = useState(false)
  const [isChangingPassword, setIsChangingPassword] = useState(false)
  const [isLoading, setIsLoading] = useState(false)

  const {
    register,
    handleSubmit,
    watch,
    reset,
    formState: { errors },
  } = useForm<ChangePasswordForm>()

  const newPassword = watch('newPassword')

  useEffect(() => {
    // Refresh user data when component mounts
    refreshAuth().catch(() => {
      // Handle silently - user might be logged out
    })
  }, [refreshAuth])

  const onSubmitPasswordChange = async (data: ChangePasswordForm) => {
    if (data.newPassword !== data.confirmPassword) {
      toast.error('New passwords do not match')
      return
    }

    setIsLoading(true)
    try {
      await apiClient.post('/api/auth/change-password', {
        current_password: data.currentPassword,
        new_password: data.newPassword,
      })
      
      toast.success('Password changed successfully')
      reset()
      setIsChangingPassword(false)
    } catch (error: any) {
      const message = error.response?.data?.message || 'Failed to change password'
      toast.error(message)
    } finally {
      setIsLoading(false)
    }
  }

  if (!user) {
    return (
      <div className="max-w-4xl mx-auto p-6">
        <div className="text-center py-12">
          <div className="text-white/60">Please log in to view your profile</div>
        </div>
      </div>
    )
  }

  const getRoleBadgeColor = (role: string) => {
    switch (role) {
      case 'admin':
        return 'bg-red-500/20 text-red-300 border-red-500/30'
      case 'analyst':
        return 'bg-blue-500/20 text-blue-300 border-blue-500/30'
      case 'viewer':
        return 'bg-green-500/20 text-green-300 border-green-500/30'
      default:
        return 'bg-gray-500/20 text-gray-300 border-gray-500/30'
    }
  }

  return (
    <div className="max-w-4xl mx-auto p-6 space-y-8">
      {/* Header */}
      <div className="flex items-center space-x-4">
        <div className="p-3 bg-gradient-to-br from-blue-500/20 to-purple-600/20 rounded-xl border border-blue-500/30">
          <UserCircleIcon className="w-8 h-8 text-blue-400" />
        </div>
        <div>
          <h1 className="text-3xl font-bold text-white">User Profile</h1>
          <p className="text-white/60">Manage your account settings and preferences</p>
        </div>
      </div>

      {/* Profile Information */}
      <div className="glass-bg rounded-xl p-6">
        <h2 className="text-xl font-semibold text-white mb-6">Account Information</h2>
        
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div>
            <label className="block text-sm font-medium text-white/70 mb-2">Username</label>
            <div className="px-4 py-3 bg-white/5 border border-white/10 rounded-lg text-white">
              {user.username}
            </div>
          </div>
          
          <div>
            <label className="block text-sm font-medium text-white/70 mb-2">Email Address</label>
            <div className="px-4 py-3 bg-white/5 border border-white/10 rounded-lg text-white">
              {user.email}
            </div>
          </div>
          
          <div>
            <label className="block text-sm font-medium text-white/70 mb-2">Role</label>
            <div className="flex items-center space-x-2">
              <span className={`inline-flex items-center px-3 py-1 rounded-full text-sm font-medium border ${getRoleBadgeColor(user.role)}`}>
                {user.role.charAt(0).toUpperCase() + user.role.slice(1)}
              </span>
            </div>
          </div>
          
          <div>
            <label className="block text-sm font-medium text-white/70 mb-2">Member Since</label>
            <div className="px-4 py-3 bg-white/5 border border-white/10 rounded-lg text-white">
              {new Date(user.created_at).toLocaleDateString()}
            </div>
          </div>
        </div>

        {/* Permissions */}
        <div className="mt-6">
          <label className="block text-sm font-medium text-white/70 mb-2">Permissions</label>
          <div className="flex flex-wrap gap-2">
            {user.permissions.map((permission) => (
              <span
                key={permission}
                className="inline-flex items-center px-3 py-1 rounded-full text-sm bg-white/10 text-white/80 border border-white/20"
              >
                {permission}
              </span>
            ))}
          </div>
        </div>
      </div>

      {/* Password Change Section */}
      <div className="glass-bg rounded-xl p-6">
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center space-x-3">
            <KeyIcon className="w-6 h-6 text-yellow-400" />
            <h2 className="text-xl font-semibold text-white">Change Password</h2>
          </div>
          {!isChangingPassword && (
            <button
              onClick={() => setIsChangingPassword(true)}
              className="px-4 py-2 bg-blue-500 hover:bg-blue-600 text-white rounded-lg transition-colors"
            >
              Change Password
            </button>
          )}
        </div>

        {isChangingPassword ? (
          <form onSubmit={handleSubmit(onSubmitPasswordChange)} className="space-y-4">
            <div>
              <label htmlFor="currentPassword" className="block text-sm font-medium text-white/70 mb-2">
                Current Password
              </label>
              <div className="relative">
                <input
                  {...register('currentPassword', { required: 'Current password is required' })}
                  type={showCurrentPassword ? 'text' : 'password'}
                  id="currentPassword"
                  className={`w-full px-4 py-3 pr-12 bg-white/5 border border-white/20 rounded-lg text-white placeholder-white/50 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all ${
                    errors.currentPassword ? 'border-red-500' : ''
                  }`}
                  placeholder="Enter your current password"
                />
                <button
                  type="button"
                  onClick={() => setShowCurrentPassword(!showCurrentPassword)}
                  className="absolute right-3 top-1/2 transform -translate-y-1/2 text-white/50 hover:text-white/70 transition-colors"
                >
                  {showCurrentPassword ? (
                    <EyeSlashIcon className="w-5 h-5" />
                  ) : (
                    <EyeIcon className="w-5 h-5" />
                  )}
                </button>
              </div>
              {errors.currentPassword && (
                <p className="mt-1 text-sm text-red-400">{errors.currentPassword.message}</p>
              )}
            </div>

            <div>
              <label htmlFor="newPassword" className="block text-sm font-medium text-white/70 mb-2">
                New Password
              </label>
              <div className="relative">
                <input
                  {...register('newPassword', { 
                    required: 'New password is required',
                    minLength: { value: 8, message: 'Password must be at least 8 characters' }
                  })}
                  type={showNewPassword ? 'text' : 'password'}
                  id="newPassword"
                  className={`w-full px-4 py-3 pr-12 bg-white/5 border border-white/20 rounded-lg text-white placeholder-white/50 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all ${
                    errors.newPassword ? 'border-red-500' : ''
                  }`}
                  placeholder="Enter your new password"
                />
                <button
                  type="button"
                  onClick={() => setShowNewPassword(!showNewPassword)}
                  className="absolute right-3 top-1/2 transform -translate-y-1/2 text-white/50 hover:text-white/70 transition-colors"
                >
                  {showNewPassword ? (
                    <EyeSlashIcon className="w-5 h-5" />
                  ) : (
                    <EyeIcon className="w-5 h-5" />
                  )}
                </button>
              </div>
              {errors.newPassword && (
                <p className="mt-1 text-sm text-red-400">{errors.newPassword.message}</p>
              )}
            </div>

            <div>
              <label htmlFor="confirmPassword" className="block text-sm font-medium text-white/70 mb-2">
                Confirm New Password
              </label>
              <div className="relative">
                <input
                  {...register('confirmPassword', { 
                    required: 'Please confirm your new password',
                    validate: value => value === newPassword || 'Passwords do not match'
                  })}
                  type={showConfirmPassword ? 'text' : 'password'}
                  id="confirmPassword"
                  className={`w-full px-4 py-3 pr-12 bg-white/5 border border-white/20 rounded-lg text-white placeholder-white/50 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all ${
                    errors.confirmPassword ? 'border-red-500' : ''
                  }`}
                  placeholder="Confirm your new password"
                />
                <button
                  type="button"
                  onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                  className="absolute right-3 top-1/2 transform -translate-y-1/2 text-white/50 hover:text-white/70 transition-colors"
                >
                  {showConfirmPassword ? (
                    <EyeSlashIcon className="w-5 h-5" />
                  ) : (
                    <EyeIcon className="w-5 h-5" />
                  )}
                </button>
              </div>
              {errors.confirmPassword && (
                <p className="mt-1 text-sm text-red-400">{errors.confirmPassword.message}</p>
              )}
            </div>

            <div className="flex space-x-3 pt-4">
              <button
                type="submit"
                disabled={isLoading}
                className="px-4 py-2 bg-green-500 hover:bg-green-600 text-white rounded-lg disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              >
                {isLoading ? 'Changing...' : 'Change Password'}
              </button>
              <button
                type="button"
                onClick={() => {
                  setIsChangingPassword(false)
                  reset()
                }}
                className="px-4 py-2 bg-gray-500 hover:bg-gray-600 text-white rounded-lg transition-colors"
              >
                Cancel
              </button>
            </div>
          </form>
        ) : (
          <p className="text-white/60">
            Click "Change Password" to update your account password
          </p>
        )}
      </div>

      {/* Account Stats */}
      <div className="glass-bg rounded-xl p-6">
        <h2 className="text-xl font-semibold text-white mb-4">Account Activity</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="flex items-center justify-between p-4 bg-white/5 rounded-lg border border-white/10">
            <span className="text-white/70">Last Login</span>
            <span className="text-white">
              {user.last_login ? new Date(user.last_login).toLocaleString() : 'Never'}
            </span>
          </div>
          <div className="flex items-center justify-between p-4 bg-white/5 rounded-lg border border-white/10">
            <span className="text-white/70">Account Created</span>
            <span className="text-white">
              {new Date(user.created_at).toLocaleDateString()}
            </span>
          </div>
        </div>
      </div>
    </div>
  )
}

export default ProfilePage