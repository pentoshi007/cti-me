import { create } from "zustand";
import { persist, createJSONStorage } from "zustand/middleware";
import { apiClient } from "../lib/api";

export interface User {
  id: string;
  username: string;
  email: string;
  role: string;
  permissions: string[];
  created_at: string;
  last_login?: string;
}

interface AuthState {
  user: User | null;
  accessToken: string | null;
  refreshToken: string | null;
  isAuthenticated: boolean;

  // Actions
  login: (username: string, password: string) => Promise<void>;
  register: (
    username: string,
    email: string,
    password: string
  ) => Promise<void>;
  logout: () => void;
  refreshAuth: () => Promise<void>;
  initialize: () => void;
  hasPermission: (permission: string) => boolean;
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set, get) => ({
      user: null,
      accessToken: null,
      refreshToken: null,
      isAuthenticated: false,

      login: async (username: string, password: string) => {
        try {
          const response = await apiClient.post("/api/auth/login", {
            username,
            password,
          });

          const { access_token, refresh_token, user } = response.data;

          // Set tokens in API client
          apiClient.defaults.headers.common[
            "Authorization"
          ] = `Bearer ${access_token}`;

          set({
            user,
            accessToken: access_token,
            refreshToken: refresh_token,
            isAuthenticated: true,
          });
        } catch (error) {
          console.error("Login failed:", error);
          throw error;
        }
      },

      register: async (username: string, email: string, password: string) => {
        try {
          const response = await apiClient.post("/api/auth/register", {
            username,
            email,
            password,
          });

          const { access_token, refresh_token, user } = response.data;

          // Set tokens in API client
          apiClient.defaults.headers.common[
            "Authorization"
          ] = `Bearer ${access_token}`;

          set({
            user,
            accessToken: access_token,
            refreshToken: refresh_token,
            isAuthenticated: true,
          });
        } catch (error) {
          console.error("Registration failed:", error);
          throw error;
        }
      },

      logout: () => {
        // Clear tokens from API client
        delete apiClient.defaults.headers.common["Authorization"];

        set({
          user: null,
          accessToken: null,
          refreshToken: null,
          isAuthenticated: false,
        });
      },

      refreshAuth: async () => {
        const { refreshToken } = get();
        if (!refreshToken) {
          throw new Error("No refresh token available");
        }

        try {
          // Temporarily set refresh token for the request
          const originalAuth =
            apiClient.defaults.headers.common["Authorization"];
          apiClient.defaults.headers.common[
            "Authorization"
          ] = `Bearer ${refreshToken}`;

          const response = await apiClient.post("/api/auth/refresh");

          const { access_token, refresh_token, user } = response.data;

          // Update authorization header with new access token
          apiClient.defaults.headers.common[
            "Authorization"
          ] = `Bearer ${access_token}`;

          set({
            user,
            accessToken: access_token,
            refreshToken: refresh_token || refreshToken, // Keep old refresh token if new one not provided
            isAuthenticated: true,
          });
        } catch (error) {
          console.error("Token refresh failed:", error);
          get().logout();
          throw error;
        }
      },

      initialize: () => {
        const { accessToken, refreshToken } = get();
        if (accessToken && refreshToken) {
          apiClient.defaults.headers.common[
            "Authorization"
          ] = `Bearer ${accessToken}`;
          set({ isAuthenticated: true });

          // Try to refresh token on startup if access token is expired
          try {
            // Decode JWT to check expiration (basic check)
            const payload = JSON.parse(atob(accessToken.split(".")[1]));
            const now = Date.now() / 1000;
            if (payload.exp && payload.exp < now + 60) {
              // If expires within 1 minute
              get()
                .refreshAuth()
                .catch(() => {
                  console.warn("Token refresh failed on initialization");
                  get().logout();
                });
            }
          } catch (error) {
            console.warn("Invalid token format, logging out");
            get().logout();
          }
        } else {
          get().logout();
        }
      },

      hasPermission: (permission: string) => {
        const { user } = get();

        if (!user) {
          return false;
        }

        // Admin has all permissions
        if (user.role === "admin") {
          return true;
        }

        // Check explicit permissions array
        if (user.permissions?.includes(permission)) {
          return true;
        }

        // Role-based permission mapping for CTI Dashboard
        const rolePermissions = {
          admin: ["admin", "tag", "export", "view", "edit", "delete"],
          analyst: ["tag", "export", "view", "edit"],
          viewer: ["view", "tag"], // Added 'tag' permission for viewers when logged in
        };

        const userPermissions =
          rolePermissions[user.role as keyof typeof rolePermissions] || [];
        return userPermissions.includes(permission);
      },
    }),
    {
      name: "auth-storage",
      storage: createJSONStorage(() => localStorage),
      partialize: (state) => ({
        user: state.user,
        accessToken: state.accessToken,
        refreshToken: state.refreshToken,
        isAuthenticated: state.isAuthenticated,
      }),
    }
  )
);
