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
          // Send refresh token in Authorization header, not request body
          const response = await apiClient.post(
            "/api/auth/refresh",
            {},
            {
              headers: {
                Authorization: `Bearer ${refreshToken}`,
              },
            }
          );

          const { access_token, refresh_token, user } = response.data;

          // Update authorization header with new access token
          apiClient.defaults.headers.common[
            "Authorization"
          ] = `Bearer ${access_token}`;

          set({
            user,
            accessToken: access_token,
            refreshToken: refresh_token, // Update refresh token too
            isAuthenticated: true,
          });
        } catch (error) {
          console.error("Token refresh failed:", error);
          get().logout();
          throw error;
        }
      },

      initialize: () => {
        const { accessToken } = get();
        if (accessToken) {
          apiClient.defaults.headers.common[
            "Authorization"
          ] = `Bearer ${accessToken}`;
          set({ isAuthenticated: true });
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
          viewer: ["view", "tag"],  // Added 'tag' permission for viewers when logged in
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
