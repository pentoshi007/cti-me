import axios from "axios";

// Create axios instance
export const apiClient = axios.create({
  // In dev, rely on Vite proxy (relative URLs). In prod, use the deployed backend.
  baseURL: import.meta.env.DEV ? "" : "https://cti-me.vercel.app",
  timeout: 30000,
  withCredentials: true,
});

// Request interceptor for authentication
apiClient.interceptors.request.use(
  (config) => {
    // Token will be set by auth store
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Response interceptor for error handling
apiClient.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;

    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;

      try {
        // Try to refresh token
        const { useAuthStore } = await import("./stores/authStore");
        await useAuthStore.getState().refreshAuth();

        // Retry original request
        return apiClient(originalRequest);
      } catch (refreshError) {
        // Refresh failed, logout user
        const { useAuthStore } = await import("./stores/authStore");
        useAuthStore.getState().logout();

        // Redirect to login if not already there
        if (window.location.pathname !== "/login") {
          window.location.href = "/login";
        }
      }
    }

    return Promise.reject(error);
  }
);

// API methods organized by namespace
export const api = {
  auth: {
    login: (credentials: { username: string; password: string }) =>
      apiClient.post("/api/auth/login", credentials),
    register: (userData: {
      username: string;
      email: string;
      password: string;
    }) => apiClient.post("/api/auth/register", userData),
    refresh: () => apiClient.post("/api/auth/refresh"),
    logout: () => apiClient.post("/api/auth/logout"),
    changePassword: (data: { currentPassword: string; newPassword: string }) =>
      apiClient.post("/api/auth/change-password", data),
  },

  iocs: {
    list: (params?: any) => apiClient.get("/api/iocs", { params }),
    get: (id: string) => apiClient.get(`/api/iocs/${id}`),
    create: (data: any) => apiClient.post("/api/iocs", data),
    update: (id: string, data: any) => apiClient.put(`/api/iocs/${id}`, data),
    delete: (id: string) => apiClient.delete(`/api/iocs/${id}`),
    addTag: (id: string, tagName: string) =>
      apiClient.post(`/api/iocs/${id}/tags`, { tag_name: tagName }),
    removeTag: (id: string, tagName: string) =>
      apiClient.delete(`/api/iocs/${id}/tags/${tagName}`),
    bulkTag: (data: { ioc_ids: string[]; tag_names: string[] }) =>
      apiClient.post("/api/iocs/bulk-tag", data),
  },

  lookup: {
    perform: (indicator: string) =>
      apiClient.post("/api/lookup", { indicator }),
    history: (params?: any) => apiClient.get("/api/lookup/history", { params }),
    get: (lookupId: string) => apiClient.get(`/api/lookup/${lookupId}`),
  },

  tags: {
    list: (params?: any) => apiClient.get("/api/tags", { params }),
    create: (data: { name: string; description?: string; color?: string }) =>
      apiClient.post("/api/tags", data),
    update: (id: string, data: any) => apiClient.put(`/api/tags/${id}`, data),
    delete: (id: string) => apiClient.delete(`/api/tags/${id}`),
    stats: () => apiClient.get("/api/tags/stats"),
  },

  metrics: {
    overview: () => apiClient.get("/api/metrics/overview"),
    // Backend route is /api/metrics/timeseries (no hyphen)
    timeSeries: (params?: any) =>
      apiClient.get("/api/metrics/timeseries", { params }),
    threats: () => apiClient.get("/api/metrics/threats"),
  },

  exports: {
    create: (data: any) => apiClient.post("/api/exports", data),
    list: (params?: any) => apiClient.get("/api/exports", { params }),
    get: (id: string) => apiClient.get(`/api/exports/${id}`),
    download: (id: string) =>
      apiClient.get(`/api/exports/${id}/download`, {
        responseType: "blob",
      }),
  },

  admin: {
    // Align with backend admin routes
    getSystemStats: () => apiClient.get("/api/admin/system/stats"),
    getIngestRuns: () => apiClient.get("/api/admin/ingest/runs"),
    getAllRuns: () => apiClient.get("/api/admin/all-runs"),
    triggerIngest: (source?: string) =>
      apiClient.post("/api/admin/ingest/run", { source }),
    triggerEnrichment: () => apiClient.post("/api/admin/enrichment/run"),
    checkAutoRun: () => apiClient.get("/api/admin/auto-run/check"),
    getUsers: () => apiClient.get("/api/admin/users"),
    createUser: (userData: any) => apiClient.post("/api/admin/users", userData),
    updateUser: (id: string, userData: any) =>
      apiClient.patch(`/api/admin/users/${id}`, userData),
    deleteUser: (id: string) => apiClient.delete(`/api/admin/users/${id}`),
  },
};

export default api;
