# 🚀 Vercel Deployment Guide

This guide walks you through deploying the CTI Dashboard on Vercel with separate frontend and backend deployments.

## 📋 Prerequisites

- [Vercel Account](https://vercel.com) (free tier works fine)
- MongoDB instance (MongoDB Atlas recommended)
- API keys (optional but recommended):
  - VirusTotal API key
  - AbuseIPDB API key

## 🔧 Backend Deployment

### Step 1: Create Backend Project

1. **Fork/Import Repository**
   - Go to [Vercel Dashboard](https://vercel.com/dashboard)
   - Click "New Project"
   - Import from GitHub: `https://github.com/pentoshi007/cti-me.git`

2. **Configure Project Settings**
   - **Framework Preset**: Other
   - **Root Directory**: `backend`
   - **Build Command**: `pip install -r requirements.txt`
   - **Output Directory**: Leave empty
   - **Install Command**: Leave empty

### Step 2: Set Environment Variables

Add these environment variables in Vercel project settings:

```env
# Required
MONGO_URI=mongodb+srv://username:password@cluster.mongodb.net/cti
FLASK_SECRET_KEY=your-super-secret-key-change-this-in-production
CORS_ORIGINS=https://your-frontend-domain.vercel.app,http://localhost:3000

# Optional but recommended
VT_API_KEY=your_virustotal_api_key
ABUSEIPDB_API_KEY=your_abuseipdb_api_key

# JWT Configuration
JWT_ACCESS_TTL=3600
JWT_REFRESH_TTL=2592000

# Application Settings
FLASK_ENV=production
SCHEDULER_TIMEZONE=UTC
RATE_LIMIT_LOOKUP_PER_MIN=60
```

### Step 3: Configure Vercel Functions

The backend is configured to run as Vercel functions. The `app.py` file is automatically detected as the main application.

### Step 4: Deploy Backend

1. Click "Deploy"
2. Wait for deployment to complete
3. Note the deployment URL (e.g., `https://your-backend.vercel.app`)

## 🎨 Frontend Deployment

### Step 1: Create Frontend Project

1. **Create New Project**
   - Click "New Project" in Vercel Dashboard
   - Import the same repository: `https://github.com/pentoshi007/cti-me.git`

2. **Configure Project Settings**
   - **Framework Preset**: Vite
   - **Root Directory**: `frontend`
   - **Build Command**: `npm run build`
   - **Output Directory**: `dist`
   - **Install Command**: `npm install`

### Step 2: Set Environment Variables

Add these environment variables:

```env
# Required - Use your backend URL from previous step
VITE_API_URL=https://your-backend.vercel.app

# Optional
VITE_APP_NAME=CTI Dashboard
VITE_APP_VERSION=1.0.0
```

### Step 3: Deploy Frontend

1. Click "Deploy"
2. Wait for deployment to complete
3. Access your application at the provided URL

## 🔄 Post-Deployment Steps

### 1. Update CORS Settings

Update your backend environment variables to include the frontend domain:

```env
CORS_ORIGINS=https://your-frontend.vercel.app,http://localhost:3000
```

### 2. Test the Application

1. **Access the frontend** at your Vercel URL
2. **Login with default credentials**:
   - Username: `admin`
   - Password: `admin123`
3. **Verify functionality**:
   - Dashboard loads correctly
   - API calls work (check Network tab)
   - Authentication flows properly

### 3. Configure MongoDB (if using Atlas)

1. **Whitelist Vercel IPs** (or use 0.0.0.0/0 for all IPs)
2. **Create database user** with appropriate permissions
3. **Test connection** from backend logs

## ⚡ Performance Optimization

### Backend Optimizations

1. **Cold Start Reduction**
   - Keep functions warm with scheduled requests
   - Optimize import statements
   - Use connection pooling for MongoDB

2. **Environment Configuration**
   ```env
   # Add these for better performance
   PYTHONUNBUFFERED=1
   PYTHONUTF8=1
   ```

### Frontend Optimizations

1. **Build Optimizations**
   - Code splitting is already configured
   - Bundle analysis: `npm run build -- --analyze`

2. **Caching Strategy**
   - Static assets are automatically cached by Vercel
   - API responses cached with React Query

## 🔒 Security Considerations

### 1. Environment Variables

- ✅ Never commit API keys to repository
- ✅ Use strong, unique secrets for production
- ✅ Rotate keys regularly

### 2. CORS Configuration

```env
# Production CORS - be specific
CORS_ORIGINS=https://your-frontend.vercel.app

# Development (add only when needed)
CORS_ORIGINS=https://your-frontend.vercel.app,http://localhost:3000
```

### 3. JWT Security

```env
# Use strong secret keys
FLASK_SECRET_KEY=generate-a-strong-secret-key-here
JWT_ACCESS_TTL=3600    # 1 hour
JWT_REFRESH_TTL=2592000 # 30 days
```

## 🐛 Troubleshooting

### Common Issues

#### 1. Backend 500 Errors
- **Check logs** in Vercel Functions tab
- **Verify MongoDB connection** string
- **Ensure all required environment variables** are set

#### 2. CORS Errors
- **Verify CORS_ORIGINS** includes your frontend domain
- **Check protocol** (http vs https)
- **Ensure no trailing slashes**

#### 3. Authentication Issues
- **Check JWT_SECRET_KEY** is set
- **Verify frontend API URL** points to backend
- **Test token refresh** functionality

#### 4. Database Connection Issues
- **Whitelist Vercel IPs** in MongoDB Atlas
- **Check connection string** format
- **Verify database user permissions**

### Debug Commands

```bash
# Test backend locally
cd backend
source venv/bin/activate
flask run

# Test frontend locally
cd frontend
npm run dev

# Check build output
npm run build
```

## 🔄 Continuous Deployment

### Automatic Deployments

Vercel automatically deploys when you push to the main branch:

1. **Push changes** to GitHub
2. **Vercel detects** changes automatically
3. **Builds and deploys** both frontend and backend
4. **Preview deployments** for pull requests

### Manual Deployments

```bash
# Install Vercel CLI
npm i -g vercel

# Deploy backend
cd backend
vercel

# Deploy frontend  
cd frontend
vercel
```

## 📊 Monitoring

### Vercel Analytics

- **Performance metrics** automatically tracked
- **Error monitoring** in Functions tab
- **Usage statistics** in project dashboard

### Application Monitoring

- **Health endpoint**: `https://your-backend.vercel.app/api/health`
- **API documentation**: `https://your-backend.vercel.app/docs/`
- **System stats**: Available in admin panel

## 🎯 Next Steps

1. **Set up custom domain** (Vercel Pro)
2. **Configure monitoring** and alerts
3. **Set up backup strategy** for MongoDB
4. **Implement rate limiting** for production use
5. **Add SSL certificates** (automatic with Vercel)

---

**Your CTI Dashboard is now live on Vercel! 🎉**

For support, check the [main README](README.md) or create an issue in the [GitHub repository](https://github.com/pentoshi007/cti-me/issues).
