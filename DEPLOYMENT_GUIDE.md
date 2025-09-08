# 🚀 CTI Dashboard - Free Cloud Deployment Guide

## ✅ Fixed Local Issues
- ✅ Fixed `start.sh` to use `python3` instead of `python`
- ✅ Fixed port configuration (backend now consistently runs on port 8080)
- ✅ Frontend build successfully completed
- ✅ Added cloud deployment configurations

## 🌐 Free Cloud Deployment Roadmap

### Phase 1: Deploy Backend to Railway (Free Tier)

**Why Railway?** 
- Free tier with 500 hours/month
- No credit card required for signup
- Supports Python/Flask apps
- Easy GitHub integration

#### Step 1: Prepare Backend for Railway

1. **Push your code to GitHub:**
   ```bash
   git add .
   git commit -m "Add cloud deployment configs"
   git push origin main
   ```

2. **Backend files are already configured:**
   - ✅ `railway.toml` - Railway configuration
   - ✅ `Procfile` - Process definition
   - ✅ `runtime.txt` - Python version
   - ✅ `requirements.txt` - Dependencies

#### Step 2: Deploy to Railway

1. **Sign up at Railway:**
   - Go to https://railway.app
   - Sign up with GitHub (no credit card needed)

2. **Create new project:**
   - Click "New Project"
   - Select "Deploy from GitHub repo"
   - Choose your repository
   - Select the `backend` folder as root directory

3. **Configure environment variables in Railway:**
   ```
   FLASK_SECRET_KEY=your_generated_secret_key_here
   MONGO_URI=your_mongodb_atlas_connection_string
   VT_API_KEY=your_virustotal_api_key
   ABUSEIPDB_API_KEY=your_abuseipdb_api_key
   FLASK_ENV=production
   CORS_ORIGINS=https://your-frontend.vercel.app
   ```

4. **Get your Railway backend URL:**
   - After deployment, copy the Railway app URL
   - Example: `https://your-backend-name.railway.app`

### Phase 2: Deploy Frontend to Vercel (Free Tier)

**Why Vercel?**
- Free tier with generous limits
- Perfect for React/Vite apps
- No credit card required
- Automatic deployments from GitHub

#### Step 1: Configure Frontend

1. **Update frontend environment:**
   - Edit `frontend/.env.production`:
   ```
   VITE_API_URL=https://your-backend-name.railway.app
   ```

2. **Update Vercel config:**
   - Edit `frontend/vercel.json` and replace:
   ```json
   "destination": "https://your-backend-name.railway.app/api/$1"
   ```

#### Step 2: Deploy to Vercel

1. **Sign up at Vercel:**
   - Go to https://vercel.com
   - Sign up with GitHub (no credit card needed)

2. **Import project:**
   - Click "New Project"
   - Import your GitHub repository
   - Set root directory to `frontend`
   - Framework preset: Vite

3. **Configure build settings:**
   ```
   Build Command: npm run build
   Output Directory: dist
   Install Command: npm install
   ```

4. **Add environment variables:**
   ```
   VITE_API_URL = https://your-backend-name.railway.app
   ```

### Phase 3: Update CORS Configuration

1. **Update backend CORS in Railway:**
   - Go to Railway dashboard
   - Add/update environment variable:
   ```
   CORS_ORIGINS=https://your-frontend.vercel.app,https://your-custom-domain.com
   ```

2. **Redeploy backend** (Railway will auto-redeploy)

### Alternative Free Platforms

#### Backend Alternatives:
1. **Render (Free Tier):**
   - 750 hours/month free
   - Auto-sleep after 15 mins of inactivity
   - Use same `requirements.txt` and `Procfile`

2. **Heroku (Limited Free):**
   - Limited free hours
   - Use same configuration files

#### Frontend Alternatives:
1. **Netlify:**
   - Excellent for static sites
   - Similar to Vercel
   - Use `dist` folder after build

2. **GitHub Pages:**
   - Free for public repos
   - Requires some additional setup

## 📋 Step-by-Step Deployment Checklist

### Prerequisites ✅
- [ ] GitHub account
- [ ] MongoDB Atlas account (free tier)
- [ ] VirusTotal API key (free)
- [ ] AbuseIPDB API key (free)

### Backend Deployment (Railway) ✅
- [ ] Code pushed to GitHub
- [ ] Railway account created
- [ ] Project imported from GitHub
- [ ] Environment variables configured
- [ ] Backend URL obtained
- [ ] Health check working (`/api/health`)

### Frontend Deployment (Vercel) ✅
- [ ] Frontend environment updated with backend URL
- [ ] Vercel account created
- [ ] Project imported from GitHub
- [ ] Build settings configured
- [ ] Environment variables set
- [ ] Frontend accessible

### Final Configuration ✅
- [ ] CORS updated with frontend URL
- [ ] Test login with default credentials
- [ ] Test API endpoints
- [ ] Test data ingestion
- [ ] Change default admin password

## 🔐 Security Configuration

### Required API Keys:
1. **MongoDB Atlas** (Free tier - 512MB):
   - Sign up at https://cloud.mongodb.com
   - Create free cluster
   - Get connection string

2. **VirusTotal API** (Free tier - 4 requests/minute):
   - Sign up at https://www.virustotal.com/gui/join-us
   - Go to API key section
   - Copy API key

3. **AbuseIPDB API** (Free tier - 1000 requests/day):
   - Sign up at https://www.abuseipdb.com/register
   - Go to API section
   - Copy API key

## 🧪 Testing Your Deployment

### Local Testing:
```bash
# Test the fixed startup
./start.sh
# Should now work without python errors
```

### Cloud Testing:
1. **Backend Health Check:**
   ```
   https://your-backend.railway.app/api/health
   ```

2. **Frontend Access:**
   ```
   https://your-frontend.vercel.app
   ```

3. **API Documentation:**
   ```
   https://your-backend.railway.app/docs/
   ```

4. **Default Login:**
   - Username: `admin`
   - Password: `admin123`

## 💰 Cost Breakdown (FREE!)

| Service | Free Tier Limits | Cost |
|---------|------------------|------|
| Railway | 500 hours/month | $0 |
| Vercel | 100GB bandwidth/month | $0 |
| MongoDB Atlas | 512MB storage | $0 |
| VirusTotal API | 4 requests/minute | $0 |
| AbuseIPDB API | 1000 requests/day | $0 |
| **TOTAL** | | **$0/month** |

## 🔧 Troubleshooting

### Common Issues:

1. **Backend not starting:**
   - Check Railway logs
   - Verify environment variables
   - Ensure MongoDB connection string is correct

2. **Frontend API errors:**
   - Check CORS configuration
   - Verify backend URL in frontend env
   - Check network tab in browser

3. **Local startup issues:**
   - Ensure using `python3` not `python`
   - Check if MongoDB is accessible
   - Verify .env file exists

### Getting Help:
- Railway logs: Railway dashboard → your app → logs
- Vercel logs: Vercel dashboard → your app → functions
- Browser console for frontend errors

## 🚀 Go Live!

Once deployed, your CTI Dashboard will be accessible at:
- **Frontend**: `https://your-app.vercel.app`
- **API**: `https://your-backend.railway.app`

**Default credentials:** admin / admin123 (⚠️ **Change immediately!**)

---

**🎉 Congratulations!** You now have a fully functional, cloud-deployed CTI Dashboard running on free tiers without any credit card requirements!