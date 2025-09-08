# 🔐 CTI Dashboard

> **Cyber Threat Intelligence Dashboard** - A comprehensive platform for managing, analyzing, and enriching Indicators of Compromise (IOCs) with real-time threat intelligence feeds.

[![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https://github.com/pentoshi007/cti-me.git)

## 🌟 Features

### 🎯 Core Functionality
- **IOC Management**: Create, update, and organize indicators of compromise
- **Real-time Feed Ingestion**: Automated URLHaus feed integration
- **Threat Intelligence Enrichment**: VirusTotal and AbuseIPDB integration
- **Advanced Search & Filtering**: Powerful query capabilities
- **Tag Management**: Categorize and organize threats
- **Export Capabilities**: Multiple export formats (JSON, CSV, STIX)

### 🔒 Security & Authentication
- **Role-based Access Control**: Admin, Analyst, and Viewer roles
- **JWT Authentication**: Secure token-based authentication
- **Permission Management**: Granular permission system
- **Session Management**: Automatic token refresh

### 📊 Analytics & Monitoring
- **System Statistics**: Real-time dashboard metrics
- **Activity Monitoring**: Track ingestion runs and enrichment operations
- **Performance Metrics**: API usage and rate limiting
- **Administrative Tools**: User management and system health

### 🎨 Modern UI/UX
- **Responsive Design**: Mobile-first approach
- **Dark/Light Theme**: Adaptive theming
- **Real-time Updates**: Live data refresh
- **Intuitive Navigation**: Clean, modern interface

## 🏗️ Architecture

### Backend (Python Flask)
```
backend/
├── auth/           # Authentication & authorization
├── iocs/           # IOC management
├── lookup/         # Threat intelligence enrichment
├── ingestion/      # Feed ingestion (URLHaus)
├── exports/        # Data export functionality
├── admin/          # Administrative operations
├── external/       # External API integrations
└── utils/          # Utility functions
```

### Frontend (React TypeScript)
```
frontend/src/
├── components/     # Reusable UI components
├── pages/          # Application pages
├── stores/         # State management (Zustand)
├── lib/            # API client and utilities
└── styles/         # Tailwind CSS styling
```

## 🚀 Quick Start

### Prerequisites
- **Python 3.11+**
- **Node.js 18+**
- **MongoDB** (local or cloud)
- **API Keys** (optional):
  - VirusTotal API key
  - AbuseIPDB API key

### Local Development

1. **Clone the repository**
   ```bash
   git clone https://github.com/pentoshi007/cti-me.git
   cd cti-me
   ```

2. **Backend Setup**
   ```bash
   cd backend
   
   # Create virtual environment (included in repo)
   source venv/bin/activate  # On Windows: venv\\Scripts\\activate
   
   # Install dependencies
   pip install -r requirements.txt
   
   # Configure environment
   cp .env.example .env
   # Edit .env with your configuration
   ```

3. **Frontend Setup**
   ```bash
   cd frontend
   
   # Install dependencies
   npm install
   
   # Configure environment
   cp .env.example .env.local
   # Edit .env.local with your configuration
   ```

4. **Start Development Servers**
   ```bash
   # From project root
   ./start.sh
   ```

   This will start:
   - **Backend**: http://localhost:8080
   - **Frontend**: http://localhost:3000
   - **API Docs**: http://localhost:8080/docs/

### Default Credentials
- **Username**: `admin`
- **Password**: `admin123`

## 🌐 Deployment

### Vercel Deployment (Recommended)

#### Backend Deployment
1. **Create new Vercel project** for backend
2. **Set environment variables**:
   ```
   MONGO_URI=your_mongodb_connection_string
   FLASK_SECRET_KEY=your_secret_key
   VT_API_KEY=your_virustotal_api_key (optional)
   ABUSEIPDB_API_KEY=your_abuseipdb_api_key (optional)
   ```
3. **Deploy** from `backend/` directory

#### Frontend Deployment
1. **Create new Vercel project** for frontend
2. **Set environment variables**:
   ```
   VITE_API_URL=https://your-backend-deployment.vercel.app
   ```
3. **Deploy** from `frontend/` directory

### Docker Deployment
```bash
# Build and run with Docker Compose
docker-compose up --build
```

### Railway/Heroku Deployment
Configuration files included:
- `backend/Procfile`
- `backend/railway.toml`
- `backend/runtime.txt`

## ⚙️ Configuration

### Environment Variables

#### Backend (.env)
```env
# MongoDB
MONGO_URI=mongodb://localhost:27017/
MONGO_DB=cti

# Authentication
FLASK_SECRET_KEY=your_secret_key
JWT_ACCESS_TTL=3600
JWT_REFRESH_TTL=2592000

# External APIs
VT_API_KEY=your_virustotal_api_key
ABUSEIPDB_API_KEY=your_abuseipdb_api_key

# CORS
CORS_ORIGINS=http://localhost:3000,https://your-frontend-domain.com
```

#### Frontend (.env.local)
```env
VITE_API_URL=http://localhost:8080
```

## 📡 API Documentation

Interactive API documentation available at: `http://localhost:8080/docs/`

### Key Endpoints
- **Authentication**: `/api/auth/*`
- **IOCs**: `/api/iocs/*`
- **Lookups**: `/api/lookup/*`
- **Admin**: `/api/admin/*`
- **Exports**: `/api/exports/*`

## 🔧 Development

### Code Structure
- **Backend**: Python Flask with Flask-RESTX for API documentation
- **Frontend**: React with TypeScript, Tailwind CSS, Zustand for state management
- **Database**: MongoDB with PyMongo
- **Authentication**: JWT with Flask-JWT-Extended

### Recent Improvements
- ✅ Fixed JWT authentication errors
- ✅ Improved URLHaus ingestion with better asyncio handling  
- ✅ Enhanced VirusTotal rate limiting
- ✅ Better error handling throughout the application
- ✅ Frontend token refresh improvements

### Testing
```bash
# Backend tests
cd backend
python -m pytest

# Frontend tests  
cd frontend
npm test
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Documentation**: Check the [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md)
- **Issues**: [GitHub Issues](https://github.com/pentoshi007/cti-me/issues)
- **API Docs**: Available at `/docs/` endpoint

## 🙏 Acknowledgments

- **URLHaus** by abuse.ch for threat intelligence feeds
- **VirusTotal** for malware scanning API
- **AbuseIPDB** for IP reputation data
- **MongoDB** for database solutions
- **Vercel** for deployment platform

---

**Built with ❤️ for the cybersecurity community**