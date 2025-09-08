# CTI Dashboard - Cyber Threat Intelligence Platform

A comprehensive Cyber Threat Intelligence (CTI) Dashboard for aggregating, analyzing, and managing threat indicators with real-time enrichment capabilities.

![CTI Dashboard](https://img.shields.io/badge/CTI-Dashboard-blue?style=for-the-badge)
![Flask](https://img.shields.io/badge/Flask-2.3.3-green?style=flat-square)
![React](https://img.shields.io/badge/React-18.2.0-blue?style=flat-square)
![MongoDB](https://img.shields.io/badge/MongoDB-Atlas-green?style=flat-square)
![TypeScript](https://img.shields.io/badge/TypeScript-5.2.2-blue?style=flat-square)

## 🚀 Features

### Core Functionality
- **Threat Intelligence Aggregation**: Automated ingestion from URLHaus feed
- **IOC Enrichment**: Real-time enrichment with VirusTotal and AbuseIPDB
- **Smart Threat Scoring**: Automated threat scoring (0-100) with severity classification
- **Advanced Search & Filtering**: Multi-parameter search with pagination
- **Tag Management**: Flexible tagging system for IOC categorization
- **CSV Export**: Background job processing for large dataset exports

### Security & Access Control
- **JWT Authentication**: Secure token-based authentication
- **Role-Based Access Control (RBAC)**: Admin, Analyst, and Viewer roles
- **Rate Limiting**: Per-user and per-IP rate limiting
- **Input Validation**: Comprehensive input sanitization

### User Experience
- **Glassmorphic UI**: Modern, accessible interface with dark/light themes
- **Responsive Design**: Mobile-first approach with Tailwind CSS
- **Real-time Analytics**: Interactive charts and KPI dashboards
- **Export Functionality**: CSV export with background processing

## 🏗️ Architecture

### Backend (Flask)
- **Framework**: Flask with Flask-RESTX for API documentation
- **Database**: MongoDB Atlas with optimized indexes
- **Scheduler**: APScheduler for periodic tasks
- **External APIs**: VirusTotal and AbuseIPDB integration
- **Rate Limiting**: Flask-Limiter for API protection

### Frontend (React + TypeScript)
- **Framework**: React 18 with TypeScript
- **Build Tool**: Vite for fast development
- **Styling**: Tailwind CSS with glassmorphic design
- **State Management**: Zustand for global state
- **Data Fetching**: TanStack Query for server state
- **Charts**: Recharts for data visualization

### Database Schema
```
indicators: IOC storage with threat scoring
lookups: User lookup history with TTL
tags: Tag management system
exports: Export job tracking with TTL
ingest_runs: Ingestion run logs
users: User authentication and roles
```

## 🛠️ Installation & Setup

### Prerequisites
- Python 3.9+
- Node.js 18+
- MongoDB Atlas account
- VirusTotal API key (free tier)
- AbuseIPDB API key (free tier)

### Backend Setup

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd project/backend
   ```

2. **Create virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\\Scripts\\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure environment variables**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

5. **Required Environment Variables**
   ```env
   FLASK_ENV=development
   FLASK_SECRET_KEY=your_secret_key_here
   MONGO_URI=mongodb+srv://username:password@cluster.mongodb.net/cti
   MONGO_DB=cti
   VT_API_KEY=your_virustotal_api_key
   ABUSEIPDB_API_KEY=your_abuseipdb_api_key
   JWT_ACCESS_TTL=900
   JWT_REFRESH_TTL=2592000
   ```

6. **Run the backend**
   ```bash
   python app.py
   ```

### Frontend Setup

1. **Navigate to frontend directory**
   ```bash
   cd ../frontend
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Start development server**
   ```bash
   npm run dev
   ```

## 🔧 Configuration

### MongoDB Atlas Setup
1. Create a free MongoDB Atlas cluster
2. Create a database user with `readWrite` permissions
3. Configure network access (add your IP or 0.0.0.0/0 for testing)
4. Get the connection string and update MONGO_URI

### API Keys Setup
1. **VirusTotal**: Register at https://www.virustotal.com/gui/join-us
2. **AbuseIPDB**: Register at https://www.abuseipdb.com/register

## 📚 API Documentation

The backend provides comprehensive API documentation via Swagger UI at:
```
http://localhost:5001/docs/
```

### Key Endpoints
- `POST /api/auth/login` - User authentication
- `GET /api/iocs` - List IOCs with filtering
- `POST /api/lookup` - Perform IOC lookup
- `GET /api/metrics/overview` - Dashboard metrics
- `POST /api/exports` - Create CSV export

## 🎯 Default Credentials

For testing purposes, a default admin user is created:
- **Username**: `admin`
- **Password**: `admin123`

⚠️ **Change these credentials in production!**

## 🔐 Security Features

### Authentication & Authorization
- JWT-based authentication with access and refresh tokens
- Role-based permissions (Admin, Analyst, Viewer)
- Automatic token refresh on API calls
- Secure password hashing with Werkzeug

### Rate Limiting
- Lookup endpoint: 60 requests/minute per user
- Global API limits: 200 requests/day, 50 requests/hour
- External API rate limiting with backoff strategies

### Data Protection
- Input validation and sanitization
- MongoDB injection prevention
- HTTPS enforcement in production
- Secrets management via environment variables

## 📊 Monitoring & Analytics

### Dashboard Metrics
- Total IOCs and severity distribution
- Recent activity (24h/7d trends)
- Top threat sources and tags
- Time series charts for threat trends

### System Administration
- Database statistics and collection counts
- Manual ingestion triggers
- Enrichment job management
- User management (Admin only)

## 🚀 Production Deployment

### Docker Deployment (Recommended)
```bash
# Build and run with Docker Compose
docker-compose up -d
```

### Manual Deployment
1. Set up reverse proxy (nginx/Apache)
2. Configure SSL certificates
3. Update environment variables for production
4. Set up process manager (PM2/systemd)
5. Configure log rotation

## 🧪 Testing

### Backend Testing
```bash
cd backend
pytest tests/
```

### Frontend Testing
```bash
cd frontend
npm run test
```

## 📈 Performance Optimizations

### Database
- Optimized MongoDB indexes for fast queries
- TTL indexes for automatic data cleanup
- Connection pooling with configurable limits

### Frontend
- Code splitting with React.lazy
- Image optimization and lazy loading
- Efficient state management with Zustand
- Query caching with TanStack Query

### Backend
- Request rate limiting and caching
- Background job processing for exports
- Efficient aggregation pipelines

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

For issues and questions:
1. Check the documentation
2. Search existing issues
3. Create a new issue with detailed information

## 🔄 Roadmap

- [ ] WebSocket support for real-time updates
- [ ] Additional threat intelligence feeds
- [ ] Machine learning-based threat scoring
- [ ] API rate limiting dashboard
- [ ] Advanced export formats (JSON, STIX)
- [ ] Integration with SIEM systems

---

Built with ❤️ for the cybersecurity community
