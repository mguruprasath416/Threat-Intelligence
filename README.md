# 🛡️ IOC Sentinel — Threat Intelligence Dashboard

**A full-stack Cyber Threat Intelligence platform for SOC analysts and CTI teams.**
Automatically enriches IOCs, maps MITRE ATT&CK techniques, and visualizes threats in real time.

[Features](#-features) • [Tech Stack](#️-tech-stack) • [Setup](#-setup) • [API](#-api-endpoints) • [Project Structure](#-project-structure) • [How It Works](#-how-it-works)

---

## 📌 What is IOC Sentinel?

IOC Sentinel is a **Threat Intelligence IOC Dashboard** that helps SOC analysts and CTI teams:

- **Search and enrich** indicators of compromise (IPs, domains, URLs, file hashes)
- **Correlate threat data** from multiple sources in one place
- **Automatically map** threats to MITRE ATT&CK techniques
- **Monitor live threat feeds** from OpenPhish and other sources
- **Generate reports** for incident documentation

Built as a **portfolio project** demonstrating real-world Cyber Threat Intelligence workflows.

---

## ✨ Features

### 🔍 IOC Search & Enrichment
- Supports **IP addresses, domains, URLs, file hashes (MD5/SHA1/SHA256)**
- Auto-detects IOC type — just paste and search
- Enriches from **3 threat intelligence APIs simultaneously**
- Results cached for 24 hours to preserve API quota

### 📊 Threat Intelligence Sources

| Source | Data Provided |
|--------|--------------|
| **VirusTotal** | 90+ AV engine detections, reputation score, geo data |
| **AbuseIPDB** | Abuse confidence score, report count, ISP, tor detection |
| **AlienVault OTX** | Threat pulses, campaign associations, passive DNS |
| **OpenPhish** | Live phishing URL feed (auto-refreshes every 6 hours) |

### 🎯 Threat Scoring Engine
- Weighted scoring algorithm: **VT (40%) + AbuseIPDB (40%) + OTX (20%)**
- Normalized 0–100 score → severity classification:
  - 🟢 **Low** (0–25)
  - 🟡 **Medium** (26–50)
  - 🟠 **High** (51–75)
  - 🔴 **Critical** (76–100)

### 🗺️ MITRE ATT&CK Auto-Mapping
Automatically maps IOC characteristics to MITRE techniques:
- `T1566` — Phishing (Initial Access)
- `T1110` — Brute Force (Credential Access)
- `T1071` — C2 Communication
- `T1486` — Data Encrypted for Impact (Ransomware)
- `T1555` — Credentials from Password Stores

### 📈 Real-Time Dashboard
- KPI cards: Total IOCs, Critical, High, Medium counts
- Severity distribution donut chart
- IOC type breakdown pie chart
- 30-day IOC trend line chart
- Top threat countries bar chart
- Tag cloud from threat intelligence

### 📡 Live Threat Feed
- Auto-refreshes every 30 seconds
- Live scrolling ticker showing critical/high threats
- Filterable by source (OpenPhish, manual, API enrichment)
- New IOC counters (last 1h, last 24h)

### 📋 Analyst Reports
- Create investigation reports bundling multiple IOCs
- Draft → Published workflow
- Summary statistics auto-calculated
- Analyst findings and recommendations

### 🔐 Authentication & Access Control
- JWT-based authentication
- Role-based access: **Admin** and **Analyst** roles
- First registered user gets admin role automatically
- Rate limiting: 100 req/15min general, 10 req/15min auth, 30 IOC searches/10min

---

## 🛠️ Tech Stack

### Frontend

| Technology | Purpose |
|-----------|---------|
| React 18 | UI framework |
| React Router v6 | Client-side routing |
| Recharts | Data visualization (charts) |
| Axios | HTTP client with interceptors |
| Vite | Build tool and dev server |
| CSS Variables | Dark cyber-ops theme |

### Backend

| Technology | Purpose |
|-----------|---------|
| Node.js + Express | REST API server |
| MongoDB + Mongoose | Database and ODM |
| JWT + bcryptjs | Authentication and password hashing |
| Winston | Structured logging |
| node-cron | Scheduled feed fetching |
| Helmet + CORS | Security middleware |
| express-rate-limit | API rate limiting |

### External APIs

| API | Free Tier |
|----|----------|
| VirusTotal | 4 requests/min, 500/day |
| AbuseIPDB | 1,000 requests/day |
| AlienVault OTX | Generous free tier |
| OpenPhish | Public feed, no key needed |

---

## 🚀 Setup

### Prerequisites
- Node.js 18+
- MongoDB (local or Atlas)
- npm or yarn

### 1. Clone the repository
```bash
git clone https://github.com/yourusername/ioc-sentinel.git
cd ioc-sentinel
```

### 2. Backend setup
```bash
cd server
npm install
```

Create `server/.env`:
```env
PORT=5000
NODE_ENV=development
MONGO_URI=mongodb://localhost:27017/ioc_dashboard
JWT_SECRET=your_super_secret_jwt_key_here
JWT_EXPIRE=7d

VT_API_KEY=your_virustotal_api_key
ABUSEIPDB_API_KEY=your_abuseipdb_api_key
OTX_API_KEY=your_otx_api_key

CLIENT_URL=http://localhost:5173
LOG_LEVEL=info
IOC_STALE_DAYS=90
```

Start backend:
```bash
npm run dev
```

### 3. Frontend setup
```bash
cd client
npm install
npm run dev
```

### 4. Open in browser
```
http://localhost:5173
```

Register an account and start analyzing threats.

---

## 🔑 Get Free API Keys

| Service | Registration Link | Free Limit |
|---------|------------------|-----------|
| VirusTotal | https://www.virustotal.com/gui/join-us | 500/day |
| AbuseIPDB | https://www.abuseipdb.com/register | 1,000/day |
| AlienVault OTX | https://otx.alienvault.com | Unlimited |

> The dashboard works without API keys but enrichment data will be empty. Add keys for full functionality.

---

## 📡 API Endpoints

### Authentication
```
POST   /api/auth/register        Create new account
POST   /api/auth/login           Login and receive JWT
GET    /api/auth/me              Get current user profile
POST   /api/auth/logout          Logout
PUT    /api/auth/password        Change password
```

### IOC Operations
```
POST   /api/ioc/search           Search and enrich an IOC
GET    /api/ioc/stats            Dashboard aggregated statistics
GET    /api/ioc                  List IOCs (paginated, filterable)
GET    /api/ioc/:id              Get single IOC details
DELETE /api/ioc/:id              Archive IOC (admin only)
PATCH  /api/ioc/:id/flag         Toggle false positive flag
```

### Reports
```
POST   /api/reports              Create new report
GET    /api/reports              List all reports
GET    /api/reports/:id          Get single report with IOC details
PUT    /api/reports/:id          Update report
POST   /api/reports/:id/publish  Publish a draft report
DELETE /api/reports/:id          Delete report (admin only)
```

### Health Check
```
GET    /health                   Server health check
```

---

## 📁 Project Structure

```
ioc-sentinel/
│
├── client/                        # React Frontend
│   ├── src/
│   │   ├── api/
│   │   │   └── axios.js           # Pre-configured axios with JWT
│   │   ├── components/
│   │   │   ├── Navbar/            # Top navigation bar
│   │   │   ├── Sidebar/           # Left navigation sidebar
│   │   │   ├── IOCSearch/         # Search bar with auto type detection
│   │   │   ├── ThreatCard/        # Enrichment result display card
│   │   │   ├── ThreatTable/       # Sortable paginated IOC table
│   │   │   ├── Charts/            # Recharts visualizations
│   │   │   ├── Loader/            # Loading spinner
│   │   │   └── Alerts/            # Toast notifications
│   │   ├── context/
│   │   │   ├── AuthContext.jsx    # JWT and user session state
│   │   │   └── IOCContext.jsx     # IOC search and list state
│   │   ├── pages/
│   │   │   ├── Dashboard.jsx      # Main dashboard with charts
│   │   │   ├── IOCSearch.jsx      # Search + results + IOC table
│   │   │   ├── IOCDetails.jsx     # Single IOC full detail view
│   │   │   ├── ThreatFeed.jsx     # Live auto-refreshing threat feed
│   │   │   ├── Reports.jsx        # Analyst report management
│   │   │   └── Login.jsx          # Authentication page
│   │   ├── routes/
│   │   │   └── AppRoutes.jsx      # Protected route definitions
│   │   ├── utils/
│   │   │   └── formatDate.js      # Date, severity, validation helpers
│   │   └── styles/
│   │       └── globals.css        # Dark cyber-ops design system
│   └── package.json
│
└── server/                        # Node.js Backend
    ├── config/
    │   ├── db.js                  # MongoDB connection
    │   └── apiKeys.js             # API key configuration
    ├── controllers/
    │   ├── iocController.js       # IOC search, list, stats logic
    │   ├── authController.js      # Login, register, JWT handling
    │   └── reportController.js    # Report CRUD operations
    ├── middleware/
    │   ├── authMiddleware.js      # JWT verification + RBAC
    │   ├── errorMiddleware.js     # Global error handler
    │   └── rateLimitMiddleware.js # Rate limiting per endpoint
    ├── models/
    │   ├── IOC.js                 # IOC MongoDB schema
    │   ├── User.js                # User schema with bcrypt hooks
    │   └── Report.js              # Analyst report schema
    ├── routes/
    │   ├── iocRoutes.js           # IOC endpoint routing
    │   ├── authRoutes.js          # Auth endpoint routing
    │   └── reportRoutes.js        # Report endpoint routing
    ├── services/
    │   ├── virustotalService.js   # VirusTotal API integration
    │   ├── abuseipdbService.js    # AbuseIPDB API integration
    │   ├── otxService.js          # AlienVault OTX integration
    │   ├── openphishService.js    # OpenPhish feed with cache
    │   └── enrichmentService.js   # Orchestrates all API calls
    ├── utils/
    │   ├── threatScore.js         # Weighted scoring algorithm
    │   ├── mitreMapper.js         # MITRE ATT&CK auto-mapping
    │   ├── iocValidator.js        # IOC type detection and validation
    │   └── logger.js              # Winston structured logging
    ├── jobs/
    │   └── fetchThreatFeeds.js    # Cron: OpenPhish every 6 hours
    ├── app.js                     # Express app configuration
    └── server.js                  # Entry point
```

---

## 🔄 How It Works

```
User types: 185.220.101.45
        ↓
Frontend auto-detects type → IP Address
        ↓
POST /api/ioc/search
        ↓
authMiddleware verifies JWT token
        ↓
iocController checks MongoDB cache (less than 24h old)
        ↓ (cache miss — fresh enrichment needed)
enrichmentService calls APIs in parallel:
  ├── VirusTotal  → 45 out of 92 engines flagged
  ├── AbuseIPDB   → 87% abuse confidence score
  └── OTX         → 12 threat pulses found
        ↓
threatScore.js calculates weighted score → 70 → HIGH severity
        ↓
mitreMapper.js assigns → T1110 Brute Force, T1071 C2 Communication
        ↓
Result saved to MongoDB for caching
        ↓
ThreatCard.jsx displays full enrichment result
```

---

## 🧠 Key Concepts Demonstrated

| Concept | Implementation |
|---------|---------------|
| Threat Intelligence Pipeline | Collection → Enrichment → Scoring → Visualization |
| IOC Enrichment | Multi-source API correlation |
| MITRE ATT&CK Mapping | Automatic TTP identification from IOC data |
| Severity Classification | Weighted scoring algorithm (0–100) |
| Caching Strategy | 24-hour MongoDB cache to preserve API quota |
| JWT Authentication | Stateless token-based session management |
| Role-Based Access Control | Admin vs Analyst permissions |
| Rate Limiting | Protects external API quotas from abuse |
| Background Jobs | Automated OpenPhish feed ingestion via cron |
| REST API Design | RESTful endpoints with proper HTTP methods |

---

## 🛡️ Security Features

- Password hashing with bcrypt (12 salt rounds)
- JWT tokens with configurable expiry
- HTTP security headers via Helmet.js
- CORS configured for specific origins only
- Rate limiting on all API endpoints
- Input validation on all IOC submissions
- Soft delete — IOCs archived not permanently deleted
- Environment variables — no hardcoded secrets

---

## 🗺️ MITRE ATT&CK Techniques Mapped

| Technique ID | Name | Tactic |
|-------------|------|--------|
| T1566 | Phishing | Initial Access |
| T1566.001 | Spearphishing Attachment | Initial Access |
| T1566.002 | Spearphishing Link | Initial Access |
| T1071 | Application Layer Protocol | Command and Control |
| T1110 | Brute Force | Credential Access |
| T1555 | Credentials from Password Stores | Credential Access |
| T1486 | Data Encrypted for Impact | Impact |
| T1041 | Exfiltration Over C2 Channel | Exfiltration |
| T1046 | Network Service Scanning | Discovery |
| T1204.002 | Malicious File | Execution |
| T1078 | Valid Accounts | Defense Evasion |
| T1589 | Gather Victim Identity Info | Reconnaissance |

---

## 🚧 Roadmap

- [ ] Real-time WebSocket alerts for critical IOCs
- [ ] Telegram channel monitoring integration
- [ ] SIEM integration (Splunk, Microsoft Sentinel)
- [ ] Shodan API for infrastructure analysis
- [ ] PDF report export
- [ ] Email alerts for new critical IOCs
- [ ] AI-powered RAG chatbot for threat analysis
- [ ] Sigma rule generation from IOCs
- [ ] Dark web monitoring module
- [ ] CSV and JSON IOC export

---

## 🤝 Use Cases

| Role | How They Use It |
|------|----------------|
| **SOC Analyst** | Quickly investigate suspicious IPs and domains during incidents |
| **CTI Analyst** | Track emerging threats and enrich indicators from multiple sources |
| **Security Engineer** | Monitor threat feeds and integrate with existing SIEM |
| **Security Researcher** | Analyze malware infrastructure and threat actor TTPs |

---

## 📄 License

MIT License — free to use for personal and educational projects.

---

## 👤 Author

**Guru Prasath**
Cybersecurity | Threat Intelligence | SOC Operations

- LinkedIn: https://linkedin.com/in/yourprofile
- GitHub: https://github.com/yourusername

---

> ⭐ Star this repository if it helped you!
>
> *Built for cybersecurity portfolio and CTI interview preparation*
