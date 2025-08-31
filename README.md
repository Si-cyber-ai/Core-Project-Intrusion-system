# SecureGuard IDS - Intrusion Detection System

A comprehensive Intrusion Detection System (IDS) with Python backend and TypeScript frontend, featuring ML-based anomaly detection, honeypot capabilities, and a professional security dashboard.

## 🚀 Features

### Backend (Python + FastAPI)
- **IDS Core Engine**: Regex pattern detection + ML anomaly detection (Isolation Forest & Random Forest)
- **Security Features**: SSL/TLS encryption, RSA/DSA digital signatures, HMAC message integrity
- **Honeypot Module**: Records suspicious connections and attacker interactions
- **Rate Limiting**: Protection against flood attacks
- **Data Handling**: Local JSON/CSV storage with dummy dataset generation
- **API Endpoints**: RESTful APIs for traffic logs, alerts, honeypot data, and system status

### Frontend (React + TypeScript)
- **Professional Dashboard**: Antivirus-style dark theme with real-time monitoring
- **Traffic Monitor**: Live packet analysis with anomaly highlighting
- **Alert Center**: Security alerts with severity levels and incident management
- **Honeypot Logs**: Attacker IP tracking, payloads, and threat intelligence
- **System Status**: SSL/TLS status, RSA verification, rate limiting status
- **Rule Management**: Add/edit regex detection rules with validation

### UI/UX
- **Dark Cyber Theme**: Professional antivirus-style design
- **Smooth Animations**: Framer Motion for cards, graphs, and alerts
- **Responsive Design**: Grid layout that works on all devices
- **Real-time Charts**: Recharts for traffic visualization and metrics

## 📋 Prerequisites

- Python 3.8+
- Node.js 16+
- npm or yarn

## 🛠️ Installation

### Backend Setup

1. Navigate to backend directory:
```bash
cd backend
```

2. Create virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Create data directory:
```bash
mkdir -p data
```

### Frontend Setup

1. Navigate to frontend directory:
```bash
cd frontend
```

2. Install dependencies:
```bash
npm install
```

## 🚀 Running the Application

### Start Backend Server

```bash
cd backend
python main.py
```

The backend will start on `http://localhost:8000`

### Start Frontend Development Server

```bash
cd frontend
npm start
```

The frontend will start on `http://localhost:3000`

## 📊 API Endpoints

### Traffic & Monitoring
- `GET /api/traffic/logs` - Get network traffic logs
- `GET /api/alerts` - Get IDS alerts with filtering
- `GET /api/honeypot` - Get honeypot activity logs
- `POST /api/simulate` - Generate dummy traffic for testing

### Analysis & Rules
- `POST /api/analyze` - Analyze specific traffic data
- `GET /api/rules` - Get current regex detection rules
- `POST /api/rules` - Add new detection rule

### System Status
- `GET /api/system/status` - Get overall system status
- `GET /api/dashboard/metrics` - Get dashboard metrics

## 🔧 Configuration

### Backend Configuration
- **Rate Limiting**: Configured via SlowAPI (30 requests/minute for most endpoints)
- **CORS**: Allows localhost:3000 for development
- **Security**: RSA-2048 signatures, AES-256-GCM encryption, HMAC-SHA256

### Frontend Configuration
- **API Base URL**: `http://localhost:8000`
- **Update Intervals**: 
  - Dashboard: 30 seconds
  - Traffic Monitor: 10 seconds
  - Alerts: 15 seconds
  - Honeypot: 20 seconds

## 🎯 Usage Examples

### Simulate Traffic
```bash
curl -X POST "http://localhost:8000/api/simulate?traffic_type=mixed&count=20"
```

### Add Detection Rule
```bash
curl -X POST "http://localhost:8000/api/rules" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Custom SQL Injection",
    "pattern": "(union|select).*from.*users",
    "severity": "High"
  }'
```

### Analyze Traffic
```bash
curl -X POST "http://localhost:8000/api/analyze" \
  -H "Content-Type: application/json" \
  -d '{
    "source_ip": "192.168.1.100",
    "destination_ip": "10.0.0.1",
    "protocol": "HTTP",
    "port": 80,
    "payload": "GET /admin?id=1 UNION SELECT * FROM users--"
  }'
```

## 🔒 Security Features

### Implemented Security Measures
- **SSL/TLS Encryption**: Secure API communication
- **Digital Signatures**: RSA-2048 with PSS padding for message integrity
- **HMAC Verification**: SHA-256 for data integrity
- **Rate Limiting**: Protection against DoS attacks
- **Input Validation**: Regex pattern validation and sanitization

### Detection Capabilities
- **SQL Injection**: Pattern-based detection with ML validation
- **XSS Attacks**: Script tag and JavaScript injection detection
- **Command Injection**: Shell command pattern recognition
- **Directory Traversal**: Path manipulation detection
- **Port Scanning**: Network reconnaissance detection
- **Brute Force**: Login attempt pattern analysis

## 📈 Monitoring & Alerts

### Alert Severity Levels
- **High**: Critical threats requiring immediate action
- **Medium**: Suspicious activity requiring investigation
- **Low**: Informational alerts for monitoring

### Dashboard Metrics
- Real-time traffic analysis
- Threat distribution charts
- Honeypot interaction statistics
- System health monitoring
- Security module status

## 🐛 Troubleshooting

### Common Issues

1. **Backend not starting**:
   - Check Python version (3.8+)
   - Verify all dependencies installed
   - Ensure port 8000 is available

2. **Frontend connection errors**:
   - Verify backend is running on port 8000
   - Check CORS configuration
   - Ensure API endpoints are accessible

3. **Missing data**:
   - Run `/api/simulate` to generate dummy data
   - Check data directory permissions
   - Verify JSON files are created in `backend/data/`

### Development Mode
- Backend runs with auto-reload enabled
- Frontend has hot module replacement
- Debug logs available in console

## 🤝 Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit changes (`git commit -m 'Add AmazingFeature'`)
4. Push to branch (`git push origin feature/AmazingFeature`)
5. Open Pull Request

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- FastAPI for the robust backend framework
- React and TypeScript for the frontend
- Tailwind CSS for styling
- Framer Motion for animations
- Recharts for data visualization
- Scikit-learn for ML capabilities

## 📞 Support

For support and questions:
- Create an issue in the repository
- Check the troubleshooting section
- Review API documentation

---

**SecureGuard IDS v1.0** - Advanced Intrusion Detection System with ML-powered threat analysis.
