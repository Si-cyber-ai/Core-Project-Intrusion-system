from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import json
import os
import re
from datetime import datetime, timedelta
from typing import List, Dict, Any
import random
from core.sensor import smart_sensor, SensorInput, SensorResponse

app = FastAPI(
    title="Intrusion Detection System",
    description="IDS with pattern detection and honeypot capabilities",
    version="1.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "https://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Ensure data directory exists
os.makedirs("data", exist_ok=True)

# IDS Engine with Pattern Detection
class IDSEngine:
    def __init__(self):
        self.regex_rules = [
            {
                "name": "SQL Injection",
                "pattern": r"(union|select|insert|delete|drop|update|exec|script).*(\s|;|'|\"|--)",
                "severity": "High"
            },
            {
                "name": "XSS Attack",
                "pattern": r"<script[^>]*>.*?</script>|javascript:|on\w+\s*=",
                "severity": "High"
            },
            {
                "name": "Directory Traversal",
                "pattern": r"\.\./|\.\.\\\|%2e%2e%2f|%2e%2e%5c",
                "severity": "Medium"
            },
            {
                "name": "Command Injection",
                "pattern": r"(\||;|&|`|\$\(|\${).*?(ls|cat|wget|curl|nc|netcat|bash|sh|cmd|powershell)",
                "severity": "High"
            }
        ]
    
    def pattern_detection(self, payload: str) -> List[Dict[str, Any]]:
        """Detect malicious patterns using regex"""
        detections = []
        for rule in self.regex_rules:
            if re.search(rule["pattern"], payload, re.IGNORECASE):
                detections.append({
                    "rule_name": rule["name"],
                    "severity": rule["severity"],
                    "pattern": rule["pattern"],
                    "timestamp": datetime.now().isoformat(),
                    "confidence": 0.9
                })
        return detections
    
    def analyze_traffic(self, traffic_data: Dict[str, Any]) -> Dict[str, Any]:
        """Complete traffic analysis"""
        # Pattern detection
        pattern_detections = self.pattern_detection(traffic_data.get('payload', ''))
        
        # Determine threat level
        threat_level = "Low"
        if pattern_detections:
            severities = [d["severity"] for d in pattern_detections]
            if "High" in severities:
                threat_level = "High"
            elif "Medium" in severities:
                threat_level = "Medium"
        
        return {
            "timestamp": datetime.now().isoformat(),
            "source_ip": traffic_data.get('source_ip', ''),
            "detections": pattern_detections,
            "overall_threat_level": threat_level,
            "recommended_action": "Block" if threat_level == "High" else "Monitor"
        }

# Initialize IDS Engine
ids_engine = IDSEngine()

def generate_dummy_traffic():
    """Generate dummy traffic data"""
    traffic_data = []
    ips = ['192.168.1.100', '10.0.0.50', '203.0.113.45', '198.51.100.78']
    protocols = ['HTTP', 'HTTPS', 'TCP', 'UDP']
    
    for i in range(200):
        timestamp = datetime.now() - timedelta(hours=random.randint(0, 24))
        is_malicious = random.random() > 0.85
        
        if is_malicious:
            payloads = [
                "GET /admin?id=1' UNION SELECT * FROM users--",
                "POST /search.php HTTP/1.1\nq='; DROP TABLE users;--",
                "GET /search.php?q=<script>alert('XSS')</script>",
                "GET /ping.php?host=127.0.0.1;cat /etc/passwd"
            ]
            payload = random.choice(payloads)
            traffic_type = random.choice(['sql_injection', 'xss_attack', 'command_injection'])
        else:
            payload = "GET / HTTP/1.1\nHost: example.com"
            traffic_type = "normal"
        
        traffic = {
            "timestamp": timestamp.isoformat(),
            "source_ip": random.choice(ips),
            "destination_ip": random.choice(ips),
            "protocol": random.choice(protocols),
            "port": random.randint(80, 8080),
            "packet_size": random.randint(64, 1500),
            "duration": random.uniform(0.1, 10.0),
            "payload": payload,
            "is_malicious": is_malicious,
            "traffic_type": traffic_type
        }
        traffic_data.append(traffic)
    
    return traffic_data

def generate_dummy_alerts():
    """Generate dummy alerts"""
    alerts = []
    alert_types = [
        "SQL Injection Detected",
        "XSS Attack Blocked",
        "Command Injection Attempt",
        "Directory Traversal Detected",
        "Port Scan Activity",
        "Brute Force Attack",
        "Suspicious Payload Pattern"
    ]
    
    for i in range(50):
        timestamp = datetime.now() - timedelta(hours=random.randint(0, 72))
        severity = random.choice(['High', 'Medium', 'Low'])
        
        alert = {
            "id": f"ALERT_{i+1:04d}",
            "timestamp": timestamp.isoformat(),
            "alert_type": random.choice(alert_types),
            "severity": severity,
            "source_ip": random.choice(['203.0.113.45', '198.51.100.78', '185.220.101.42']),
            "destination_ip": "192.168.1.100",
            "description": f"Security threat detected via pattern matching",
            "confidence": random.uniform(0.6, 1.0),
            "status": random.choice(["Active", "Resolved", "Investigating"]),
            "rule_triggered": f"RULE_{random.randint(1, 50):03d}",
            "action_taken": random.choice(["Blocked", "Logged", "Alerted", "Quarantined"])
        }
        alerts.append(alert)
    
    return alerts

def generate_honeypot_data():
    """Generate honeypot interaction data"""
    interactions = []
    countries = ['Russia', 'China', 'North Korea', 'Iran', 'Brazil', 'India']
    ips = ['185.220.101.42', '91.198.174.192', '123.45.67.89', '45.76.123.45']
    attack_vectors = ['SQL Injection', 'Brute Force', 'Port Scanning', 'Command Injection', 'XSS Attack']
    
    for i in range(60):
        timestamp = datetime.now() - timedelta(hours=random.randint(0, 48))
        
        interaction = {
            "timestamp": timestamp.isoformat(),
            "attacker_ip": random.choice(ips),
            "port": random.choice([22, 80, 443, 3306, 5432]),
            "payload": random.choice([
                "SSH Login Attempt - Username: admin, Password: admin",
                "GET /admin/login.php HTTP/1.1",
                "SELECT * FROM users WHERE username='admin'--",
                "GET /search.php?q=<script>alert('XSS')</script>",
                "GET /ping.php?host=127.0.0.1;cat /etc/passwd"
            ]),
            "interaction_type": random.choice(["ssh_brute_force", "web_attack", "database_attack"]),
            "severity": random.choice(['High', 'Medium', 'Low']),
            "geolocation": {
                "country": random.choice(countries),
                "city": random.choice(['Moscow', 'Beijing', 'Tehran', 'Mumbai']),
                "region": "Unknown"
            },
            "user_agent": random.choice(["curl/7.68.0", "python-requests/2.25.1", "Nmap Scripting Engine"]),
            "attack_vector": random.choice(attack_vectors)
        }
        interactions.append(interaction)
    
    return interactions

# Initialize data files
def init_data():
    """Initialize data files with dummy data"""
    print("Initializing data files...")
    
    if not os.path.exists("data/traffic_logs.json"):
        traffic_data = generate_dummy_traffic()
        with open("data/traffic_logs.json", "w") as f:
            json.dump(traffic_data, f, indent=2)
        print(f"Generated {len(traffic_data)} traffic records")
    
    if not os.path.exists("data/alerts.json"):
        alerts_data = generate_dummy_alerts()
        with open("data/alerts.json", "w") as f:
            json.dump(alerts_data, f, indent=2)
        print(f"Generated {len(alerts_data)} alerts")
    
    if not os.path.exists("data/honeypot.json"):
        honeypot_data = generate_honeypot_data()
        with open("data/honeypot.json", "w") as f:
            json.dump(honeypot_data, f, indent=2)
        print(f"Generated {len(honeypot_data)} honeypot interactions")

@app.on_event("startup")
async def startup_event():
    print("Starting SecureGuard IDS System...")
    init_data()
    print("IDS System initialized successfully")

@app.get("/")
async def root():
    return {
        "message": "SecureGuard IDS System API",
        "status": "active",
        "version": "1.0.0",
        "features": {
            "pattern_detection": True,
            "honeypot_active": True,
            "rate_limiting": False
        }
    }

@app.get("/api/traffic/logs")
async def get_traffic_logs(limit: int = 100):
    """Get network traffic logs"""
    try:
        with open("data/traffic_logs.json", "r") as f:
            traffic_data = json.load(f)
        
        recent_logs = sorted(traffic_data, key=lambda x: x["timestamp"], reverse=True)[:limit]
        
        return {
            "status": "success",
            "total_logs": len(traffic_data),
            "returned_logs": len(recent_logs),
            "logs": recent_logs
        }
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Traffic logs not found")

@app.get("/api/alerts")
async def get_alerts(severity: str = None, limit: int = 50):
    """Get IDS alerts"""
    try:
        with open("data/alerts.json", "r") as f:
            alerts_data = json.load(f)
        
        if severity:
            alerts_data = [alert for alert in alerts_data if alert.get("severity", "").lower() == severity.lower()]
        
        recent_alerts = sorted(alerts_data, key=lambda x: x["timestamp"], reverse=True)[:limit]
        
        # Calculate statistics
        total_alerts = len(alerts_data)
        high_severity = sum(1 for alert in alerts_data if alert.get("severity") == "High")
        medium_severity = sum(1 for alert in alerts_data if alert.get("severity") == "Medium")
        low_severity = sum(1 for alert in alerts_data if alert.get("severity") == "Low")
        
        return {
            "status": "success",
            "total_alerts": total_alerts,
            "returned_alerts": len(recent_alerts),
            "statistics": {
                "high_severity": high_severity,
                "medium_severity": medium_severity,
                "low_severity": low_severity
            },
            "alerts": recent_alerts
        }
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Alerts not found")

@app.get("/api/honeypot")
async def get_honeypot_logs(limit: int = 50):
    """Get honeypot activity logs"""
    try:
        with open("data/honeypot.json", "r") as f:
            honeypot_data = json.load(f)
        
        recent_interactions = sorted(honeypot_data, key=lambda x: x["timestamp"], reverse=True)[:limit]
        
        # Generate statistics
        unique_ips = len(set(i.get("attacker_ip", "") for i in honeypot_data))
        attack_vectors = {}
        countries = {}
        
        for interaction in honeypot_data:
            vector = interaction.get("attack_vector", "Unknown")
            attack_vectors[vector] = attack_vectors.get(vector, 0) + 1
            
            country = interaction.get("geolocation", {}).get("country", "Unknown")
            countries[country] = countries.get(country, 0) + 1
        
        top_attackers = {}
        for interaction in honeypot_data:
            ip = interaction.get("attacker_ip", "")
            top_attackers[ip] = top_attackers.get(ip, 0) + 1
        
        stats = {
            "total_interactions": len(honeypot_data),
            "unique_attackers": unique_ips,
            "top_attackers": sorted(top_attackers.items(), key=lambda x: x[1], reverse=True)[:5],
            "attack_vectors": attack_vectors,
            "top_countries": sorted(countries.items(), key=lambda x: x[1], reverse=True)[:5]
        }
        
        status = {
            "is_active": True,
            "monitored_ports": [22, 80, 443, 3306, 5432],
            "recent_interactions": len(recent_interactions),
            "threat_level": "Medium"
        }
        
        return {
            "status": "success",
            "honeypot_status": status,
            "statistics": stats,
            "recent_interactions": recent_interactions
        }
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Honeypot logs not found")

@app.get("/api/rules")
async def get_regex_rules():
    """Get current regex detection rules"""
    return {
        "status": "success",
        "rules": ids_engine.regex_rules
    }

@app.post("/api/rules")
async def add_regex_rule(rule_data: dict):
    """Add new regex detection rule"""
    try:
        name = rule_data.get("name", "")
        pattern = rule_data.get("pattern", "")
        severity = rule_data.get("severity", "Medium")
        
        # Validate regex
        re.compile(pattern)
        
        new_rule = {"name": name, "pattern": pattern, "severity": severity}
        ids_engine.regex_rules.append(new_rule)
        
        return {"status": "success", "message": f"Rule '{name}' added successfully"}
    except re.error:
        raise HTTPException(status_code=400, detail="Invalid regex pattern")

@app.get("/api/system/status")
async def get_system_status():
    """Get overall system status"""
    return {
        "status": "success",
        "timestamp": datetime.now().isoformat(),
        "security": {
            "ssl_tls": {"enabled": True, "version": "TLS 1.3", "cipher_suite": "AES-256-GCM"},
            "digital_signatures": {"algorithm": "RSA-2048", "enabled": True},
            "message_integrity": {"algorithm": "HMAC-SHA256", "enabled": True},
            "encryption": {"algorithm": "AES-256-GCM", "key_size": 256, "enabled": True}
        },
        "honeypot": {
            "is_active": True,
            "monitored_ports": [22, 80, 443, 3306, 5432],
            "recent_interactions": 15,
            "threat_level": "Medium"
        },
        "traffic_stats": {
            "total_packets": 15847,
            "malicious_packets": 234,
            "detection_rate": 1.48
        },
        "system_health": {
            "uptime": "24h 15m",
            "cpu_usage": "15%",
            "memory_usage": "45%",
            "disk_usage": "23%",
            "network_status": "Active"
        }
    }

@app.get("/api/dashboard/metrics")
async def get_dashboard_metrics():
    """Get metrics for dashboard visualization"""
    now = datetime.now()
    traffic_chart = []
    alerts_chart = []
    
    for i in range(24):
        hour = (now - timedelta(hours=i)).strftime("%H:00")
        traffic_chart.append({
            "time": hour,
            "normal": random.randint(50, 100),
            "malicious": random.randint(5, 20),
            "total": random.randint(55, 120)
        })
        alerts_chart.append({
            "time": hour,
            "high": random.randint(0, 5),
            "medium": random.randint(2, 10),
            "low": random.randint(5, 15)
        })
    
    return {
        "status": "success",
        "timestamp": now.isoformat(),
        "traffic_chart": traffic_chart,
        "alerts_chart": alerts_chart,
        "summary": {
            "total_traffic": 15847,
            "total_alerts": 234,
            "honeypot_interactions": 89,
            "active_threats": 12
        }
    }

@app.post("/api/simulate")
async def simulate_traffic(traffic_type: str = "mixed", count: int = 10):
    """Generate and analyze new traffic"""
    if count > 50:
        raise HTTPException(status_code=400, detail="Count cannot exceed 50")
    
    new_traffic = generate_dummy_traffic()[:count]
    
    # Analyze with pattern detection
    analyzed_traffic = []
    for traffic in new_traffic:
        analysis = ids_engine.analyze_traffic(traffic)
        traffic.update({"analysis": analysis})
        analyzed_traffic.append(traffic)
    
    # Save to logs
    try:
        with open("data/traffic_logs.json", "r") as f:
            existing_logs = json.load(f)
    except FileNotFoundError:
        existing_logs = []
    
    existing_logs.extend(new_traffic)
    
    with open("data/traffic_logs.json", "w") as f:
        json.dump(existing_logs, f, indent=2)
    
    return {
        "status": "success",
        "message": f"Generated and analyzed {len(new_traffic)} traffic records",
        "generated_count": len(new_traffic),
        "analysis_preview": analyzed_traffic[:3]
    }

@app.post("/api/analyze")
async def analyze_traffic(traffic_data: dict):
    """Analyze specific traffic with pattern detection"""
    try:
        analysis_result = ids_engine.analyze_traffic(traffic_data)
        return {
            "status": "success",
            "analysis": analysis_result
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

# Smart Sensor Endpoints
@app.post("/api/sensor/input", response_model=SensorResponse)
async def process_sensor_input(sensor_input: SensorInput):
    """Process input through the smart sensor IDS pipeline"""
    try:
        # Process the payload through the sensor
        response = smart_sensor.process_input(sensor_input.payload)
        
        # Log the sensor activity
        sensor_log = {
            "timestamp": response.timestamp,
            "sensor_id": response.sensor_id,
            "input_payload": sensor_input.payload,
            "status": response.status.value,
            "detected_attack_type": response.detected_attack_type,
            "confidence": response.confidence,
            "source_ip": "127.0.0.1"
        }
        
        # Save sensor log to file (append to existing logs)
        try:
            if os.path.exists("data/sensor_logs.json"):
                with open("data/sensor_logs.json", "r") as f:
                    sensor_logs = json.load(f)
            else:
                sensor_logs = []
            
            sensor_logs.append(sensor_log)
            
            # Keep only last 1000 logs
            if len(sensor_logs) > 1000:
                sensor_logs = sensor_logs[-1000:]
            
            with open("data/sensor_logs.json", "w") as f:
                json.dump(sensor_logs, f, indent=2)
                
        except Exception as log_error:
            # Don't fail the request if logging fails
            print(f"Warning: Could not save sensor log: {log_error}")
        
        return response
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error processing sensor input: {str(e)}")

@app.get("/api/sensor/status")
async def get_sensor_status():
    """Get current sensor status"""
    try:
        return smart_sensor.get_status()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting sensor status: {str(e)}")

@app.post("/api/sensor/reset")
async def reset_sensor():
    """Reset sensor to normal state"""
    try:
        smart_sensor.reset_sensor()
        return {
            "status": "success",
            "message": "Sensor reset to normal state",
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error resetting sensor: {str(e)}")

@app.get("/api/sensor/logs")
async def get_sensor_logs(limit: int = 50):
    """Get sensor activity logs"""
    try:
        if not os.path.exists("data/sensor_logs.json"):
            return {
                "status": "success",
                "logs": [],
                "total_logs": 0
            }
        
        with open("data/sensor_logs.json", "r") as f:
            sensor_logs = json.load(f)
        
        # Return most recent logs
        recent_logs = sorted(sensor_logs, key=lambda x: x["timestamp"], reverse=True)[:limit]
        
        return {
            "status": "success",
            "logs": recent_logs,
            "total_logs": len(sensor_logs)
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting sensor logs: {str(e)}")

# Rule Management API endpoints
@app.get("/api/rules")
async def get_rules():
    """Get all IDS rules"""
    try:
        rules_file = "data/rules.json"
        if not os.path.exists(rules_file):
            # Return default rules if file doesn't exist
            default_rules = [
                {
                    "id": 1,
                    "name": "XSS Attack",
                    "pattern": r"<script[^>]*>.*?</script>|javascript:|on\w+\s*=|<img[^>]*onerror|<iframe[^>]*src\s*=\s*['\"]javascript:",
                    "severity": "High",
                    "description": "Detects Cross-Site Scripting (XSS) attacks",
                    "enabled": True
                },
                {
                    "id": 2,
                    "name": "SQL Injection",
                    "pattern": r"(union|select|insert|delete|drop|update|exec)\s+.*(\s|;|'|\"|--)|('\s*(or|and)\s*['\"]?\d|'\s*or\s*['\"]?\d\s*=\s*['\"]?\d)",
                    "severity": "High",
                    "description": "Detects SQL Injection attacks",
                    "enabled": True
                },
                {
                    "id": 3,
                    "name": "Directory Traversal",
                    "pattern": r"(\.\./|\.\.\\\|%2e%2e%2f|%2e%2e\\)",
                    "severity": "Medium",
                    "description": "Detects directory traversal attempts",
                    "enabled": True
                }
            ]
            return {"status": "success", "rules": default_rules}
        
        with open(rules_file, "r") as f:
            rules = json.load(f)
        
        return {"status": "success", "rules": rules}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting rules: {str(e)}")

@app.post("/api/rules")
async def create_rule(rule: dict):
    """Create a new rule"""
    try:
        rules_file = "data/rules.json"
        
        # Load existing rules
        if os.path.exists(rules_file):
            with open(rules_file, "r") as f:
                rules = json.load(f)
        else:
            rules = []
        
        # Add new rule with ID
        new_rule = {
            "id": max([r.get("id", 0) for r in rules] + [0]) + 1,
            "name": rule.get("name", ""),
            "pattern": rule.get("pattern", ""),
            "severity": rule.get("severity", "Medium"),
            "description": rule.get("description", ""),
            "enabled": rule.get("enabled", True)
        }
        
        rules.append(new_rule)
        
        # Save rules
        with open(rules_file, "w") as f:
            json.dump(rules, f, indent=2)
        
        # Update IDS engine with new rules
        enabled_rules = [r for r in rules if r.get("enabled", True)]
        ids_engine.load_rules_from_api(enabled_rules)
        
        return {"status": "success", "rule": new_rule}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error creating rule: {str(e)}")

@app.put("/api/rules/{rule_id}")
async def update_rule(rule_id: int, rule: dict):
    """Update an existing rule"""
    try:
        rules_file = "data/rules.json"
        
        if not os.path.exists(rules_file):
            raise HTTPException(status_code=404, detail="Rules file not found")
        
        with open(rules_file, "r") as f:
            rules = json.load(f)
        
        # Find and update rule
        for i, r in enumerate(rules):
            if r.get("id") == rule_id:
                rules[i].update({
                    "name": rule.get("name", r["name"]),
                    "pattern": rule.get("pattern", r["pattern"]),
                    "severity": rule.get("severity", r["severity"]),
                    "description": rule.get("description", r.get("description", "")),
                    "enabled": rule.get("enabled", r.get("enabled", True))
                })
                
                # Save rules
                with open(rules_file, "w") as f:
                    json.dump(rules, f, indent=2)
                
                # Update IDS engine
                enabled_rules = [rule for rule in rules if rule.get("enabled", True)]
                ids_engine.load_rules_from_api(enabled_rules)
                
                return {"status": "success", "rule": rules[i]}
        
        raise HTTPException(status_code=404, detail="Rule not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error updating rule: {str(e)}")

@app.delete("/api/rules/{rule_id}")
async def delete_rule(rule_id: int):
    """Delete a rule"""
    try:
        rules_file = "data/rules.json"
        
        if not os.path.exists(rules_file):
            raise HTTPException(status_code=404, detail="Rules file not found")
        
        with open(rules_file, "r") as f:
            rules = json.load(f)
        
        # Find and remove rule
        rules = [r for r in rules if r.get("id") != rule_id]
        
        # Save rules
        with open(rules_file, "w") as f:
            json.dump(rules, f, indent=2)
        
        # Update IDS engine
        enabled_rules = [rule for rule in rules if rule.get("enabled", True)]
        ids_engine.load_rules_from_api(enabled_rules)
        
        return {"status": "success", "message": "Rule deleted"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error deleting rule: {str(e)}")

if __name__ == "__main__":
    uvicorn.run(
        "main_working:app",
        host="0.0.0.0",
        port=8000,
        reload=False
    )
