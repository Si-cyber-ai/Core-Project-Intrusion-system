import json
import socket
import threading
import time
from datetime import datetime
from typing import Dict, List, Any
import logging
import random

class HoneypotModule:
    def __init__(self):
        self.active_connections = {}
        self.interaction_logs = []
        self.honeypot_ports = [2222, 8080, 9090, 3306, 5432]  # SSH, HTTP, MySQL, PostgreSQL
        self.is_running = False
        self.threads = []
        
        # Setup logging
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
        
        # Load existing logs
        self._load_logs()
        
    def _load_logs(self):
        """Load existing honeypot logs from file"""
        try:
            with open('data/honeypot.json', 'r') as f:
                self.interaction_logs = json.load(f)
        except FileNotFoundError:
            self.interaction_logs = []
        except Exception as e:
            self.logger.error(f"Error loading honeypot logs: {e}")
            self.interaction_logs = []
    
    def _save_logs(self):
        """Save honeypot logs to file"""
        try:
            with open('data/honeypot.json', 'w') as f:
                json.dump(self.interaction_logs, f, indent=2)
        except Exception as e:
            self.logger.error(f"Error saving honeypot logs: {e}")
    
    def log_interaction(self, attacker_ip: str, port: int, payload: str, interaction_type: str):
        """Log honeypot interaction"""
        interaction = {
            "timestamp": datetime.now().isoformat(),
            "attacker_ip": attacker_ip,
            "port": port,
            "payload": payload,
            "interaction_type": interaction_type,
            "severity": self._assess_severity(payload, interaction_type),
            "geolocation": self._get_fake_geolocation(),
            "user_agent": self._extract_user_agent(payload),
            "attack_vector": self._identify_attack_vector(payload)
        }
        
        self.interaction_logs.append(interaction)
        self._save_logs()
        
        self.logger.info(f"Honeypot interaction logged: {attacker_ip}:{port} - {interaction_type}")
    
    def _assess_severity(self, payload: str, interaction_type: str) -> str:
        """Assess the severity of the honeypot interaction"""
        high_risk_patterns = [
            'rm -rf', 'wget', 'curl', 'nc -e', 'bash -i',
            'python -c', 'perl -e', 'php -r', '/bin/sh',
            'union select', 'drop table', 'exec master',
            'script>', 'javascript:', 'eval('
        ]
        
        medium_risk_patterns = [
            'admin', 'root', 'password', 'login',
            'config', 'backup', 'database', 'user'
        ]
        
        payload_lower = payload.lower()
        
        if any(pattern in payload_lower for pattern in high_risk_patterns):
            return "High"
        elif any(pattern in payload_lower for pattern in medium_risk_patterns):
            return "Medium"
        elif interaction_type in ['brute_force', 'port_scan']:
            return "Medium"
        else:
            return "Low"
    
    def _get_fake_geolocation(self) -> Dict[str, str]:
        """Generate fake geolocation data for demo purposes"""
        locations = [
            {"country": "Russia", "city": "Moscow", "region": "Moscow"},
            {"country": "China", "city": "Beijing", "region": "Beijing"},
            {"country": "North Korea", "city": "Pyongyang", "region": "Pyongyang"},
            {"country": "Iran", "city": "Tehran", "region": "Tehran"},
            {"country": "Brazil", "city": "São Paulo", "region": "São Paulo"},
            {"country": "India", "city": "Mumbai", "region": "Maharashtra"},
            {"country": "Ukraine", "city": "Kiev", "region": "Kiev"},
            {"country": "Romania", "city": "Bucharest", "region": "Bucharest"}
        ]
        return random.choice(locations)
    
    def _extract_user_agent(self, payload: str) -> str:
        """Extract or generate user agent from payload"""
        if "User-Agent:" in payload:
            lines = payload.split('\n')
            for line in lines:
                if line.startswith('User-Agent:'):
                    return line.split(':', 1)[1].strip()
        
        # Return common malicious user agents
        malicious_agents = [
            "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)",
            "curl/7.68.0",
            "wget/1.20.3",
            "python-requests/2.25.1",
            "Nmap Scripting Engine",
            "sqlmap/1.4.7",
            "Nikto/2.1.6"
        ]
        return random.choice(malicious_agents)
    
    def _identify_attack_vector(self, payload: str) -> str:
        """Identify the type of attack vector"""
        payload_lower = payload.lower()
        
        if any(sql in payload_lower for sql in ['union', 'select', 'insert', 'drop', 'exec']):
            return "SQL Injection"
        elif any(xss in payload_lower for xss in ['<script', 'javascript:', 'onerror=']):
            return "Cross-Site Scripting (XSS)"
        elif any(cmd in payload_lower for cmd in ['wget', 'curl', 'nc -e', 'bash']):
            return "Command Injection"
        elif '../' in payload or '..\\' in payload:
            return "Directory Traversal"
        elif any(brute in payload_lower for brute in ['admin', 'root', 'password']):
            return "Brute Force"
        elif 'nmap' in payload_lower or 'scan' in payload_lower:
            return "Port Scanning"
        else:
            return "Unknown/Reconnaissance"
    
    def simulate_ssh_honeypot(self, attacker_ip: str):
        """Simulate SSH honeypot interaction"""
        common_attempts = [
            "admin:admin",
            "root:password",
            "root:123456",
            "admin:password",
            "user:user",
            "test:test",
            "guest:guest",
            "oracle:oracle"
        ]
        
        attempt = random.choice(common_attempts)
        username, password = attempt.split(':')
        
        payload = f"SSH Login Attempt - Username: {username}, Password: {password}"
        self.log_interaction(attacker_ip, 22, payload, "ssh_brute_force")
    
    def simulate_web_honeypot(self, attacker_ip: str):
        """Simulate web honeypot interaction"""
        web_attacks = [
            "GET /admin/login.php HTTP/1.1",
            "POST /wp-admin/admin-ajax.php HTTP/1.1\nContent-Type: application/x-www-form-urlencoded\naction=revslider_show_image&img=../wp-config.php",
            "GET /index.php?id=1' UNION SELECT 1,2,3,user(),database(),version()-- HTTP/1.1",
            "GET /search.php?q=<script>alert('XSS')</script> HTTP/1.1",
            "GET /.env HTTP/1.1",
            "GET /phpinfo.php HTTP/1.1",
            "POST /upload.php HTTP/1.1\nContent-Type: multipart/form-data\nfile=shell.php"
        ]
        
        attack = random.choice(web_attacks)
        self.log_interaction(attacker_ip, 80, attack, "web_attack")
    
    def simulate_database_honeypot(self, attacker_ip: str):
        """Simulate database honeypot interaction"""
        db_attacks = [
            "SELECT * FROM users WHERE username='admin'--",
            "SHOW DATABASES;",
            "USE mysql; SELECT user,password FROM user;",
            "INSERT INTO users (username,password) VALUES ('hacker','pwned');",
            "DROP TABLE users;--",
            "EXEC xp_cmdshell 'net user hacker password123 /add';"
        ]
        
        attack = random.choice(db_attacks)
        port = random.choice([3306, 5432, 1433])  # MySQL, PostgreSQL, SQL Server
        self.log_interaction(attacker_ip, port, attack, "database_attack")
    
    def generate_fake_interactions(self, count: int = 10):
        """Generate fake honeypot interactions for demo purposes"""
        fake_ips = [
            "192.168.1.100", "10.0.0.50", "172.16.0.25",
            "203.0.113.45", "198.51.100.78", "192.0.2.123",
            "185.220.101.42", "91.198.174.192", "123.45.67.89"
        ]
        
        attack_types = [
            self.simulate_ssh_honeypot,
            self.simulate_web_honeypot,
            self.simulate_database_honeypot
        ]
        
        for _ in range(count):
            attacker_ip = random.choice(fake_ips)
            attack_func = random.choice(attack_types)
            attack_func(attacker_ip)
            time.sleep(0.1)  # Small delay between attacks
    
    def get_recent_interactions(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Get honeypot interactions from the last N hours"""
        cutoff_time = datetime.now() - timedelta(hours=hours)
        
        recent_interactions = []
        for interaction in self.interaction_logs:
            try:
                interaction_time = datetime.fromisoformat(interaction['timestamp'])
                if interaction_time >= cutoff_time:
                    recent_interactions.append(interaction)
            except ValueError:
                continue
        
        return sorted(recent_interactions, key=lambda x: x['timestamp'], reverse=True)
    
    def get_attacker_statistics(self) -> Dict[str, Any]:
        """Get statistics about attackers"""
        if not self.interaction_logs:
            return {}
        
        attacker_ips = {}
        attack_vectors = {}
        countries = {}
        
        for interaction in self.interaction_logs:
            # Count by IP
            ip = interaction.get('attacker_ip', 'Unknown')
            attacker_ips[ip] = attacker_ips.get(ip, 0) + 1
            
            # Count by attack vector
            vector = interaction.get('attack_vector', 'Unknown')
            attack_vectors[vector] = attack_vectors.get(vector, 0) + 1
            
            # Count by country
            country = interaction.get('geolocation', {}).get('country', 'Unknown')
            countries[country] = countries.get(country, 0) + 1
        
        return {
            "total_interactions": len(self.interaction_logs),
            "unique_attackers": len(attacker_ips),
            "top_attackers": sorted(attacker_ips.items(), key=lambda x: x[1], reverse=True)[:10],
            "attack_vectors": attack_vectors,
            "top_countries": sorted(countries.items(), key=lambda x: x[1], reverse=True)[:10]
        }
    
    def get_honeypot_status(self) -> Dict[str, Any]:
        """Get current honeypot status"""
        recent_interactions = self.get_recent_interactions(1)  # Last hour
        
        return {
            "is_active": True,
            "monitored_ports": self.honeypot_ports,
            "recent_interactions": len(recent_interactions),
            "total_interactions": len(self.interaction_logs),
            "last_interaction": self.interaction_logs[-1]['timestamp'] if self.interaction_logs else None,
            "threat_level": self._calculate_threat_level(recent_interactions)
        }
    
    def _calculate_threat_level(self, recent_interactions: List[Dict[str, Any]]) -> str:
        """Calculate current threat level based on recent activity"""
        if not recent_interactions:
            return "Low"
        
        high_severity_count = sum(1 for i in recent_interactions if i.get('severity') == 'High')
        total_count = len(recent_interactions)
        
        if high_severity_count > 5 or total_count > 20:
            return "High"
        elif high_severity_count > 2 or total_count > 10:
            return "Medium"
        else:
            return "Low"
