import re
import json
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from typing import List, Dict, Any, Tuple
from datetime import datetime, timedelta
import logging

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
            },
            {
                "name": "Port Scan",
                "pattern": r"nmap|masscan|zmap|unicornscan",
                "severity": "Medium"
            },
            {
                "name": "Brute Force",
                "pattern": r"(admin|root|administrator|login|password).*?(admin|password|123456|qwerty)",
                "severity": "Medium"
            }
        ]
        
        self.isolation_forest = IsolationForest(
            contamination=0.1,
            random_state=42,
            n_estimators=100
        )
        
        self.random_forest = RandomForestClassifier(
            n_estimators=100,
            random_state=42,
            max_depth=10
        )
        
        self.scaler = StandardScaler()
        self.is_trained = False
        
        # Initialize logging
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
        
    def add_regex_rule(self, name: str, pattern: str, severity: str) -> bool:
        """Add a new regex rule for pattern detection"""
        try:
            # Test if pattern is valid
            re.compile(pattern)
            
            new_rule = {
                "name": name,
                "pattern": pattern,
                "severity": severity
            }
            self.regex_rules.append(new_rule)
            self.logger.info(f"Added new regex rule: {name}")
            return True
        except re.error:
            self.logger.error(f"Invalid regex pattern: {pattern}")
            return False
    
    def pattern_detection(self, payload: str) -> List[Dict[str, Any]]:
        """Detect malicious patterns using regex rules"""
        detections = []
        
        for rule in self.regex_rules:
            try:
                if re.search(rule["pattern"], payload, re.IGNORECASE):
                    detection = {
                        "rule_name": rule["name"],
                        "severity": rule["severity"],
                        "pattern": rule["pattern"],
                        "matched_text": payload,
                        "timestamp": datetime.now().isoformat(),
                        "confidence": 0.9
                    }
                    detections.append(detection)
            except Exception as e:
                self.logger.error(f"Error in pattern detection: {e}")
        
        return detections
    
    def extract_features(self, traffic_data: Dict[str, Any]) -> np.ndarray:
        """Extract numerical features from traffic data for ML analysis"""
        features = []
        
        # Basic features
        features.append(traffic_data.get('packet_size', 0))
        features.append(traffic_data.get('port', 0))
        features.append(traffic_data.get('duration', 0))
        features.append(len(traffic_data.get('payload', '')))
        
        # Protocol features (encoded)
        protocol_mapping = {'TCP': 1, 'UDP': 2, 'ICMP': 3, 'HTTP': 4, 'HTTPS': 5}
        features.append(protocol_mapping.get(traffic_data.get('protocol', ''), 0))
        
        # Time-based features
        hour = datetime.now().hour
        features.append(hour)
        features.append(1 if 22 <= hour or hour <= 6 else 0)  # Night time flag
        
        # Payload analysis features
        payload = traffic_data.get('payload', '')
        features.append(len(set(payload)))  # Unique characters
        features.append(payload.count('/'))  # Path separators
        features.append(payload.count('='))  # Query parameters
        features.append(payload.count('<'))  # HTML tags
        features.append(payload.count('script'))  # Script tags
        features.append(payload.count('union'))  # SQL keywords
        
        return np.array(features).reshape(1, -1)
    
    def train_models(self, training_data: List[Dict[str, Any]]) -> bool:
        """Train ML models with historical data"""
        try:
            if len(training_data) < 10:
                self.logger.warning("Insufficient training data")
                return False
            
            # Extract features
            features_list = []
            labels = []
            
            for data in training_data:
                features = self.extract_features(data)
                features_list.append(features.flatten())
                labels.append(1 if data.get('is_malicious', False) else 0)
            
            X = np.array(features_list)
            y = np.array(labels)
            
            # Scale features
            X_scaled = self.scaler.fit_transform(X)
            
            # Train models
            self.isolation_forest.fit(X_scaled)
            self.random_forest.fit(X_scaled, y)
            
            self.is_trained = True
            self.logger.info("ML models trained successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Error training models: {e}")
            return False
    
    def anomaly_detection(self, traffic_data: Dict[str, Any]) -> Dict[str, Any]:
        """Detect anomalies using ML models"""
        try:
            features = self.extract_features(traffic_data)
            
            if not self.is_trained:
                # Use simple heuristics if models aren't trained
                return self._heuristic_detection(traffic_data)
            
            features_scaled = self.scaler.transform(features)
            
            # Isolation Forest prediction
            isolation_score = self.isolation_forest.decision_function(features_scaled)[0]
            isolation_anomaly = self.isolation_forest.predict(features_scaled)[0] == -1
            
            # Random Forest prediction
            rf_prediction = self.random_forest.predict(features_scaled)[0]
            rf_probability = self.random_forest.predict_proba(features_scaled)[0]
            
            # Combined analysis
            confidence = max(abs(isolation_score), max(rf_probability))
            is_anomaly = isolation_anomaly or rf_prediction == 1
            
            severity = "High" if confidence > 0.8 else "Medium" if confidence > 0.5 else "Low"
            
            return {
                "is_anomaly": is_anomaly,
                "confidence": float(confidence),
                "severity": severity,
                "isolation_score": float(isolation_score),
                "rf_prediction": int(rf_prediction),
                "timestamp": datetime.now().isoformat(),
                "method": "ML_Analysis"
            }
            
        except Exception as e:
            self.logger.error(f"Error in anomaly detection: {e}")
            return self._heuristic_detection(traffic_data)
    
    def _heuristic_detection(self, traffic_data: Dict[str, Any]) -> Dict[str, Any]:
        """Fallback heuristic-based detection"""
        payload = traffic_data.get('payload', '')
        packet_size = traffic_data.get('packet_size', 0)
        port = traffic_data.get('port', 0)
        
        suspicious_score = 0
        
        # Large packet size
        if packet_size > 1500:
            suspicious_score += 0.3
        
        # Suspicious ports
        if port in [22, 23, 135, 139, 445, 1433, 3389]:
            suspicious_score += 0.2
        
        # Payload analysis
        if len(payload) > 1000:
            suspicious_score += 0.2
        
        if any(keyword in payload.lower() for keyword in ['script', 'union', 'select', 'exec']):
            suspicious_score += 0.4
        
        is_anomaly = suspicious_score > 0.5
        severity = "High" if suspicious_score > 0.8 else "Medium" if suspicious_score > 0.5 else "Low"
        
        return {
            "is_anomaly": is_anomaly,
            "confidence": suspicious_score,
            "severity": severity,
            "timestamp": datetime.now().isoformat(),
            "method": "Heuristic_Analysis"
        }
    
    def analyze_traffic(self, traffic_data: Dict[str, Any]) -> Dict[str, Any]:
        """Complete traffic analysis combining pattern detection and anomaly detection"""
        results = {
            "timestamp": datetime.now().isoformat(),
            "source_ip": traffic_data.get('source_ip', ''),
            "destination_ip": traffic_data.get('destination_ip', ''),
            "protocol": traffic_data.get('protocol', ''),
            "port": traffic_data.get('port', 0),
            "payload": traffic_data.get('payload', ''),
            "detections": [],
            "anomaly_analysis": {},
            "overall_threat_level": "Low",
            "recommended_action": "Monitor"
        }
        
        # Pattern-based detection
        pattern_detections = self.pattern_detection(traffic_data.get('payload', ''))
        results["detections"] = pattern_detections
        
        # ML-based anomaly detection
        anomaly_result = self.anomaly_detection(traffic_data)
        results["anomaly_analysis"] = anomaly_result
        
        # Determine overall threat level
        max_severity = "Low"
        if pattern_detections:
            severities = [d["severity"] for d in pattern_detections]
            if "High" in severities:
                max_severity = "High"
            elif "Medium" in severities:
                max_severity = "Medium"
        
        if anomaly_result.get("is_anomaly") and anomaly_result.get("severity") == "High":
            max_severity = "High"
        elif anomaly_result.get("is_anomaly") and max_severity == "Low":
            max_severity = "Medium"
        
        results["overall_threat_level"] = max_severity
        
        # Recommended actions
        if max_severity == "High":
            results["recommended_action"] = "Block and Alert"
        elif max_severity == "Medium":
            results["recommended_action"] = "Alert and Monitor"
        else:
            results["recommended_action"] = "Monitor"
        
        return results
