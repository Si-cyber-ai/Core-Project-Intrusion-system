import json
import re
from datetime import datetime
from typing import Dict, Any, Optional, List
from enum import Enum
from pydantic import BaseModel
from core.ids_engine import IDSEngine

class SensorStatus(str, Enum):
    NORMAL = "Normal"
    SUSPICIOUS = "Suspicious"
    ATTACK = "Attack"

class SensorInput(BaseModel):
    payload: str

class SensorResponse(BaseModel):
    sensor_id: str
    status: SensorStatus
    detected_attack_type: Optional[str] = None
    confidence: float = 0.0
    timestamp: str

class SmartSensor:
    def __init__(self, sensor_id: str = "IDS-001"):
        self.sensor_id = sensor_id
        self.status = SensorStatus.NORMAL
        self.last_input = ""
        self.detected_attack_type = None
        self.last_detection_time = None
        self.confidence = 0.0
        
        # Initialize IDS engine for detection
        self.ids_engine = IDSEngine()
        
        # Load some training data if available to improve ML detection
        self._initialize_training_data()
    
    def _initialize_training_data(self):
        """Initialize the sensor with some basic training data"""
        training_data = [
            # Normal traffic examples
            {"payload": "GET / HTTP/1.1", "is_malicious": False, "packet_size": 100, "port": 80, "protocol": "HTTP"},
            {"payload": "POST /login HTTP/1.1", "is_malicious": False, "packet_size": 150, "port": 80, "protocol": "HTTP"},
            {"payload": "Hello world", "is_malicious": False, "packet_size": 50, "port": 80, "protocol": "HTTP"},
            {"payload": "Welcome to our site", "is_malicious": False, "packet_size": 80, "port": 80, "protocol": "HTTP"},
            
            # Malicious traffic examples
            {"payload": "GET /admin?id=1 UNION SELECT * FROM users--", "is_malicious": True, "packet_size": 200, "port": 80, "protocol": "HTTP"},
            {"payload": "<script>alert('XSS')</script>", "is_malicious": True, "packet_size": 150, "port": 80, "protocol": "HTTP"},
            {"payload": "'; DROP TABLE users; --", "is_malicious": True, "packet_size": 120, "port": 80, "protocol": "HTTP"},
            {"payload": "../../../etc/passwd", "is_malicious": True, "packet_size": 100, "port": 80, "protocol": "HTTP"},
        ]
        
        # Train the models
        self.ids_engine.train_models(training_data)
    
    def _load_latest_rules(self):
        """Load latest rules from the rules file"""
        try:
            import os
            rules_file = "data/rules.json"
            if os.path.exists(rules_file):
                with open(rules_file, "r") as f:
                    rules = json.load(f)
                
                # Filter enabled rules only
                enabled_rules = [rule for rule in rules if rule.get("enabled", True)]
                if enabled_rules:
                    self.ids_engine.load_rules_from_api(enabled_rules)
        except Exception as e:
            print(f"Warning: Could not load latest rules: {e}")

    def process_input(self, payload: str) -> SensorResponse:
        """Process input payload through IDS detection pipeline"""
        self.last_input = payload
        
        # Load latest rules before processing
        self._load_latest_rules()
        
        # Create traffic data structure for IDS analysis
        traffic_data = {
            "source_ip": "127.0.0.1",
            "destination_ip": "192.168.1.100",
            "protocol": "HTTP",
            "port": 80,
            "payload": payload,
            "packet_size": len(payload),
            "duration": 0.1,
            "timestamp": datetime.now().isoformat()
        }
        
        # Run through IDS analysis pipeline
        analysis_result = self.ids_engine.analyze_traffic(traffic_data)
        
        # Determine sensor status based on analysis
        self._update_sensor_status(analysis_result)
        
        return SensorResponse(
            sensor_id=self.sensor_id,
            status=self.status,
            detected_attack_type=self.detected_attack_type,
            confidence=self.confidence,
            timestamp=datetime.now().isoformat()
        )
    
    def _update_sensor_status(self, analysis_result: Dict[str, Any]):
        """Update sensor status based on IDS analysis results"""
        detections = analysis_result.get("detections", [])
        anomaly_analysis = analysis_result.get("anomaly_analysis", {})
        overall_threat_level = analysis_result.get("overall_threat_level", "Low")
        
        # Reset status
        self.status = SensorStatus.NORMAL
        self.detected_attack_type = None
        self.confidence = 0.0
        
        # Check pattern-based detections first (highest priority)
        if detections:
            self.status = SensorStatus.ATTACK
            # Get the first high-severity detection or any detection
            high_severity_detections = [d for d in detections if d.get("severity") == "High"]
            if high_severity_detections:
                self.detected_attack_type = high_severity_detections[0]["rule_name"]
                self.confidence = high_severity_detections[0].get("confidence", 0.9)
            else:
                self.detected_attack_type = detections[0]["rule_name"]
                self.confidence = detections[0].get("confidence", 0.7)
        
        # Check ML-based anomaly detection
        elif anomaly_analysis.get("is_anomaly", False):
            confidence = anomaly_analysis.get("confidence", 0.5)
            severity = anomaly_analysis.get("severity", "Low")
            
            if severity == "High" or confidence > 0.8:
                self.status = SensorStatus.ATTACK
                self.detected_attack_type = "Unknown Attack Pattern"
                self.confidence = confidence
            elif severity == "Medium" or confidence > 0.5:
                self.status = SensorStatus.SUSPICIOUS
                self.detected_attack_type = "Anomalous Behavior"
                self.confidence = confidence
        
        # Fallback to overall threat level assessment
        elif overall_threat_level == "High":
            self.status = SensorStatus.ATTACK
            self.detected_attack_type = "High Threat Activity"
            self.confidence = 0.6
        elif overall_threat_level == "Medium":
            self.status = SensorStatus.SUSPICIOUS
            self.detected_attack_type = "Potentially Suspicious"
            self.confidence = 0.4
        
        # Update detection time
        if self.status != SensorStatus.NORMAL:
            self.last_detection_time = datetime.now()
    
    def get_status(self) -> Dict[str, Any]:
        """Get current sensor status"""
        return {
            "sensor_id": self.sensor_id,
            "status": self.status.value,
            "last_input": self.last_input,
            "detected_attack_type": self.detected_attack_type,
            "confidence": self.confidence,
            "last_detection_time": self.last_detection_time.isoformat() if self.last_detection_time else None,
            "timestamp": datetime.now().isoformat()
        }
    
    def reset_sensor(self):
        """Reset sensor to normal state"""
        self.status = SensorStatus.NORMAL
        self.detected_attack_type = None
        self.confidence = 0.0
        self.last_detection_time = None

# Global sensor instance
smart_sensor = SmartSensor()