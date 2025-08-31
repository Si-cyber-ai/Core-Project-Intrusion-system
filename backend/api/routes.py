from fastapi import APIRouter, HTTPException, Request, Depends
from slowapi import Limiter
from slowapi.util import get_remote_address
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
import json
import os
from datetime import datetime

router = APIRouter()

# Rate limiter
limiter = Limiter(key_func=get_remote_address)

class TrafficData(BaseModel):
    source_ip: str
    destination_ip: str
    protocol: str
    port: int
    payload: str
    packet_size: Optional[int] = 0
    duration: Optional[float] = 0.0

class RegexRule(BaseModel):
    name: str
    pattern: str
    severity: str

@router.get("/traffic/logs")
@limiter.limit("30/minute")
async def get_traffic_logs(request: Request, limit: int = 100):
    """Get network traffic logs"""
    try:
        with open("data/traffic_logs.json", "r") as f:
            traffic_data = json.load(f)
        
        # Return most recent logs
        recent_logs = sorted(traffic_data, key=lambda x: x["timestamp"], reverse=True)[:limit]
        
        return {
            "status": "success",
            "total_logs": len(traffic_data),
            "returned_logs": len(recent_logs),
            "logs": recent_logs
        }
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Traffic logs not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error reading traffic logs: {str(e)}")

@router.get("/alerts")
@limiter.limit("30/minute")
async def get_alerts(request: Request, severity: Optional[str] = None, limit: int = 50):
    """Get IDS alerts with optional severity filtering"""
    try:
        with open("data/alerts.json", "r") as f:
            alerts_data = json.load(f)
        
        # Filter by severity if specified
        if severity:
            alerts_data = [alert for alert in alerts_data if alert.get("severity", "").lower() == severity.lower()]
        
        # Return most recent alerts
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
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error reading alerts: {str(e)}")

@router.get("/honeypot")
@limiter.limit("30/minute")
async def get_honeypot_logs(request: Request, limit: int = 50):
    """Get honeypot activity logs"""
    try:
        # Get honeypot module from app state
        honeypot = request.app.state.honeypot
        
        # Get recent interactions
        recent_interactions = honeypot.get_recent_interactions(24)[:limit]
        
        # Get statistics
        stats = honeypot.get_attacker_statistics()
        status = honeypot.get_honeypot_status()
        
        return {
            "status": "success",
            "honeypot_status": status,
            "statistics": stats,
            "recent_interactions": recent_interactions
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error reading honeypot logs: {str(e)}")

@router.post("/simulate")
@limiter.limit("10/minute")
async def simulate_traffic(request: Request, traffic_type: str = "mixed", count: int = 10):
    """Trigger dummy traffic generation"""
    try:
        if count > 100:
            raise HTTPException(status_code=400, detail="Count cannot exceed 100")
        
        data_generator = request.app.state.data_generator
        ids_engine = request.app.state.ids_engine
        honeypot = request.app.state.honeypot
        
        generated_data = []
        
        if traffic_type in ["normal", "mixed"]:
            normal_count = count if traffic_type == "normal" else count // 2
            normal_traffic = data_generator.generate_normal_traffic(normal_count)
            generated_data.extend(normal_traffic)
        
        if traffic_type in ["malicious", "mixed"]:
            malicious_count = count if traffic_type == "malicious" else count // 2
            malicious_traffic = data_generator.generate_malicious_traffic(malicious_count)
            generated_data.extend(malicious_traffic)
        
        if traffic_type == "honeypot":
            honeypot.generate_fake_interactions(count)
            return {
                "status": "success",
                "message": f"Generated {count} honeypot interactions",
                "traffic_type": traffic_type
            }
        
        # Analyze generated traffic with IDS
        analysis_results = []
        for traffic in generated_data:
            analysis = ids_engine.analyze_traffic(traffic)
            analysis_results.append(analysis)
        
        # Save updated traffic logs
        try:
            with open("data/traffic_logs.json", "r") as f:
                existing_logs = json.load(f)
        except FileNotFoundError:
            existing_logs = []
        
        existing_logs.extend(generated_data)
        
        with open("data/traffic_logs.json", "w") as f:
            json.dump(existing_logs, f, indent=2)
        
        return {
            "status": "success",
            "message": f"Generated and analyzed {len(generated_data)} traffic records",
            "traffic_type": traffic_type,
            "generated_count": len(generated_data),
            "analysis_results": analysis_results[:5]  # Return first 5 for preview
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error simulating traffic: {str(e)}")

@router.post("/analyze")
@limiter.limit("20/minute")
async def analyze_traffic(request: Request, traffic_data: TrafficData):
    """Analyze specific traffic data with IDS engine"""
    try:
        ids_engine = request.app.state.ids_engine
        
        # Convert Pydantic model to dict
        traffic_dict = traffic_data.dict()
        
        # Analyze with IDS engine
        analysis_result = ids_engine.analyze_traffic(traffic_dict)
        
        return {
            "status": "success",
            "analysis": analysis_result
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error analyzing traffic: {str(e)}")

@router.get("/rules")
@limiter.limit("30/minute")
async def get_regex_rules(request: Request):
    """Get current regex detection rules"""
    try:
        ids_engine = request.app.state.ids_engine
        
        return {
            "status": "success",
            "rules": ids_engine.regex_rules
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting rules: {str(e)}")

@router.post("/rules")
@limiter.limit("10/minute")
async def add_regex_rule(request: Request, rule: RegexRule):
    """Add new regex detection rule"""
    try:
        ids_engine = request.app.state.ids_engine
        
        success = ids_engine.add_regex_rule(rule.name, rule.pattern, rule.severity)
        
        if success:
            return {
                "status": "success",
                "message": f"Rule '{rule.name}' added successfully"
            }
        else:
            raise HTTPException(status_code=400, detail="Invalid regex pattern")
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error adding rule: {str(e)}")

@router.get("/system/status")
@limiter.limit("60/minute")
async def get_system_status(request: Request):
    """Get overall system status"""
    try:
        security_manager = request.app.state.security_manager
        honeypot = request.app.state.honeypot
        data_generator = request.app.state.data_generator
        
        # Get security status
        security_status = security_manager.get_security_status()
        
        # Get honeypot status
        honeypot_status = honeypot.get_honeypot_status()
        
        # Get traffic statistics
        traffic_stats = data_generator.get_traffic_stats()
        
        # System health metrics
        system_health = {
            "uptime": "24h 15m",  # Mock uptime
            "cpu_usage": "15%",
            "memory_usage": "45%",
            "disk_usage": "23%",
            "network_status": "Active"
        }
        
        return {
            "status": "success",
            "timestamp": datetime.now().isoformat(),
            "security": security_status,
            "honeypot": honeypot_status,
            "traffic_stats": traffic_stats,
            "system_health": system_health,
            "overall_status": "Operational"
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting system status: {str(e)}")

@router.get("/dashboard/metrics")
@limiter.limit("60/minute")
async def get_dashboard_metrics(request: Request):
    """Get metrics for dashboard visualization"""
    try:
        # Read traffic logs
        with open("data/traffic_logs.json", "r") as f:
            traffic_data = json.load(f)
        
        # Read alerts
        with open("data/alerts.json", "r") as f:
            alerts_data = json.load(f)
        
        honeypot = request.app.state.honeypot
        honeypot_interactions = honeypot.get_recent_interactions(24)
        
        # Calculate metrics for charts
        now = datetime.now()
        hourly_traffic = {}
        hourly_alerts = {}
        
        # Initialize last 24 hours
        for i in range(24):
            hour = (now - timedelta(hours=i)).strftime("%H:00")
            hourly_traffic[hour] = {"normal": 0, "malicious": 0}
            hourly_alerts[hour] = {"high": 0, "medium": 0, "low": 0}
        
        # Count traffic by hour
        for traffic in traffic_data:
            try:
                traffic_time = datetime.fromisoformat(traffic["timestamp"])
                if (now - traffic_time).total_seconds() <= 86400:  # Last 24 hours
                    hour = traffic_time.strftime("%H:00")
                    if hour in hourly_traffic:
                        if traffic.get("is_malicious", False):
                            hourly_traffic[hour]["malicious"] += 1
                        else:
                            hourly_traffic[hour]["normal"] += 1
            except:
                continue
        
        # Count alerts by hour
        for alert in alerts_data:
            try:
                alert_time = datetime.fromisoformat(alert["timestamp"])
                if (now - alert_time).total_seconds() <= 86400:  # Last 24 hours
                    hour = alert_time.strftime("%H:00")
                    if hour in hourly_alerts:
                        severity = alert.get("severity", "low").lower()
                        if severity in hourly_alerts[hour]:
                            hourly_alerts[hour][severity] += 1
            except:
                continue
        
        # Prepare chart data
        traffic_chart_data = []
        for hour in sorted(hourly_traffic.keys()):
            traffic_chart_data.append({
                "time": hour,
                "normal": hourly_traffic[hour]["normal"],
                "malicious": hourly_traffic[hour]["malicious"],
                "total": hourly_traffic[hour]["normal"] + hourly_traffic[hour]["malicious"]
            })
        
        alerts_chart_data = []
        for hour in sorted(hourly_alerts.keys()):
            alerts_chart_data.append({
                "time": hour,
                "high": hourly_alerts[hour]["high"],
                "medium": hourly_alerts[hour]["medium"],
                "low": hourly_alerts[hour]["low"]
            })
        
        return {
            "status": "success",
            "timestamp": now.isoformat(),
            "traffic_chart": traffic_chart_data,
            "alerts_chart": alerts_chart_data,
            "summary": {
                "total_traffic": len(traffic_data),
                "total_alerts": len(alerts_data),
                "honeypot_interactions": len(honeypot_interactions),
                "active_threats": sum(1 for alert in alerts_data if alert.get("status") == "Active")
            }
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting dashboard metrics: {str(e)}")
