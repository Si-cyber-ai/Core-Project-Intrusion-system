#!/usr/bin/env python3
"""
Smart Sensor Test Script
Tests the Attack Sensor Simulator functionality
"""

import requests
import json
from time import sleep

BASE_URL = "http://localhost:8000"

def test_sensor_api():
    """Test the sensor API with different payloads"""
    
    test_cases = [
        {
            "name": "Normal Text",
            "payload": "Hello world",
            "expected_status": "Normal"
        },
        {
            "name": "SQL Injection",
            "payload": "GET /admin?id=1 UNION SELECT * FROM users--",
            "expected_status": "Attack"
        },
        {
            "name": "XSS Attack",
            "payload": "<script>alert('XSS')</script>",
            "expected_status": "Attack"
        },
        {
            "name": "Directory Traversal",
            "payload": "../../../etc/passwd",
            "expected_status": "Attack"
        },
        {
            "name": "Command Injection",
            "payload": "GET /ping.php?host=127.0.0.1;cat /etc/passwd",
            "expected_status": "Attack"
        },
        {
            "name": "Normal Login",
            "payload": "POST /login HTTP/1.1",
            "expected_status": "Normal"
        }
    ]
    
    print("🔍 Testing Smart Sensor API")
    print("=" * 50)
    
    for i, test_case in enumerate(test_cases, 1):
        print(f"\n{i}. Testing: {test_case['name']}")
        print(f"   Payload: {test_case['payload'][:50]}...")
        
        try:
            # Send request to sensor API
            response = requests.post(
                f"{BASE_URL}/api/sensor/input",
                json={"payload": test_case["payload"]},
                headers={"Content-Type": "application/json"}
            )
            
            if response.status_code == 200:
                result = response.json()
                status = result.get("status", "Unknown")
                attack_type = result.get("detected_attack_type", "None")
                confidence = result.get("confidence", 0.0)
                
                # Status color coding
                status_color = {
                    "Normal": "🟢",
                    "Suspicious": "🟡", 
                    "Attack": "🔴"
                }.get(status, "⚪")
                
                print(f"   Result: {status_color} {status}")
                if attack_type:
                    print(f"   Attack Type: {attack_type}")
                    print(f"   Confidence: {confidence:.2%}")
                
                # Check if result matches expectation
                if status == test_case["expected_status"]:
                    print("   ✅ Test PASSED")
                else:
                    print(f"   ❌ Test FAILED (expected {test_case['expected_status']})")
                    
            else:
                print(f"   ❌ API Error: {response.status_code}")
                
        except requests.exceptions.ConnectionError:
            print("   ❌ Connection Error: Backend server not running")
            break
        except Exception as e:
            print(f"   ❌ Error: {e}")
        
        sleep(0.5)  # Small delay between requests
    
    print("\n" + "=" * 50)
    print("Testing completed!")

if __name__ == "__main__":
    test_sensor_api()