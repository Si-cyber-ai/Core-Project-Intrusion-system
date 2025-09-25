import requests
import json

# Test different attack payloads
test_payloads = [
    # XSS Attacks
    "<script>alert('XSS')</script>",
    "javascript:alert('XSS')",
    "<img onerror=\"alert('XSS')\" src=\"x\">",
    "<iframe src=\"javascript:alert('XSS')\">",
    
    # SQL Injection Attacks
    "' OR '1'='1' --",
    "1 UNION SELECT * FROM users",
    "'; DROP TABLE users; --",
    "admin' AND 1=1 --",
    
    # Directory Traversal
    "../../../etc/passwd",
    "..\\..\\..\\windows\\system32",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    
    # Command Injection
    "; ls -la",
    "| cat /etc/passwd",
    "`whoami`",
    
    # Normal Traffic
    "Hello world",
    "Welcome to our website",
    "User login successful"
]

def test_sensor_detection():
    base_url = "http://localhost:8000"
    
    print("Testing Sensor Detection with Updated Rules")
    print("=" * 50)
    
    for payload in test_payloads:
        print(f"\nTesting payload: {payload}")
        
        try:
            # Test sensor input
            response = requests.post(f"{base_url}/api/sensor/input", 
                                   json={"payload": payload})
            
            if response.status_code == 200:
                result = response.json()
                print(f"Status: {result['status']}")
                if result.get('detected_attack_type'):
                    print(f"Attack Type: {result['detected_attack_type']}")
                    print(f"Confidence: {result['confidence']:.2f}")
                else:
                    print("No attack detected")
            else:
                print(f"Error: {response.status_code}")
                
        except Exception as e:
            print(f"Error testing payload: {e}")

if __name__ == "__main__":
    test_sensor_detection()