import hashlib
import hmac
import base64
import json
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import secrets
import logging
from typing import Dict, Any, Optional, Tuple

class SecurityManager:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Generate RSA key pair for message signing
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        
        # Secret key for HMAC
        self.hmac_secret = secrets.token_bytes(32)
        
        # SSL/TLS status
        self.ssl_enabled = True
        self.tls_version = "TLS 1.3"
        
        self.logger.info("Security Manager initialized with RSA-2048 and HMAC-SHA256")
    
    def generate_signature(self, message: str) -> str:
        """Generate RSA digital signature for message integrity"""
        try:
            message_bytes = message.encode('utf-8')
            signature = self.private_key.sign(
                message_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return base64.b64encode(signature).decode('utf-8')
        except Exception as e:
            self.logger.error(f"Error generating signature: {e}")
            return ""
    
    def verify_signature(self, message: str, signature: str) -> bool:
        """Verify RSA digital signature"""
        try:
            message_bytes = message.encode('utf-8')
            signature_bytes = base64.b64decode(signature)
            
            self.public_key.verify(
                signature_bytes,
                message_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception as e:
            self.logger.error(f"Signature verification failed: {e}")
            return False
    
    def generate_hmac(self, data: str) -> str:
        """Generate HMAC for data integrity"""
        try:
            data_bytes = data.encode('utf-8')
            hmac_hash = hmac.new(
                self.hmac_secret,
                data_bytes,
                hashlib.sha256
            ).hexdigest()
            return hmac_hash
        except Exception as e:
            self.logger.error(f"Error generating HMAC: {e}")
            return ""
    
    def verify_hmac(self, data: str, hmac_hash: str) -> bool:
        """Verify HMAC integrity"""
        try:
            expected_hmac = self.generate_hmac(data)
            return hmac.compare_digest(expected_hmac, hmac_hash)
        except Exception as e:
            self.logger.error(f"HMAC verification failed: {e}")
            return False
    
    def encrypt_data(self, plaintext: str, key: Optional[bytes] = None) -> Dict[str, str]:
        """Encrypt data using AES-256-GCM"""
        try:
            if key is None:
                key = secrets.token_bytes(32)  # 256-bit key
            
            # Generate random IV
            iv = secrets.token_bytes(12)  # 96-bit IV for GCM
            
            # Create cipher
            cipher = Cipher(
                algorithms.AES(key),
                modes.GCM(iv),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            
            # Encrypt data
            ciphertext = encryptor.update(plaintext.encode('utf-8')) + encryptor.finalize()
            
            return {
                "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
                "iv": base64.b64encode(iv).decode('utf-8'),
                "tag": base64.b64encode(encryptor.tag).decode('utf-8'),
                "key": base64.b64encode(key).decode('utf-8')
            }
        except Exception as e:
            self.logger.error(f"Encryption failed: {e}")
            return {}
    
    def decrypt_data(self, encrypted_data: Dict[str, str]) -> str:
        """Decrypt AES-256-GCM encrypted data"""
        try:
            ciphertext = base64.b64decode(encrypted_data['ciphertext'])
            iv = base64.b64decode(encrypted_data['iv'])
            tag = base64.b64decode(encrypted_data['tag'])
            key = base64.b64decode(encrypted_data['key'])
            
            # Create cipher
            cipher = Cipher(
                algorithms.AES(key),
                modes.GCM(iv, tag),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            
            # Decrypt data
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            return plaintext.decode('utf-8')
        except Exception as e:
            self.logger.error(f"Decryption failed: {e}")
            return ""
    
    def hash_password(self, password: str, salt: Optional[bytes] = None) -> Dict[str, str]:
        """Hash password using PBKDF2 with SHA-256"""
        try:
            if salt is None:
                salt = secrets.token_bytes(32)
            
            # Use PBKDF2 with 100,000 iterations
            key = hashlib.pbkdf2_hmac(
                'sha256',
                password.encode('utf-8'),
                salt,
                100000
            )
            
            return {
                "hash": base64.b64encode(key).decode('utf-8'),
                "salt": base64.b64encode(salt).decode('utf-8')
            }
        except Exception as e:
            self.logger.error(f"Password hashing failed: {e}")
            return {}
    
    def verify_password(self, password: str, hash_data: Dict[str, str]) -> bool:
        """Verify password against hash"""
        try:
            salt = base64.b64decode(hash_data['salt'])
            expected_hash = base64.b64decode(hash_data['hash'])
            
            key = hashlib.pbkdf2_hmac(
                'sha256',
                password.encode('utf-8'),
                salt,
                100000
            )
            
            return hmac.compare_digest(key, expected_hash)
        except Exception as e:
            self.logger.error(f"Password verification failed: {e}")
            return False
    
    def generate_secure_token(self, length: int = 32) -> str:
        """Generate cryptographically secure random token"""
        return secrets.token_urlsafe(length)
    
    def create_secure_session(self, user_id: str, expires_in: int = 3600) -> Dict[str, Any]:
        """Create secure session with expiration"""
        session_data = {
            "user_id": user_id,
            "created_at": datetime.now().isoformat(),
            "expires_at": (datetime.now() + timedelta(seconds=expires_in)).isoformat(),
            "session_id": self.generate_secure_token()
        }
        
        # Sign the session data
        session_json = json.dumps(session_data, sort_keys=True)
        signature = self.generate_signature(session_json)
        
        return {
            "session_data": session_data,
            "signature": signature,
            "token": self.generate_secure_token()
        }
    
    def validate_session(self, session_data: Dict[str, Any], signature: str) -> bool:
        """Validate session integrity and expiration"""
        try:
            # Check signature
            session_json = json.dumps(session_data, sort_keys=True)
            if not self.verify_signature(session_json, signature):
                return False
            
            # Check expiration
            expires_at = datetime.fromisoformat(session_data['expires_at'])
            if datetime.now() > expires_at:
                return False
            
            return True
        except Exception as e:
            self.logger.error(f"Session validation failed: {e}")
            return False
    
    def get_public_key_pem(self) -> str:
        """Get public key in PEM format for client verification"""
        try:
            pem = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            return pem.decode('utf-8')
        except Exception as e:
            self.logger.error(f"Error exporting public key: {e}")
            return ""
    
    def get_security_status(self) -> Dict[str, Any]:
        """Get current security status"""
        return {
            "ssl_tls": {
                "enabled": self.ssl_enabled,
                "version": self.tls_version,
                "cipher_suite": "AES-256-GCM"
            },
            "digital_signatures": {
                "algorithm": "RSA-2048 with PSS padding",
                "hash_function": "SHA-256",
                "enabled": True
            },
            "message_integrity": {
                "algorithm": "HMAC-SHA256",
                "enabled": True
            },
            "encryption": {
                "algorithm": "AES-256-GCM",
                "key_size": 256,
                "enabled": True
            },
            "password_hashing": {
                "algorithm": "PBKDF2-SHA256",
                "iterations": 100000,
                "enabled": True
            },
            "session_management": {
                "secure_tokens": True,
                "digital_signatures": True,
                "expiration_tracking": True
            }
        }
    
    def security_audit_log(self, event_type: str, details: Dict[str, Any]) -> Dict[str, Any]:
        """Create security audit log entry"""
        audit_entry = {
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type,
            "details": details,
            "security_level": self._assess_security_level(event_type),
            "source_ip": details.get("source_ip", "unknown"),
            "user_agent": details.get("user_agent", "unknown")
        }
        
        # Sign the audit entry
        audit_json = json.dumps(audit_entry, sort_keys=True)
        audit_entry["signature"] = self.generate_signature(audit_json)
        
        return audit_entry
    
    def _assess_security_level(self, event_type: str) -> str:
        """Assess security level of an event"""
        high_risk_events = [
            "authentication_failure",
            "unauthorized_access",
            "signature_verification_failed",
            "encryption_failure",
            "session_hijack_attempt"
        ]
        
        medium_risk_events = [
            "session_expired",
            "invalid_token",
            "rate_limit_exceeded",
            "suspicious_activity"
        ]
        
        if event_type in high_risk_events:
            return "High"
        elif event_type in medium_risk_events:
            return "Medium"
        else:
            return "Low"
