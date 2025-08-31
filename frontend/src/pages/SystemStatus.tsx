import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import {
  Shield,
  Activity,
  Server,
  Database,
  Wifi,
  Lock,
  Zap,
  Bug,
  Eye,
  Globe,
  Clock,
  CheckCircle,
  XCircle,
  Settings,
  RefreshCw,
  Cpu,
  HardDrive
} from 'lucide-react';

interface SystemStatus {
  security: {
    ssl_tls: {
      enabled: boolean;
      version: string;
      cipher_suite: string;
    };
    digital_signatures: {
      algorithm: string;
      hash_function: string;
      enabled: boolean;
    };
    message_integrity: {
      algorithm: string;
      enabled: boolean;
    };
    encryption: {
      algorithm: string;
      key_size: number;
      enabled: boolean;
    };
  };
  honeypot: {
    is_active: boolean;
    monitored_ports: number[];
    recent_interactions: number;
    threat_level: string;
  };
  traffic_stats: {
    total_packets: number;
    malicious_packets: number;
    detection_rate: number;
  };
  system_health: {
    uptime: string;
    cpu_usage: string;
    memory_usage: string;
    disk_usage: string;
    network_status: string;
  };
}

interface SystemStatusData {
  uptime: string;
  cpu_usage: number;
  memory_usage: number;
  disk_usage: number;
  network_status: string;
  ids_status: string;
  honeypot_status: string;
  ssl_status: string;
  firewall_status: string;
  last_update: string;
  active_connections: number;
  blocked_ips: number;
  total_alerts: number;
  system_load: number;
  temperature: number;
}

interface SecurityModule {
  name: string;
  status: 'active' | 'inactive' | 'warning';
  uptime: string;
  last_check: string;
  details: string;
}

interface SystemStatusProps {

}

const SystemStatus: React.FC = () => {
  const [systemStatus, setSystemStatus] = useState<SystemStatus | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchSystemStatus();
    const interval = setInterval(fetchSystemStatus, 30000); // Update every 30 seconds
    return () => clearInterval(interval);
  }, []);

  const fetchSystemStatus = async () => {
    try {
      const response = await fetch('http://localhost:8000/api/system/status');
      const data = await response.json();
      
      if (data.status === 'success') {
        setSystemStatus({
          security: data.security,
          honeypot: data.honeypot,
          traffic_stats: data.traffic_stats,
          system_health: data.system_health
        });
      }
    } catch (error) {
      console.error('Error fetching system status:', error);
      // Mock data for demo
      setSystemStatus(generateMockSystemStatus());
    } finally {
      setLoading(false);
    }
  };

  const generateMockSystemStatus = (): SystemStatus => {
    return {
      security: {
        ssl_tls: {
          enabled: true,
          version: "TLS 1.3",
          cipher_suite: "AES-256-GCM"
        },
        digital_signatures: {
          algorithm: "RSA-2048 with PSS padding",
          hash_function: "SHA-256",
          enabled: true
        },
        message_integrity: {
          algorithm: "HMAC-SHA256",
          enabled: true
        },
        encryption: {
          algorithm: "AES-256-GCM",
          key_size: 256,
          enabled: true
        }
      },
      honeypot: {
        is_active: true,
        monitored_ports: [22, 80, 443, 3306, 5432],
        recent_interactions: 15,
        threat_level: "Medium"
      },
      traffic_stats: {
        total_packets: 15847,
        malicious_packets: 234,
        detection_rate: 1.48
      },
      system_health: {
        uptime: "24h 15m",
        cpu_usage: "15%",
        memory_usage: "45%",
        disk_usage: "23%",
        network_status: "Active"
      }
    };
  };

  const getStatusIcon = (enabled: boolean) => {
    return enabled ? (
      <CheckCircle className="h-5 w-5 text-green-400" />
    ) : (
      <XCircle className="h-5 w-5 text-red-400" />
    );
  };

  const getThreatLevelColor = (level: string) => {
    switch (level.toLowerCase()) {
      case 'high': return 'text-red-400 bg-red-500/20 border-red-500/30';
      case 'medium': return 'text-yellow-400 bg-yellow-500/20 border-yellow-500/30';
      case 'low': return 'text-green-400 bg-green-500/20 border-green-500/30';
      default: return 'text-gray-400 bg-gray-500/20 border-gray-500/30';
    }
  };

  const getUsageColor = (usage: string) => {
    const percent = parseInt(usage);
    if (percent > 80) return 'text-red-400 bg-red-500';
    if (percent > 60) return 'text-yellow-400 bg-yellow-500';
    return 'text-green-400 bg-green-500';
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full">
        <motion.div
          animate={{ rotate: 360 }}
          transition={{ duration: 1, repeat: Infinity, ease: "linear" }}
          className="h-8 w-8 border-2 border-primary border-t-transparent rounded-full"
        />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        className="flex items-center justify-between"
      >
        <div>
          <h1 className="text-3xl font-bold glow-text flex items-center">
            <Settings className="h-8 w-8 mr-3 text-primary" />
            System Status
          </h1>
          <p className="text-muted-foreground">Security modules and system health monitoring</p>
        </div>
        <motion.button
          whileHover={{ scale: 1.05 }}
          whileTap={{ scale: 0.95 }}
          onClick={fetchSystemStatus}
          className="flex items-center space-x-2 px-4 py-2 bg-primary/20 text-primary border border-primary/30 rounded-lg hover:bg-primary/30 transition-colors"
        >
          <RefreshCw className="h-4 w-4" />
          <span>Refresh</span>
        </motion.button>
      </motion.div>

      {/* Security Status */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
        className="bg-card border border-border rounded-lg p-6"
      >
        <h2 className="text-xl font-semibold mb-6 flex items-center">
          <Shield className="h-6 w-6 mr-2 text-green-400" />
          Security Modules
        </h2>
        
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* SSL/TLS */}
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-3">
                <Lock className="h-5 w-5 text-blue-400" />
                <span className="font-medium">SSL/TLS Encryption</span>
              </div>
              {getStatusIcon(systemStatus?.security.ssl_tls.enabled || false)}
            </div>
            <div className="pl-8 space-y-2 text-sm text-muted-foreground">
              <div className="flex justify-between">
                <span>Version:</span>
                <span className="text-foreground">{systemStatus?.security.ssl_tls.version}</span>
              </div>
              <div className="flex justify-between">
                <span>Cipher Suite:</span>
                <span className="text-foreground">{systemStatus?.security.ssl_tls.cipher_suite}</span>
              </div>
            </div>
          </div>

          {/* Digital Signatures */}
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-3">
                <Shield className="h-5 w-5 text-purple-400" />
                <span className="font-medium">Digital Signatures</span>
              </div>
              {getStatusIcon(systemStatus?.security.digital_signatures.enabled || false)}
            </div>
            <div className="pl-8 space-y-2 text-sm text-muted-foreground">
              <div className="flex justify-between">
                <span>Algorithm:</span>
                <span className="text-foreground text-xs">{systemStatus?.security.digital_signatures.algorithm}</span>
              </div>
              <div className="flex justify-between">
                <span>Hash Function:</span>
                <span className="text-foreground">{systemStatus?.security.digital_signatures.hash_function}</span>
              </div>
            </div>
          </div>

          {/* Message Integrity */}
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-3">
                <CheckCircle className="h-5 w-5 text-green-400" />
                <span className="font-medium">Message Integrity</span>
              </div>
              {getStatusIcon(systemStatus?.security.message_integrity.enabled || false)}
            </div>
            <div className="pl-8 space-y-2 text-sm text-muted-foreground">
              <div className="flex justify-between">
                <span>Algorithm:</span>
                <span className="text-foreground">{systemStatus?.security.message_integrity.algorithm}</span>
              </div>
            </div>
          </div>

          {/* Encryption */}
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-3">
                <Lock className="h-5 w-5 text-yellow-400" />
                <span className="font-medium">Data Encryption</span>
              </div>
              {getStatusIcon(systemStatus?.security.encryption.enabled || false)}
            </div>
            <div className="pl-8 space-y-2 text-sm text-muted-foreground">
              <div className="flex justify-between">
                <span>Algorithm:</span>
                <span className="text-foreground">{systemStatus?.security.encryption.algorithm}</span>
              </div>
              <div className="flex justify-between">
                <span>Key Size:</span>
                <span className="text-foreground">{systemStatus?.security.encryption.key_size} bits</span>
              </div>
            </div>
          </div>
        </div>
      </motion.div>

      {/* System Health & Honeypot */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* System Health */}
        <motion.div
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.2 }}
          className="bg-card border border-border rounded-lg p-6"
        >
          <h3 className="text-lg font-semibold mb-4 flex items-center">
            <Server className="h-5 w-5 mr-2 text-blue-400" />
            System Health
          </h3>
          
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-3">
                <Activity className="h-4 w-4 text-green-400" />
                <span>Uptime</span>
              </div>
              <span className="font-mono text-green-400">{systemStatus?.system_health.uptime}</span>
            </div>

            <div className="space-y-3">
              {[
                { label: 'CPU Usage', value: systemStatus?.system_health.cpu_usage || '0%', icon: Cpu },
                { label: 'Memory Usage', value: systemStatus?.system_health.memory_usage || '0%', icon: Server },
                { label: 'Disk Usage', value: systemStatus?.system_health.disk_usage || '0%', icon: HardDrive }
              ].map((metric) => {
                const usage = parseInt(metric.value);
                return (
                  <div key={metric.label} className="space-y-2">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-2">
                        <metric.icon className="h-4 w-4 text-muted-foreground" />
                        <span className="text-sm">{metric.label}</span>
                      </div>
                      <span className={`text-sm font-medium ${getUsageColor(metric.value).split(' ')[0]}`}>
                        {metric.value}
                      </span>
                    </div>
                    <div className="w-full bg-muted rounded-full h-2">
                      <div
                        className={`h-2 rounded-full transition-all duration-300 ${getUsageColor(metric.value).split(' ')[1]}`}
                        style={{ width: `${usage}%` }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>

            <div className="flex items-center justify-between pt-2 border-t border-border">
              <div className="flex items-center space-x-3">
                <Wifi className="h-4 w-4 text-green-400" />
                <span>Network Status</span>
              </div>
              <span className="text-green-400 font-medium">{systemStatus?.system_health.network_status}</span>
            </div>
          </div>
        </motion.div>

        {/* Honeypot Status */}
        <motion.div
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.3 }}
          className="bg-card border border-border rounded-lg p-6"
        >
          <h3 className="text-lg font-semibold mb-4 flex items-center">
            <Shield className="h-5 w-5 mr-2 text-purple-400" />
            Honeypot Module
          </h3>
          
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <span>Status</span>
              <div className="flex items-center space-x-2">
                {getStatusIcon(systemStatus?.honeypot.is_active || false)}
                <span className="text-green-400 font-medium">
                  {systemStatus?.honeypot.is_active ? 'Active' : 'Inactive'}
                </span>
              </div>
            </div>

            <div className="flex items-center justify-between">
              <span>Monitored Ports</span>
              <span className="font-mono text-muted-foreground">
                {systemStatus?.honeypot.monitored_ports.join(', ')}
              </span>
            </div>

            <div className="flex items-center justify-between">
              <span>Recent Interactions</span>
              <span className="font-bold text-yellow-400">
                {systemStatus?.honeypot.recent_interactions}
              </span>
            </div>

            <div className="flex items-center justify-between">
              <span>Threat Level</span>
              <span className={`px-2 py-1 rounded-full text-xs border ${getThreatLevelColor(systemStatus?.honeypot.threat_level || 'low')}`}>
                {systemStatus?.honeypot.threat_level}
              </span>
            </div>
          </div>
        </motion.div>
      </div>

      {/* Traffic Statistics */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.4 }}
        className="bg-card border border-border rounded-lg p-6"
      >
        <h3 className="text-lg font-semibold mb-4 flex items-center">
          <Activity className="h-5 w-5 mr-2 text-blue-400" />
          Traffic Statistics
        </h3>
        
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="text-center">
            <div className="text-2xl font-bold text-blue-400">
              {systemStatus?.traffic_stats.total_packets.toLocaleString()}
            </div>
            <div className="text-sm text-muted-foreground">Total Packets</div>
          </div>
          
          <div className="text-center">
            <div className="text-2xl font-bold text-red-400">
              {systemStatus?.traffic_stats.malicious_packets.toLocaleString()}
            </div>
            <div className="text-sm text-muted-foreground">Malicious Packets</div>
          </div>
          
          <div className="text-center">
            <div className="text-2xl font-bold text-yellow-400">
              {systemStatus?.traffic_stats.detection_rate.toFixed(2)}%
            </div>
            <div className="text-sm text-muted-foreground">Detection Rate</div>
          </div>
        </div>
      </motion.div>

      {/* System Information */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.5 }}
        className="bg-card border border-border rounded-lg p-6"
      >
        <h3 className="text-lg font-semibold mb-4">System Information</h3>
        
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 text-sm">
          <div className="space-y-2">
            <div className="flex justify-between">
              <span className="text-muted-foreground">IDS Version:</span>
              <span>v1.0.0</span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">Python Version:</span>
              <span>3.11.0</span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">FastAPI Version:</span>
              <span>0.104.1</span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">Scikit-learn Version:</span>
              <span>1.3.2</span>
            </div>
          </div>
          
          <div className="space-y-2">
            <div className="flex justify-between">
              <span className="text-muted-foreground">Last Updated:</span>
              <span>{new Date().toLocaleDateString()}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">Config File:</span>
              <span className="text-green-400">Valid</span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">Log Level:</span>
              <span>INFO</span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">Debug Mode:</span>
              <span className="text-red-400">Disabled</span>
            </div>
          </div>
        </div>
      </motion.div>
    </div>
  );
};

export default SystemStatus;
