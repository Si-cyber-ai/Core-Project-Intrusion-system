import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import {
  Activity,
  Filter,
  Search,
  Download,
  RefreshCw,
  Shield,
  CheckCircle,
  XCircle,
  Clock
} from 'lucide-react';

interface TrafficLog {
  timestamp: string;
  source_ip: string;
  destination_ip: string;
  protocol: string;
  port: number;
  payload: string;
  packet_size: number;
  is_malicious: boolean;
  traffic_type: string;
}

const TrafficMonitor: React.FC = () => {
  const [trafficLogs, setTrafficLogs] = useState<TrafficLog[]>([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState('all');
  const [searchTerm, setSearchTerm] = useState('');
  const [currentPage, setCurrentPage] = useState(1);
  const logsPerPage = 20;

  useEffect(() => {
    fetchTrafficLogs();
    const interval = setInterval(fetchTrafficLogs, 15000); // Update every 15 seconds
    return () => clearInterval(interval);
  }, []);

  const fetchTrafficLogs = async () => {
    try {
      setLoading(true);
      const response = await fetch('http://localhost:8000/api/traffic/logs?limit=200');
      const data = await response.json();
      
      if (data.status === 'success') {
        setTrafficLogs(data.logs);
      }
    } catch (error) {
      console.error('Error fetching traffic logs:', error);
      // Mock data for demo
      setTrafficLogs(generateMockTrafficLogs());
    } finally {
      setLoading(false);
    }
  };

  const generateMockTrafficLogs = (): TrafficLog[] => {
    const logs: TrafficLog[] = [];
    const ips = ['192.168.1.100', '10.0.0.50', '203.0.113.45', '198.51.100.78'];
    const protocols = ['HTTP', 'HTTPS', 'TCP', 'UDP'];
    const trafficTypes = ['normal', 'sql_injection', 'xss_attack', 'port_scan', 'brute_force'];

    for (let i = 0; i < 50; i++) {
      const timestamp = new Date(Date.now() - Math.random() * 86400000);
      const isMalicious = Math.random() > 0.7;
      logs.push({
        timestamp: timestamp.toISOString(),
        source_ip: ips[Math.floor(Math.random() * ips.length)],
        destination_ip: ips[Math.floor(Math.random() * ips.length)],
        protocol: protocols[Math.floor(Math.random() * protocols.length)],
        port: Math.floor(Math.random() * 65535),
        payload: isMalicious ? "GET /admin?id=1' UNION SELECT * FROM users--" : "GET / HTTP/1.1",
        packet_size: Math.floor(Math.random() * 1500) + 64,
        is_malicious: isMalicious,
        traffic_type: isMalicious ? trafficTypes[Math.floor(Math.random() * 4) + 1] : 'normal'
      });
    }
    return logs.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
  };

  const filteredLogs = trafficLogs.filter(log => {
    const matchesFilter = filter === 'all' || 
      (filter === 'malicious' && log.is_malicious) ||
      (filter === 'normal' && !log.is_malicious);
    
    const matchesSearch = searchTerm === '' ||
      log.source_ip.includes(searchTerm) ||
      log.destination_ip.includes(searchTerm) ||
      log.payload.toLowerCase().includes(searchTerm.toLowerCase());
    
    return matchesFilter && matchesSearch;
  });

  const paginatedLogs = filteredLogs.slice(
    (currentPage - 1) * logsPerPage,
    currentPage * logsPerPage
  );

  const totalPages = Math.ceil(filteredLogs.length / logsPerPage);

  const getStatusIcon = (isMalicious: boolean) => {
    if (isMalicious) {
      return <XCircle className="h-4 w-4 text-red-400" />;
    }
    return <CheckCircle className="h-4 w-4 text-green-400" />;
  };

  const getTrafficTypeColor = (type: string) => {
    switch (type) {
      case 'sql_injection': return 'bg-red-500/20 text-red-400 border-red-500/30';
      case 'xss_attack': return 'bg-orange-500/20 text-orange-400 border-orange-500/30';
      case 'port_scan': return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
      case 'brute_force': return 'bg-purple-500/20 text-purple-400 border-purple-500/30';
      default: return 'bg-green-500/20 text-green-400 border-green-500/30';
    }
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
            <Activity className="h-8 w-8 mr-3 text-primary" />
            Traffic Monitor
          </h1>
          <p className="text-muted-foreground">Real-time network traffic analysis</p>
        </div>
        <div className="flex items-center space-x-3">
          <motion.button
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
            onClick={fetchTrafficLogs}
            className="flex items-center space-x-2 px-4 py-2 bg-primary/20 text-primary border border-primary/30 rounded-lg hover:bg-primary/30 transition-colors"
          >
            <RefreshCw className="h-4 w-4" />
            <span>Refresh</span>
          </motion.button>
          <motion.button
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
            className="flex items-center space-x-2 px-4 py-2 bg-secondary text-secondary-foreground rounded-lg hover:bg-secondary/80 transition-colors"
          >
            <Download className="h-4 w-4" />
            <span>Export</span>
          </motion.button>
        </div>
      </motion.div>

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        {[
          { label: 'Total Packets', value: trafficLogs.length, color: 'text-blue-400' },
          { label: 'Malicious', value: trafficLogs.filter(log => log.is_malicious).length, color: 'text-red-400' },
          { label: 'Normal', value: trafficLogs.filter(log => !log.is_malicious).length, color: 'text-green-400' },
          { label: 'Detection Rate', value: `${((trafficLogs.filter(log => log.is_malicious).length / trafficLogs.length) * 100 || 0).toFixed(1)}%`, color: 'text-yellow-400' }
        ].map((stat, index) => (
          <motion.div
            key={stat.label}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: index * 0.1 }}
            className="bg-card border border-border rounded-lg p-4"
          >
            <p className="text-sm text-muted-foreground">{stat.label}</p>
            <p className={`text-xl font-bold ${stat.color}`}>{stat.value}</p>
          </motion.div>
        ))}
      </div>

      {/* Filters */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.4 }}
        className="bg-card border border-border rounded-lg p-4"
      >
        <div className="flex flex-col md:flex-row md:items-center md:justify-between space-y-4 md:space-y-0">
          <div className="flex items-center space-x-4">
            <Filter className="h-5 w-5 text-muted-foreground" />
            <select
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              className="bg-background border border-border rounded-md px-3 py-2 text-sm"
            >
              <option value="all">All Traffic</option>
              <option value="malicious">Malicious Only</option>
              <option value="normal">Normal Only</option>
            </select>
          </div>
          <div className="flex items-center space-x-2">
            <Search className="h-5 w-5 text-muted-foreground" />
            <input
              type="text"
              placeholder="Search by IP or payload..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="bg-background border border-border rounded-md px-3 py-2 text-sm w-64"
            />
          </div>
        </div>
      </motion.div>

      {/* Traffic Table */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.5 }}
        className="bg-card border border-border rounded-lg overflow-hidden"
      >
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-muted/50">
              <tr>
                <th className="px-4 py-3 text-left text-sm font-medium">Status</th>
                <th className="px-4 py-3 text-left text-sm font-medium">Timestamp</th>
                <th className="px-4 py-3 text-left text-sm font-medium">Source IP</th>
                <th className="px-4 py-3 text-left text-sm font-medium">Destination IP</th>
                <th className="px-4 py-3 text-left text-sm font-medium">Protocol</th>
                <th className="px-4 py-3 text-left text-sm font-medium">Port</th>
                <th className="px-4 py-3 text-left text-sm font-medium">Type</th>
                <th className="px-4 py-3 text-left text-sm font-medium">Payload</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {paginatedLogs.map((log, index) => (
                <motion.tr
                  key={index}
                  initial={{ opacity: 0, x: -20 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: index * 0.05 }}
                  className="hover:bg-muted/30 transition-colors"
                >
                  <td className="px-4 py-3">
                    {getStatusIcon(log.is_malicious)}
                  </td>
                  <td className="px-4 py-3 text-sm terminal-text">
                    {new Date(log.timestamp).toLocaleString()}
                  </td>
                  <td className="px-4 py-3 text-sm font-mono">{log.source_ip}</td>
                  <td className="px-4 py-3 text-sm font-mono">{log.destination_ip}</td>
                  <td className="px-4 py-3 text-sm">{log.protocol}</td>
                  <td className="px-4 py-3 text-sm">{log.port}</td>
                  <td className="px-4 py-3">
                    <span className={`px-2 py-1 rounded-full text-xs border ${getTrafficTypeColor(log.traffic_type)}`}>
                      {log.traffic_type.replace('_', ' ')}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-sm max-w-xs truncate font-mono">
                    {log.payload}
                  </td>
                </motion.tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        <div className="px-4 py-3 border-t border-border flex items-center justify-between">
          <p className="text-sm text-muted-foreground">
            Showing {((currentPage - 1) * logsPerPage) + 1} to {Math.min(currentPage * logsPerPage, filteredLogs.length)} of {filteredLogs.length} results
          </p>
          <div className="flex items-center space-x-2">
            <button
              onClick={() => setCurrentPage(prev => Math.max(prev - 1, 1))}
              disabled={currentPage === 1}
              className="px-3 py-1 text-sm border border-border rounded disabled:opacity-50 disabled:cursor-not-allowed hover:bg-muted/50"
            >
              Previous
            </button>
            <span className="text-sm">
              Page {currentPage} of {totalPages}
            </span>
            <button
              onClick={() => setCurrentPage(prev => Math.min(prev + 1, totalPages))}
              disabled={currentPage === totalPages}
              className="px-3 py-1 text-sm border border-border rounded disabled:opacity-50 disabled:cursor-not-allowed hover:bg-muted/50"
            >
              Next
            </button>
          </div>
        </div>
      </motion.div>
    </div>
  );
};

export default TrafficMonitor;
