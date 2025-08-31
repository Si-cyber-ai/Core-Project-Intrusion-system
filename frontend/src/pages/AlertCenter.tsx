import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import {
  AlertTriangle,
  Filter,
  Download,
  RefreshCw,
  Search,
  Clock,
  Shield,
  Eye,
  CheckCircle2
} from 'lucide-react';

interface Alert {
  id: string;
  timestamp: string;
  alert_type: string;
  severity: string;
  source_ip: string;
  destination_ip: string;
  description: string;
  confidence: number;
  status: string;
  rule_triggered: string;
  action_taken: string;
}

const AlertCenter: React.FC = () => {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState('all');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [searchTerm, setSearchTerm] = useState('');
  const [currentPage, setCurrentPage] = useState(1);
  const alertsPerPage = 15;

  useEffect(() => {
    const interval = setInterval(fetchAlerts, 15000); // Update every 15 seconds
    return () => clearInterval(interval);
  }, []);

  const fetchAlerts = async () => {
    try {
      setLoading(true);
      const response = await fetch('http://localhost:8000/api/alerts?limit=100');
      const data = await response.json();
      
      if (data.status === 'success') {
        setAlerts(data.alerts);
      }
    } catch (error) {
      console.error('Error fetching alerts:', error);
      // Mock data for demo
      setAlerts(generateMockAlerts());
    } finally {
      setLoading(false);
    }
  };

  const generateMockAlerts = (): Alert[] => {
    const alertTypes = [
      'SQL Injection Detected',
      'XSS Attack Blocked',
      'Command Injection Attempt',
      'Directory Traversal Detected',
      'Port Scan Activity',
      'Brute Force Attack',
      'Anomalous Traffic Pattern',
      'Suspicious Payload Detected'
    ];
    
    const severities = ['High', 'Medium', 'Low'];
    const statuses = ['Active', 'Resolved', 'Investigating'];
    const actions = ['Blocked', 'Logged', 'Alerted', 'Quarantined'];
    const ips = ['203.0.113.45', '198.51.100.78', '192.0.2.123', '185.220.101.42'];

    return Array.from({ length: 30 }, (_, i) => {
      const timestamp = new Date(Date.now() - Math.random() * 86400000 * 3);
      const severity = severities[Math.floor(Math.random() * severities.length)];
      const alertType = alertTypes[Math.floor(Math.random() * alertTypes.length)];
      
      return {
        id: `ALERT_${(i + 1).toString().padStart(4, '0')}`,
        timestamp: timestamp.toISOString(),
        alert_type: alertType,
        severity,
        source_ip: ips[Math.floor(Math.random() * ips.length)],
        destination_ip: '192.168.1.100',
        description: `${alertType} from ${ips[Math.floor(Math.random() * ips.length)]}`,
        confidence: Math.random() * 0.4 + 0.6,
        status: statuses[Math.floor(Math.random() * statuses.length)],
        rule_triggered: `RULE_${(Math.floor(Math.random() * 50) + 1).toString().padStart(3, '0')}`,
        action_taken: actions[Math.floor(Math.random() * actions.length)]
      };
    }).sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
  };

  const filteredAlerts = alerts.filter(alert => {
    const matchesStatus = filter === 'all' || alert.status.toLowerCase() === filter;
    const matchesSeverity = severityFilter === 'all' || alert.severity.toLowerCase() === severityFilter;
    const matchesSearch = searchTerm === '' ||
      alert.alert_type.toLowerCase().includes(searchTerm.toLowerCase()) ||
      alert.source_ip.includes(searchTerm) ||
      alert.description.toLowerCase().includes(searchTerm.toLowerCase());
    
    return matchesStatus && matchesSeverity && matchesSearch;
  });

  const paginatedAlerts = filteredAlerts.slice(
    (currentPage - 1) * alertsPerPage,
    currentPage * alertsPerPage
  );

  const totalPages = Math.ceil(filteredAlerts.length / alertsPerPage);

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'high': return 'bg-red-500/20 text-red-400 border-red-500/30';
      case 'medium': return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
      case 'low': return 'bg-blue-500/20 text-blue-400 border-blue-500/30';
      default: return 'bg-gray-500/20 text-gray-400 border-gray-500/30';
    }
  };

  const getStatusColor = (status: string) => {
    switch (status.toLowerCase()) {
      case 'active': return 'bg-red-500/20 text-red-400 border-red-500/30';
      case 'investigating': return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
      case 'resolved': return 'bg-green-500/20 text-green-400 border-green-500/30';
      default: return 'bg-gray-500/20 text-gray-400 border-gray-500/30';
    }
  };

  const getActionIcon = (action: string) => {
    switch (action.toLowerCase()) {
      case 'blocked': return <Shield className="h-4 w-4 text-red-400" />;
      case 'quarantined': return <AlertTriangle className="h-4 w-4 text-yellow-400" />;
      case 'alerted': return <Eye className="h-4 w-4 text-blue-400" />;
      default: return <CheckCircle2 className="h-4 w-4 text-green-400" />;
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
            <AlertTriangle className="h-8 w-8 mr-3 text-yellow-400" />
            Alert Center
          </h1>
          <p className="text-muted-foreground">Security alerts and incident management</p>
        </div>
        <div className="flex items-center space-x-3">
          <motion.button
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
            onClick={fetchAlerts}
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
          { 
            label: 'Total Alerts', 
            value: alerts.length, 
            color: 'text-blue-400',
            icon: AlertTriangle
          },
          { 
            label: 'High Severity', 
            value: alerts.filter(alert => alert.severity === 'High').length, 
            color: 'text-red-400',
            icon: Shield
          },
          { 
            label: 'Active', 
            value: alerts.filter(alert => alert.status === 'Active').length, 
            color: 'text-yellow-400',
            icon: Eye
          },
          { 
            label: 'Resolved', 
            value: alerts.filter(alert => alert.status === 'Resolved').length, 
            color: 'text-green-400',
            icon: CheckCircle2
          }
        ].map((stat, index) => (
          <motion.div
            key={stat.label}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: index * 0.1 }}
            className="bg-card border border-border rounded-lg p-4"
          >
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">{stat.label}</p>
                <p className={`text-xl font-bold ${stat.color}`}>{stat.value}</p>
              </div>
              <stat.icon className={`h-6 w-6 ${stat.color}`} />
            </div>
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
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between space-y-4 lg:space-y-0">
          <div className="flex flex-col md:flex-row md:items-center space-y-4 md:space-y-0 md:space-x-4">
            <div className="flex items-center space-x-2">
              <Filter className="h-5 w-5 text-muted-foreground" />
              <select
                value={filter}
                onChange={(e) => setFilter(e.target.value)}
                className="bg-background border border-border rounded-md px-3 py-2 text-sm"
              >
                <option value="all">All Status</option>
                <option value="active">Active</option>
                <option value="investigating">Investigating</option>
                <option value="resolved">Resolved</option>
              </select>
            </div>
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="bg-background border border-border rounded-md px-3 py-2 text-sm"
            >
              <option value="all">All Severity</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </div>
          <div className="flex items-center space-x-2">
            <Search className="h-5 w-5 text-muted-foreground" />
            <input
              type="text"
              placeholder="Search alerts..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="bg-background border border-border rounded-md px-3 py-2 text-sm w-64"
            />
          </div>
        </div>
      </motion.div>

      {/* Alerts Table */}
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
                <th className="px-4 py-3 text-left text-sm font-medium">Alert ID</th>
                <th className="px-4 py-3 text-left text-sm font-medium">Timestamp</th>
                <th className="px-4 py-3 text-left text-sm font-medium">Type</th>
                <th className="px-4 py-3 text-left text-sm font-medium">Severity</th>
                <th className="px-4 py-3 text-left text-sm font-medium">Source IP</th>
                <th className="px-4 py-3 text-left text-sm font-medium">Status</th>
                <th className="px-4 py-3 text-left text-sm font-medium">Action</th>
                <th className="px-4 py-3 text-left text-sm font-medium">Confidence</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {paginatedAlerts.map((alert, index) => (
                <motion.tr
                  key={alert.id}
                  initial={{ opacity: 0, x: -20 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: index * 0.05 }}
                  className="hover:bg-muted/30 transition-colors cursor-pointer"
                >
                  <td className="px-4 py-3 text-sm font-mono text-primary">
                    {alert.id}
                  </td>
                  <td className="px-4 py-3 text-sm terminal-text">
                    <div className="flex items-center space-x-2">
                      <Clock className="h-3 w-3" />
                      <span>{new Date(alert.timestamp).toLocaleString()}</span>
                    </div>
                  </td>
                  <td className="px-4 py-3 text-sm max-w-xs">
                    <div className="truncate" title={alert.alert_type}>
                      {alert.alert_type}
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <span className={`px-2 py-1 rounded-full text-xs border ${getSeverityColor(alert.severity)}`}>
                      {alert.severity}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-sm font-mono">{alert.source_ip}</td>
                  <td className="px-4 py-3">
                    <span className={`px-2 py-1 rounded-full text-xs border ${getStatusColor(alert.status)}`}>
                      {alert.status}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center space-x-2">
                      {getActionIcon(alert.action_taken)}
                      <span className="text-sm">{alert.action_taken}</span>
                    </div>
                  </td>
                  <td className="px-4 py-3 text-sm">
                    <div className="flex items-center space-x-2">
                      <div className="w-16 bg-muted rounded-full h-2">
                        <div
                          className="bg-primary h-2 rounded-full transition-all duration-300"
                          style={{ width: `${alert.confidence * 100}%` }}
                        />
                      </div>
                      <span className="text-xs text-muted-foreground">
                        {(alert.confidence * 100).toFixed(0)}%
                      </span>
                    </div>
                  </td>
                </motion.tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        <div className="px-4 py-3 border-t border-border flex items-center justify-between">
          <p className="text-sm text-muted-foreground">
            Showing {((currentPage - 1) * alertsPerPage) + 1} to {Math.min(currentPage * alertsPerPage, filteredAlerts.length)} of {filteredAlerts.length} results
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

export default AlertCenter;
