import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import {
  Shield,
  Activity,
  AlertTriangle,
  Bug,
  TrendingUp,
  Zap,
  Lock
} from 'lucide-react';
import {
  LineChart,
  Line,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell
} from 'recharts';

interface DashboardMetrics {
  totalTraffic: number;
  threatsBlocked: number;
  activeAlerts: number;
  honeypotInteractions: number;
  trafficChart: Array<{
    time: string;
    normal: number;
    malicious: number;
    total: number;
  }>;
  alertsChart: Array<{
    time: string;
    high: number;
    medium: number;
    low: number;
  }>;
}

const Dashboard: React.FC = () => {
  const [metrics, setMetrics] = useState<DashboardMetrics | null>(null);
  const [loading, setLoading] = useState(true);

  const fetchDashboardMetrics = async () => {
    try {
      const response = await fetch('http://localhost:8000/api/system/status');
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      const data = await response.json();
      
      if (data.status === 'success') {
        setMetrics({
          totalTraffic: data.summary?.total_traffic || 0,
          threatsBlocked: data.summary?.total_alerts || 0,
          activeAlerts: data.summary?.active_threats || 0,
          honeypotInteractions: data.summary?.honeypot_interactions || 0,
          trafficChart: data.traffic_chart || generateMockTrafficData(),
          alertsChart: data.alerts_chart || generateMockAlertsData()
        });
      } else {
        throw new Error('API returned error status');
      }
    } catch (error) {
      console.error('Error fetching dashboard metrics:', error);
      // Mock data for demo
      setMetrics({
        totalTraffic: 15847,
        threatsBlocked: 234,
        activeAlerts: 12,
        honeypotInteractions: 89,
        trafficChart: generateMockTrafficData(),
        alertsChart: generateMockAlertsData()
      });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDashboardMetrics();
    const interval = setInterval(fetchDashboardMetrics, 30000);
    return () => clearInterval(interval);
  }, []);

  const generateMockTrafficData = (): Array<{
    time: string;
    normal: number;
    malicious: number;
    total: number;
  }> => {
    const data: Array<{
      time: string;
      normal: number;
      malicious: number;
      total: number;
    }> = [];
    for (let i = 23; i >= 0; i--) {
      const hour = new Date();
      hour.setHours(hour.getHours() - i);
      data.push({
        time: hour.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' }),
        normal: Math.floor(Math.random() * 100) + 50,
        malicious: Math.floor(Math.random() * 20) + 5,
        total: 0
      });
    }
    return data.map(item => ({ ...item, total: item.normal + item.malicious }));
  };

  const generateMockAlertsData = (): Array<{
    time: string;
    high: number;
    medium: number;
    low: number;
  }> => {
    const data: Array<{
      time: string;
      high: number;
      medium: number;
      low: number;
    }> = [];
    for (let i = 23; i >= 0; i--) {
      const hour = new Date();
      hour.setHours(hour.getHours() - i);
      data.push({
        time: hour.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' }),
        high: Math.floor(Math.random() * 5),
        medium: Math.floor(Math.random() * 10) + 2,
        low: Math.floor(Math.random() * 15) + 5
      });
    }
    return data;
  };

  const threatDistribution = [
    { name: 'SQL Injection', value: 35, color: '#dc2626' },
    { name: 'XSS', value: 25, color: '#ea580c' },
    { name: 'Port Scan', value: 20, color: '#d97706' },
    { name: 'Brute Force', value: 15, color: '#65a30d' },
    { name: 'Other', value: 5, color: '#6b7280' }
  ];

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
          <h1 className="text-3xl font-bold glow-text">Security Dashboard</h1>
          <p className="text-muted-foreground">Real-time intrusion detection monitoring</p>
        </div>
        <div className="flex items-center space-x-2">
          <div className="h-3 w-3 bg-green-500 rounded-full animate-pulse"></div>
          <span className="text-sm text-green-400">Live Monitoring</span>
        </div>
      </motion.div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {[
          {
            title: 'Total Traffic',
            value: metrics?.totalTraffic.toLocaleString() || '0',
            icon: Activity,
            color: 'text-blue-400',
            bg: 'bg-blue-500/10',
            border: 'border-blue-500/20'
          },
          {
            title: 'Threats Blocked',
            value: metrics?.threatsBlocked.toLocaleString() || '0',
            icon: Shield,
            color: 'text-red-400',
            bg: 'bg-red-500/10',
            border: 'border-red-500/20'
          },
          {
            title: 'Active Alerts',
            value: metrics?.activeAlerts.toString() || '0',
            icon: AlertTriangle,
            color: 'text-yellow-400',
            bg: 'bg-yellow-500/10',
            border: 'border-yellow-500/20'
          },
          {
            title: 'Honeypot Hits',
            value: metrics?.honeypotInteractions.toString() || '0',
            icon: Bug,
            color: 'text-purple-400',
            bg: 'bg-purple-500/10',
            border: 'border-purple-500/20'
          }
        ].map((stat, index) => (
          <motion.div
            key={stat.title}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: index * 0.1 }}
            className={`bg-card border ${stat.border} rounded-lg p-6 matrix-bg`}
          >
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">{stat.title}</p>
                <p className="text-2xl font-bold mt-1">{stat.value}</p>
              </div>
              <div className={`${stat.bg} ${stat.color} p-3 rounded-lg`}>
                <stat.icon className="h-6 w-6" />
              </div>
            </div>
          </motion.div>
        ))}
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Traffic Chart */}
        <motion.div
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.4 }}
          className="bg-card border border-border rounded-lg p-6"
        >
          <h3 className="text-lg font-semibold mb-4 flex items-center">
            <TrendingUp className="h-5 w-5 mr-2 text-primary" />
            Network Traffic (24h)
          </h3>
          <ResponsiveContainer width="100%" height={300}>
            <AreaChart data={metrics?.trafficChart || []}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.1)" />
              <XAxis dataKey="time" stroke="rgba(255,255,255,0.7)" />
              <YAxis stroke="rgba(255,255,255,0.7)" />
              <Tooltip
                contentStyle={{
                  backgroundColor: 'rgba(0,0,0,0.8)',
                  border: '1px solid rgba(255,255,255,0.2)',
                  borderRadius: '8px'
                }}
              />
              <Area
                type="monotone"
                dataKey="malicious"
                stackId="1"
                stroke="#dc2626"
                fill="#dc2626"
                fillOpacity={0.6}
              />
              <Area
                type="monotone"
                dataKey="normal"
                stackId="1"
                stroke="#16a34a"
                fill="#16a34a"
                fillOpacity={0.6}
              />
            </AreaChart>
          </ResponsiveContainer>
        </motion.div>

        {/* Alerts Chart */}
        <motion.div
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.5 }}
          className="bg-card border border-border rounded-lg p-6"
        >
          <h3 className="text-lg font-semibold mb-4 flex items-center">
            <AlertTriangle className="h-5 w-5 mr-2 text-yellow-400" />
            Security Alerts (24h)
          </h3>
          <ResponsiveContainer width="100%" height={300}>
            <LineChart data={metrics?.alertsChart || []}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.1)" />
              <XAxis dataKey="time" stroke="rgba(255,255,255,0.7)" />
              <YAxis stroke="rgba(255,255,255,0.7)" />
              <Tooltip
                contentStyle={{
                  backgroundColor: 'rgba(0,0,0,0.8)',
                  border: '1px solid rgba(255,255,255,0.2)',
                  borderRadius: '8px'
                }}
              />
              <Line type="monotone" dataKey="high" stroke="#dc2626" strokeWidth={2} />
              <Line type="monotone" dataKey="medium" stroke="#ea580c" strokeWidth={2} />
              <Line type="monotone" dataKey="low" stroke="#65a30d" strokeWidth={2} />
            </LineChart>
          </ResponsiveContainer>
        </motion.div>
      </div>

      {/* Bottom Section */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Threat Distribution */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.6 }}
          className="bg-card border border-border rounded-lg p-6"
        >
          <h3 className="text-lg font-semibold mb-4 flex items-center">
            <Zap className="h-5 w-5 mr-2 text-orange-400" />
            Threat Distribution
          </h3>
          <ResponsiveContainer width="100%" height={200}>
            <PieChart>
              <Pie
                data={threatDistribution}
                cx="50%"
                cy="50%"
                innerRadius={40}
                outerRadius={80}
                paddingAngle={5}
                dataKey="value"
              >
                {threatDistribution.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{
                  backgroundColor: 'rgba(0,0,0,0.9)',
                  border: '1px solid rgba(255,255,255,0.3)',
                  borderRadius: '8px',
                  color: '#ffffff'
                }}
                labelStyle={{ color: '#ffffff' }}
              />
            </PieChart>
          </ResponsiveContainer>
        </motion.div>

        {/* System Status */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.7 }}
          className="bg-card border border-border rounded-lg p-6"
        >
          <h3 className="text-lg font-semibold mb-4 flex items-center">
            <Lock className="h-5 w-5 mr-2 text-green-400" />
            Security Status
          </h3>
          <div className="space-y-3">
            {[
              { name: 'SSL/TLS', status: 'Active', color: 'text-green-400' },
              { name: 'Firewall', status: 'Protected', color: 'text-green-400' },
              { name: 'IDS Engine', status: 'Running', color: 'text-green-400' },
              { name: 'Honeypot', status: 'Monitoring', color: 'text-green-400' },
              { name: 'Rate Limiting', status: 'Enabled', color: 'text-green-400' }
            ].map((item, index) => (
              <div key={item.name} className="flex items-center justify-between">
                <span className="text-sm text-muted-foreground">{item.name}</span>
                <span className={`text-sm font-medium ${item.color}`}>
                  {item.status}
                </span>
              </div>
            ))}
          </div>
        </motion.div>

        {/* Recent Activity */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.8 }}
          className="bg-card border border-border rounded-lg p-6"
        >
          <h3 className="text-lg font-semibold mb-4">Recent Activity</h3>
          <div className="space-y-3">
            {[
              { event: 'SQL injection blocked', time: '2 min ago', severity: 'high' },
              { event: 'Port scan detected', time: '5 min ago', severity: 'medium' },
              { event: 'Honeypot interaction', time: '8 min ago', severity: 'low' },
              { event: 'Brute force attempt', time: '12 min ago', severity: 'high' },
              { event: 'XSS attack prevented', time: '15 min ago', severity: 'medium' }
            ].map((activity, index) => (
              <div key={index} className="flex items-center justify-between">
                <div className="flex items-center space-x-2">
                  <div className={`h-2 w-2 rounded-full ${
                    activity.severity === 'high' ? 'bg-red-500' :
                    activity.severity === 'medium' ? 'bg-yellow-500' : 'bg-green-500'
                  }`} />
                  <span className="text-sm">{activity.event}</span>
                </div>
                <span className="text-xs text-muted-foreground">{activity.time}</span>
              </div>
            ))}
          </div>
        </motion.div>
      </div>
    </div>
  );
};

export default Dashboard;
