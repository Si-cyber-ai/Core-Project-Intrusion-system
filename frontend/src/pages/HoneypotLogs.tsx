import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import {
  Bug,
  Globe,
  MapPin,
  Clock,
  Shield,
  AlertTriangle,
  RefreshCw,
  Download,
  Search,
  Filter
} from 'lucide-react';

interface HoneypotInteraction {
  timestamp: string;
  attacker_ip: string;
  port: number;
  payload: string;
  interaction_type: string;
  severity: string;
  geolocation: {
    country: string;
    city: string;
    region: string;
  };
  user_agent: string;
  attack_vector: string;
}

interface HoneypotStats {
  total_interactions: number;
  unique_attackers: number;
  top_attackers: Array<[string, number]>;
  attack_vectors: Record<string, number>;
  top_countries: Array<[string, number]>;
}

const HoneypotLogs: React.FC = () => {
  const [interactions, setInteractions] = useState<HoneypotInteraction[]>([]);
  const [stats, setStats] = useState<HoneypotStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState('all');
  const [searchTerm, setSearchTerm] = useState('');
  const [currentPage, setCurrentPage] = useState(1);
  const logsPerPage = 15;

  const fetchHoneypotData = async () => {
    try {
      setLoading(true);
      const response = await fetch('http://localhost:8000/api/honeypot?limit=100');
      const data = await response.json();
      if (data.status === 'success') {
        setInteractions(data.interactions);
      }
    } catch (error) {
      console.error('Error fetching honeypot data:', error);
      setInteractions(generateMockInteractions());
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHoneypotData();
    const interval = setInterval(fetchHoneypotData, 20000);
    return () => clearInterval(interval);
  }, []);


  const generateMockInteractions = (): HoneypotInteraction[] => {
    const attackVectors = ['SQL Injection', 'Cross-Site Scripting (XSS)', 'Command Injection', 'Directory Traversal', 'Brute Force', 'Port Scanning'];
    const countries = ['Russia', 'China', 'North Korea', 'Iran', 'Brazil', 'India', 'Ukraine', 'Romania'];
    const cities = ['Moscow', 'Beijing', 'Pyongyang', 'Tehran', 'São Paulo', 'Mumbai', 'Kiev', 'Bucharest'];
    const ips = ['185.220.101.42', '91.198.174.192', '123.45.67.89', '203.0.113.45', '198.51.100.78'];
    const userAgents = ['curl/7.68.0', 'python-requests/2.25.1', 'Nmap Scripting Engine', 'sqlmap/1.4.7', 'Nikto/2.1.6'];
    const severities = ['High', 'Medium', 'Low'];

    return Array.from({ length: 40 }, (_, i) => {
      const timestamp = new Date(Date.now() - Math.random() * 86400000 * 2);
      const countryIndex = Math.floor(Math.random() * countries.length);
      
      return {
        timestamp: timestamp.toISOString(),
        attacker_ip: ips[Math.floor(Math.random() * ips.length)],
        port: [22, 80, 443, 3306, 5432][Math.floor(Math.random() * 5)],
        payload: generateMockPayload(),
        interaction_type: ['ssh_brute_force', 'web_attack', 'database_attack'][Math.floor(Math.random() * 3)],
        severity: severities[Math.floor(Math.random() * severities.length)],
        geolocation: {
          country: countries[countryIndex],
          city: cities[countryIndex],
          region: cities[countryIndex]
        },
        user_agent: userAgents[Math.floor(Math.random() * userAgents.length)],
        attack_vector: attackVectors[Math.floor(Math.random() * attackVectors.length)]
      };
    }).sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
  };

  const generateMockPayload = (): string => {
    const payloads = [
      "SSH Login Attempt - Username: admin, Password: admin",
      "GET /admin/login.php HTTP/1.1",
      "POST /wp-admin/admin-ajax.php HTTP/1.1",
      "SELECT * FROM users WHERE username='admin'--",
      "GET /index.php?id=1' UNION SELECT 1,2,3,user(),database(),version()--",
      "GET /search.php?q=<script>alert('XSS')</script>",
      "GET /.env HTTP/1.1",
      "POST /upload.php HTTP/1.1"
    ];
    return payloads[Math.floor(Math.random() * payloads.length)];
  };

  const generateMockStats = (): HoneypotStats => {
    return {
      total_interactions: 156,
      unique_attackers: 23,
      top_attackers: [
        ['185.220.101.42', 15],
        ['91.198.174.192', 12],
        ['123.45.67.89', 8],
        ['203.0.113.45', 6],
        ['198.51.100.78', 5]
      ],
      attack_vectors: {
        'SQL Injection': 35,
        'Cross-Site Scripting (XSS)': 28,
        'Brute Force': 22,
        'Command Injection': 18,
        'Directory Traversal': 15,
        'Port Scanning': 12
      },
      top_countries: [
        ['Russia', 45],
        ['China', 32],
        ['North Korea', 18],
        ['Iran', 15],
        ['Brazil', 12]
      ]
    };
  };

  const filteredInteractions = (interactions || []).filter(interaction => {
    const matchesFilter = filter === 'all' || interaction.severity.toLowerCase() === filter;
    const matchesSearch = searchTerm === '' ||
      interaction.attacker_ip.includes(searchTerm) ||
      interaction.attack_vector.toLowerCase().includes(searchTerm.toLowerCase()) ||
      interaction.geolocation.country.toLowerCase().includes(searchTerm.toLowerCase());
    
    return matchesFilter && matchesSearch;
  });

  const paginatedInteractions = filteredInteractions.slice(
    (currentPage - 1) * logsPerPage,
    currentPage * logsPerPage
  );

  const totalPages = Math.ceil(filteredInteractions.length / logsPerPage);

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'high': return 'bg-red-500/20 text-red-400 border-red-500/30';
      case 'medium': return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
      case 'low': return 'bg-blue-500/20 text-blue-400 border-blue-500/30';
      default: return 'bg-gray-500/20 text-gray-400 border-gray-500/30';
    }
  };

  const getPortColor = (port: number) => {
    if (port === 22) return 'text-red-400'; // SSH
    if (port === 80 || port === 443) return 'text-blue-400'; // HTTP/HTTPS
    if (port === 3306 || port === 5432) return 'text-purple-400'; // Database
    return 'text-gray-400';
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
            <Bug className="h-8 w-8 mr-3 text-purple-400" />
            Honeypot Logs
          </h1>
          <p className="text-muted-foreground">Attacker interactions and threat intelligence</p>
        </div>
        <div className="flex items-center space-x-3">
          <motion.button
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
            onClick={fetchHoneypotData}
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

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {[
          {
            title: 'Total Interactions',
            value: stats?.total_interactions.toLocaleString() || '0',
            icon: Bug,
            color: 'text-purple-400',
            bg: 'bg-purple-500/10',
            border: 'border-purple-500/20'
          },
          {
            title: 'Unique Attackers',
            value: stats?.unique_attackers.toString() || '0',
            icon: Globe,
            color: 'text-red-400',
            bg: 'bg-red-500/10',
            border: 'border-red-500/20'
          },
          {
            title: 'High Severity',
            value: (interactions || []).filter(i => i.severity === 'High').length.toString(),
            icon: AlertTriangle,
            color: 'text-yellow-400',
            bg: 'bg-yellow-500/10',
            border: 'border-yellow-500/20'
          },
          {
            title: 'Countries',
            value: stats?.top_countries.length.toString() || '0',
            icon: MapPin,
            color: 'text-blue-400',
            bg: 'bg-blue-500/10',
            border: 'border-blue-500/20'
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

      {/* Top Attackers & Attack Vectors */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <motion.div
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.4 }}
          className="bg-card border border-border rounded-lg p-6"
        >
          <h3 className="text-lg font-semibold mb-4 flex items-center">
            <Shield className="h-5 w-5 mr-2 text-red-400" />
            Top Attackers
          </h3>
          <div className="space-y-3">
            {stats?.top_attackers.slice(0, 5).map(([ip, count], index) => (
              <div key={ip} className="flex items-center justify-between">
                <span className="font-mono text-sm">{ip}</span>
                <div className="flex items-center space-x-2">
                  <div className="w-20 bg-muted rounded-full h-2">
                    <div
                      className="bg-red-500 h-2 rounded-full transition-all duration-300"
                      style={{ width: `${(count / (stats?.top_attackers[0][1] || 1)) * 100}%` }}
                    />
                  </div>
                  <span className="text-sm text-muted-foreground w-8">{count}</span>
                </div>
              </div>
            ))}
          </div>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.5 }}
          className="bg-card border border-border rounded-lg p-6"
        >
          <h3 className="text-lg font-semibold mb-4 flex items-center">
            <AlertTriangle className="h-5 w-5 mr-2 text-yellow-400" />
            Attack Vectors
          </h3>
          <div className="space-y-3">
            {stats && Object.entries(stats.attack_vectors)
              .sort(([,a], [,b]) => b - a)
              .slice(0, 5)
              .map(([vector, count]) => (
                <div key={vector} className="flex items-center justify-between">
                  <span className="text-sm">{vector}</span>
                  <div className="flex items-center space-x-2">
                    <div className="w-20 bg-muted rounded-full h-2">
                      <div
                        className="bg-yellow-500 h-2 rounded-full transition-all duration-300"
                        style={{ 
                          width: `${(count / Math.max(...Object.values(stats.attack_vectors))) * 100}%` 
                        }}
                      />
                    </div>
                    <span className="text-sm text-muted-foreground w-8">{count}</span>
                  </div>
                </div>
              ))}
          </div>
        </motion.div>
      </div>

      {/* Filters */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.6 }}
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
              placeholder="Search by IP, attack vector, or country..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="bg-background border border-border rounded-md px-3 py-2 text-sm w-80"
            />
          </div>
        </div>
      </motion.div>

      {/* Interactions Table */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.7 }}
        className="bg-card border border-border rounded-lg overflow-hidden"
      >
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-muted/50">
              <tr>
                <th className="px-4 py-3 text-left text-sm font-medium">Timestamp</th>
                <th className="px-4 py-3 text-left text-sm font-medium">Attacker IP</th>
                <th className="px-4 py-3 text-left text-sm font-medium">Location</th>
                <th className="px-4 py-3 text-left text-sm font-medium">Port</th>
                <th className="px-4 py-3 text-left text-sm font-medium">Attack Vector</th>
                <th className="px-4 py-3 text-left text-sm font-medium">Severity</th>
                <th className="px-4 py-3 text-left text-sm font-medium">Payload</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {paginatedInteractions.map((interaction, index) => (
                <motion.tr
                  key={index}
                  initial={{ opacity: 0, x: -20 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: index * 0.05 }}
                  className="hover:bg-muted/30 transition-colors"
                >
                  <td className="px-4 py-3 text-sm terminal-text">
                    <div className="flex items-center space-x-2">
                      <Clock className="h-3 w-3" />
                      <span>{new Date(interaction.timestamp).toLocaleString()}</span>
                    </div>
                  </td>
                  <td className="px-4 py-3 text-sm font-mono text-red-400">
                    {interaction.attacker_ip}
                  </td>
                  <td className="px-4 py-3 text-sm">
                    <div className="flex items-center space-x-2">
                      <MapPin className="h-3 w-3 text-muted-foreground" />
                      <span>{interaction.geolocation.country}</span>
                    </div>
                  </td>
                  <td className="px-4 py-3 text-sm">
                    <span className={`font-mono ${getPortColor(interaction.port)}`}>
                      {interaction.port}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-sm">{interaction.attack_vector}</td>
                  <td className="px-4 py-3">
                    <span className={`px-2 py-1 rounded-full text-xs border ${getSeverityColor(interaction.severity)}`}>
                      {interaction.severity}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-sm max-w-xs">
                    <div className="truncate font-mono text-muted-foreground" title={interaction.payload}>
                      {interaction.payload}
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
            Showing {((currentPage - 1) * logsPerPage) + 1} to {Math.min(currentPage * logsPerPage, filteredInteractions.length)} of {filteredInteractions.length} results
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

export default HoneypotLogs;
