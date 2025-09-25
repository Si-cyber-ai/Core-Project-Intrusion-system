import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import {
  Lock,
  Plus,
  Edit,
  Trash2,
  Save,
  X,
  RefreshCw,
  AlertTriangle,
  CheckCircle,
  Code
} from 'lucide-react';

interface RegexRule {
  id?: number;
  name: string;
  pattern: string;
  severity: string;
  description?: string;
  enabled?: boolean;
}

const RuleManagement: React.FC = () => {
  const [rules, setRules] = useState<RegexRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [showAddForm, setShowAddForm] = useState(false);
  const [editingRule, setEditingRule] = useState<RegexRule | null>(null);
  const [newRule, setNewRule] = useState<RegexRule>({
    name: '',
    pattern: '',
    severity: 'Medium'
  });

  const fetchRules = async () => {
    try {
      setLoading(true);
      const response = await fetch('http://localhost:8000/api/rules');
      const data = await response.json();
      if (data.status === 'success') {
        setRules(data.rules);
      }
    } catch (error) {
      console.error('Error fetching rules:', error);
      setRules(generateMockRules());
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchRules();
  }, []);


  const generateMockRules = (): RegexRule[] => {
    return [
      {
        name: "SQL Injection",
        pattern: "(union|select|insert|delete|drop|update|exec|script).*(\s|;|'|\"|--)",
        severity: "High"
      },
      {
        name: "XSS Attack",
        pattern: "<script[^>]*>.*?</script>|javascript:|on\\w+\\s*=",
        severity: "High"
      },
      {
        name: "Directory Traversal",
        pattern: "(\\.\\.[/\\\\]|\\.\\..%2F|\\.\\..%5C)",
        severity: "Medium"
      },
      {
        name: "Command Injection",
        pattern: "\\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION)\\b",
        severity: "High"
      },
      {
        name: "Port Scan",
        pattern: "nmap|masscan|zmap|unicornscan",
        severity: "Medium"
      },
      {
        name: "Brute Force",
        pattern: "(admin|root|administrator|login|password).*?(admin|password|123456|qwerty)",
        severity: "Medium"
      }
    ];
  };

  const handleAddRule = async () => {
    if (!newRule.name.trim() || !newRule.pattern.trim()) {
      alert('Please fill in all required fields');
      return;
    }

    if (!validateRegex(newRule.pattern)) {
      alert('Please enter a valid regex pattern');
      return;
    }

    try {
      const response = await fetch('http://localhost:8000/api/rules', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(newRule),
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const data = await response.json();
      
      if (data.status === 'success') {
        setRules([...rules, { ...newRule }]);
        setNewRule({ name: '', pattern: '', severity: 'Medium' });
        setShowAddForm(false);
      } else {
        throw new Error(data.message || 'Failed to add rule');
      }
    } catch (error) {
      console.error('Error adding rule:', error);
      // For demo, add locally
      setRules([...rules, { ...newRule }]);
      setNewRule({ name: '', pattern: '', severity: 'Medium' });
      setShowAddForm(false);
    }
  };

  const handleDeleteRule = async (index: number) => {
    const rule = rules[index];
    if (!rule.id) {
      // Fallback for rules without ID
      setRules(rules.filter((_, i) => i !== index));
      return;
    }

    try {
      const response = await fetch(`http://localhost:8000/api/rules/${rule.id}`, {
        method: 'DELETE',
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const data = await response.json();
      
      if (data.status === 'success') {
        setRules(rules.filter((_, i) => i !== index));
      } else {
        throw new Error(data.message || 'Failed to delete rule');
      }
    } catch (error) {
      console.error('Error deleting rule:', error);
      alert('Failed to delete rule. Please try again.');
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'high': return 'bg-red-500/20 text-red-400 border-red-500/30';
      case 'medium': return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
      case 'low': return 'bg-blue-500/20 text-blue-400 border-blue-500/30';
      default: return 'bg-gray-500/20 text-gray-400 border-gray-500/30';
    }
  };

  const validateRegex = (pattern: string): boolean => {
    try {
      new RegExp(pattern);
      return true;
    } catch {
      return false;
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
            <Lock className="h-8 w-8 mr-3 text-primary" />
            Rule Management
          </h1>
          <p className="text-muted-foreground">Configure detection rules and patterns</p>
        </div>
        <div className="flex items-center space-x-3">
          <motion.button
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
            onClick={fetchRules}
            className="flex items-center space-x-2 px-4 py-2 bg-secondary text-secondary-foreground rounded-lg hover:bg-secondary/80 transition-colors"
          >
            <RefreshCw className="h-4 w-4" />
            <span>Refresh</span>
          </motion.button>
          <motion.button
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
            onClick={() => setShowAddForm(true)}
            className="flex items-center space-x-2 px-4 py-2 bg-primary text-primary-foreground rounded-lg hover:bg-primary/90 transition-colors"
          >
            <Plus className="h-4 w-4" />
            <span>Add Rule</span>
          </motion.button>
        </div>
      </motion.div>

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {[
          { label: 'Total Rules', value: rules.length, color: 'text-blue-400' },
          { label: 'High Severity', value: rules.filter(rule => rule.severity === 'High').length, color: 'text-red-400' },
          { label: 'Active Rules', value: rules.length, color: 'text-green-400' }
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

      {/* Add Rule Form */}
      {showAddForm && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="bg-card border border-border rounded-lg p-6"
        >
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold flex items-center">
              <Plus className="h-5 w-5 mr-2 text-primary" />
              Add New Rule
            </h3>
            <button
              onClick={() => setShowAddForm(false)}
              className="text-muted-foreground hover:text-foreground"
            >
              <X className="h-5 w-5" />
            </button>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div>
              <label className="block text-sm font-medium mb-2">Rule Name</label>
              <input
                type="text"
                value={newRule.name}
                onChange={(e) => setNewRule({ ...newRule, name: e.target.value })}
                placeholder="Enter rule name"
                className="w-full bg-background border border-border rounded-md px-3 py-2 text-sm"
              />
            </div>
            
            <div>
              <label className="block text-sm font-medium mb-2">Severity</label>
              <select
                value={newRule.severity}
                onChange={(e) => setNewRule({ ...newRule, severity: e.target.value })}
                className="w-full bg-background border border-border rounded-md px-3 py-2 text-sm"
              >
                <option value="High">High</option>
                <option value="Medium">Medium</option>
                <option value="Low">Low</option>
              </select>
            </div>
            
            <div className="flex items-end">
              <motion.button
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
                onClick={handleAddRule}
                disabled={!newRule.name || !newRule.pattern || !validateRegex(newRule.pattern)}
                className="w-full flex items-center justify-center space-x-2 px-4 py-2 bg-primary text-primary-foreground rounded-lg hover:bg-primary/90 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <Save className="h-4 w-4" />
                <span>Save Rule</span>
              </motion.button>
            </div>
          </div>
          
          <div className="mt-4">
            <label className="block text-sm font-medium mb-2">Regex Pattern</label>
            <div className="relative">
              <input
                type="text"
                value={newRule.pattern}
                onChange={(e) => setNewRule({ ...newRule, pattern: e.target.value })}
                placeholder="Enter regex pattern"
                className={`w-full bg-background border rounded-md px-3 py-2 text-sm font-mono ${
                  newRule.pattern && !validateRegex(newRule.pattern) 
                    ? 'border-red-500' 
                    : 'border-border'
                }`}
              />
              {newRule.pattern && (
                <div className="absolute right-3 top-2">
                  {validateRegex(newRule.pattern) ? (
                    <CheckCircle className="h-4 w-4 text-green-400" />
                  ) : (
                    <AlertTriangle className="h-4 w-4 text-red-400" />
                  )}
                </div>
              )}
            </div>
            {newRule.pattern && !validateRegex(newRule.pattern) && (
              <p className="text-red-400 text-xs mt-1">Invalid regex pattern</p>
            )}
          </div>
        </motion.div>
      )}

      {/* Rules Table */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.4 }}
        className="bg-card border border-border rounded-lg overflow-hidden"
      >
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-muted/50">
              <tr>
                <th className="px-4 py-3 text-left text-sm font-medium">Rule Name</th>
                <th className="px-4 py-3 text-left text-sm font-medium">Pattern</th>
                <th className="px-4 py-3 text-left text-sm font-medium">Severity</th>
                <th className="px-4 py-3 text-left text-sm font-medium">Status</th>
                <th className="px-4 py-3 text-left text-sm font-medium">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {rules.map((rule, index) => (
                <motion.tr
                  key={index}
                  initial={{ opacity: 0, x: -20 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: index * 0.05 }}
                  className="hover:bg-muted/30 transition-colors"
                >
                  <td className="px-4 py-3 text-sm font-medium">{rule.name}</td>
                  <td className="px-4 py-3 text-sm max-w-md">
                    <div className="flex items-center space-x-2">
                      <Code className="h-4 w-4 text-muted-foreground flex-shrink-0" />
                      <code className="font-mono text-xs bg-muted/50 px-2 py-1 rounded truncate">
                        {rule.pattern}
                      </code>
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <span className={`px-2 py-1 rounded-full text-xs border ${getSeverityColor(rule.severity)}`}>
                      {rule.severity}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center space-x-2">
                      <div className="h-2 w-2 bg-green-500 rounded-full"></div>
                      <span className="text-sm text-green-400">Active</span>
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center space-x-2">
                      <motion.button
                        whileHover={{ scale: 1.1 }}
                        whileTap={{ scale: 0.9 }}
                        onClick={() => setEditingRule(null)}
                        className="text-blue-400 hover:text-blue-300"
                      >
                        <Edit className="h-4 w-4" />
                      </motion.button>
                      <motion.button
                        whileHover={{ scale: 1.1 }}
                        whileTap={{ scale: 0.9 }}
                        onClick={() => handleDeleteRule(index)}
                        className="text-red-400 hover:text-red-300"
                      >
                        <Trash2 className="h-4 w-4" />
                      </motion.button>
                    </div>
                  </td>
                </motion.tr>
              ))}
            </tbody>
          </table>
        </div>
      </motion.div>

      {/* Rule Examples */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.5 }}
        className="bg-card border border-border rounded-lg p-6"
      >
        <h3 className="text-lg font-semibold mb-4">Common Regex Patterns</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
          <div className="space-y-3">
            <div>
              <div className="font-medium text-red-400 mb-1">SQL Injection</div>
              <code className="bg-muted/50 px-2 py-1 rounded text-xs font-mono block">
                (union|select|insert|delete|drop).*(\s|;|'|")
              </code>
            </div>
            <div>
              <div className="font-medium text-orange-400 mb-1">XSS Attack</div>
              <code className="bg-muted/50 px-2 py-1 rounded text-xs font-mono block">
                &lt;script[^&gt;]*&gt;.*?&lt;/script&gt;|javascript:
              </code>
            </div>
            <div>
              <div className="font-medium text-yellow-400 mb-1">Directory Traversal</div>
              <code className="bg-muted/50 px-2 py-1 rounded text-xs font-mono block">
                \.\./|\.\.\|%2e%2e%2f|%2e%2e%5c
              </code>
            </div>
          </div>
          <div className="space-y-3">
            <div>
              <div className="font-medium text-purple-400 mb-1">Command Injection</div>
              <code className="bg-muted/50 px-2 py-1 rounded text-xs font-mono block">
                (\||;|&|`|\$\().*?(ls|cat|wget|curl|bash)
              </code>
            </div>
            <div>
              <div className="font-medium text-blue-400 mb-1">Email Pattern</div>
              <code className="bg-muted/50 px-2 py-1 rounded text-xs font-mono block">
                [a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]&#123;2,&#125;
              </code>
            </div>
            <div>
              <div className="font-medium text-green-400 mb-1">IP Address</div>
              <code className="bg-muted/50 px-2 py-1 rounded text-xs font-mono block">
                \b(?:[0-9]&#123;1,3&#125;\.&#41;&#123;3&#125;[0-9]&#123;1,3&#125;\b
              </code>
            </div>
          </div>
        </div>
      </motion.div>
    </div>
  );
};

export default RuleManagement;
