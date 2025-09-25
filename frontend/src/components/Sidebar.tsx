import React from 'react';
import { NavLink } from 'react-router-dom';
import { motion } from 'framer-motion';
import {
  Shield,
  Activity,
  AlertTriangle,
  Bug,
  Settings,
  BarChart3,
  Lock,
  Zap,
  Cpu
} from 'lucide-react';

const navigation = [
  { name: 'Dashboard', href: '/', icon: BarChart3 },
  { name: 'Traffic Monitor', href: '/traffic', icon: Activity },
  { name: 'Sensor Simulator', href: '/sensor', icon: Cpu },
  { name: 'Alert Center', href: '/alerts', icon: AlertTriangle },
  { name: 'Honeypot Logs', href: '/honeypot', icon: Bug },
  { name: 'System Status', href: '/system', icon: Settings },
  { name: 'Rule Management', href: '/rules', icon: Lock },
];

const Sidebar: React.FC = () => {
  return (
    <div className="w-64 bg-card border-r border-border flex flex-col">
      {/* Logo */}
      <div className="p-6 border-b border-border">
        <motion.div
          initial={{ opacity: 0, scale: 0.9 }}
          animate={{ opacity: 1, scale: 1 }}
          className="flex items-center space-x-3"
        >
          <div className="relative">
            <Shield className="h-8 w-8 text-primary" />
            <motion.div
              animate={{ rotate: 360 }}
              transition={{ duration: 8, repeat: Infinity, ease: "linear" }}
              className="absolute inset-0"
            >
              <Zap className="h-8 w-8 text-primary opacity-50" />
            </motion.div>
          </div>
          <div>
            <h1 className="text-xl font-bold glow-text">SecureGuard</h1>
            <p className="text-xs text-muted-foreground">IDS v1.0</p>
          </div>
        </motion.div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 p-4 space-y-2">
        {navigation.map((item, index) => (
          <motion.div
            key={item.name}
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: index * 0.1 }}
          >
            <NavLink
              to={item.href}
              className={({ isActive }) =>
                `flex items-center space-x-3 px-3 py-2 rounded-lg text-sm font-medium transition-all duration-200 ${
                  isActive
                    ? 'bg-primary/20 text-primary border border-primary/30 pulse-border'
                    : 'text-muted-foreground hover:text-foreground hover:bg-accent'
                }`
              }
            >
              <item.icon className="h-5 w-5" />
              <span>{item.name}</span>
            </NavLink>
          </motion.div>
        ))}
      </nav>

      {/* Status indicator */}
      <div className="p-4 border-t border-border">
        <motion.div
          animate={{ opacity: [1, 0.5, 1] }}
          transition={{ duration: 2, repeat: Infinity }}
          className="flex items-center space-x-2 text-sm"
        >
          <div className="h-2 w-2 bg-green-500 rounded-full"></div>
          <span className="text-muted-foreground">System Active</span>
        </motion.div>
      </div>
    </div>
  );
};

export default Sidebar;
