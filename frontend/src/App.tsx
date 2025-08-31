import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { motion } from 'framer-motion';
import Sidebar from './components/Sidebar';
import Header from './components/Header';
import Dashboard from './pages/Dashboard';
import TrafficMonitor from './pages/TrafficMonitor';
import AlertCenter from './pages/AlertCenter';
import HoneypotLogs from './pages/HoneypotLogs';
import SystemStatus from './pages/SystemStatus';
import RuleManagement from './pages/RuleManagement';

function App() {
  return (
    <Router>
      <div className="min-h-screen bg-gradient-cyber text-foreground">
        {/* Matrix background effect */}
        <div className="fixed inset-0 cyber-grid opacity-20 pointer-events-none" />
        
        <div className="flex h-screen">
          <Sidebar />
          
          <div className="flex-1 flex flex-col overflow-hidden">
            <Header />
            
            <main className="flex-1 overflow-auto p-6">
              <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.5 }}
                className="h-full"
              >
                <Routes>
                  <Route path="/" element={<Dashboard />} />
                  <Route path="/traffic" element={<TrafficMonitor />} />
                  <Route path="/alerts" element={<AlertCenter />} />
                  <Route path="/honeypot" element={<HoneypotLogs />} />
                  <Route path="/system" element={<SystemStatus />} />
                  <Route path="/rules" element={<RuleManagement />} />
                </Routes>
              </motion.div>
            </main>
          </div>
        </div>
      </div>
    </Router>
  );
}

export default App;
