import React, { useState, useEffect, useRef } from 'react';
import { Network } from 'vis-network';
import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from 'recharts';
import { ShieldAlert, User, Cpu, Activity, AlertTriangle, ShieldCheck, Clock, Shield, Sun, Moon } from 'lucide-react';

export default function App() {
  const [alerts, setAlerts] = useState([]);
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [riskTrend, setRiskTrend] = useState([]);
  const [isLightMode, setIsLightMode] = useState(false);
  const graphRef = useRef(null);
  const networkRef = useRef(null);

  // Apply Light Mode class to Body
  useEffect(() => {
    if (isLightMode) {
      document.body.classList.add('light-theme');
    } else {
      document.body.classList.remove('light-theme');
    }
  }, [isLightMode]);

  // 1. Fetch Alerts from FastAPI
  useEffect(() => {
    fetch('http://127.0.0.1:8000/api/alerts')
      .then(res => res.json())
      .then(data => {
        if (data.status === 'success' && data.data.length > 0) {
          setAlerts(data.data);
          handleSelectAlert(data.data[0]);
        }
      })
      .catch(err => console.error("Error fetching alerts:", err));
  }, []);

  // 2. Fetch Entity History & Render Graph
  const handleSelectAlert = (alert) => {
    setSelectedAlert(alert);
    
    // Fetch Trend
    fetch(`http://127.0.0.1:8000/api/entity/${alert.entity_id}/history`)
      .then(res => res.json())
      .then(data => {
        if (data.status === 'success') {
          const formatted = data.risk_trend.map((t, idx) => ({
            time: `T-${data.risk_trend.length - idx}`,
            risk: t.risk_score
          }));
          setRiskTrend(formatted);
        }
      });
  };

  // 3. Update Graph dynamically whenever selectedAlert OR isLightMode changes
  useEffect(() => {
    if (!selectedAlert || !graphRef.current) return;

    const nodeBg = isLightMode ? '#ffffff' : '#1e293b';
    const nodeFont = isLightMode ? '#0f172a' : 'white';
    const edgeFontBg = isLightMode ? '#f8fafc' : '#18181b';

    const nodes = [
      { id: 1, label: `Entity:\n${selectedAlert.entity_id}`, shape: 'circle', color: { background: nodeBg, border: '#3b82f6' }, font: { color: nodeFont } },
      { id: 2, label: `IP:\n${selectedAlert.source_ip}`, shape: 'box', color: { background: nodeBg, border: '#94a3b8' }, font: { color: nodeFont } },
      { id: 3, label: `Resource:\n${selectedAlert.resource_accessed}`, shape: 'diamond', color: { background: '#ef4444', border: '#dc2626' }, font: { color: 'white' } }
    ];

    const edges = [
      { from: 1, to: 2, label: 'logged in from', color: '#94a3b8' },
      { from: 2, to: 3, label: 'accessed', color: '#ef4444', width: 2, dashes: true }
    ];

    if (selectedAlert.chain_involved) {
      nodes.push({ id: 4, label: 'Compromised\nSequence', shape: 'star', color: { background: '#ef4444', border: '#dc2626' }, font: { color: 'white' } });
      edges.push({ from: 1, to: 4, color: '#ef4444', width: 2 });
      edges.push({ from: 4, to: 3, color: '#ef4444', width: 2 });
    }

    const data = { nodes, edges };
    const options = {
      physics: { enabled: true, solver: 'forceAtlas2Based' },
      edges: { font: { color: '#a1a1aa', size: 12, background: edgeFontBg } }
    };

    if (networkRef.current) networkRef.current.destroy();
    networkRef.current = new Network(graphRef.current, data, options);
  }, [selectedAlert, isLightMode]);

  // 4. Handle Feedback Action
  const handleFeedback = (decision) => {
    fetch(`http://127.0.0.1:8000/api/alerts/${selectedAlert.id}/feedback`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ decision, notes: "Logged via Dashboard" })
    })
    .then(res => res.json())
    .then(data => {
      const newAlerts = alerts.filter(a => a.id !== selectedAlert.id);
      setAlerts(newAlerts);
      if (newAlerts.length > 0) handleSelectAlert(newAlerts[0]);
    });
  };

  if (!selectedAlert) return <div style={{height: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center'}}>Loading Models...</div>;

  return (
    <div>
      {/* NAVBAR */}
      <div className="navbar">
        <div className="nav-title">
          <Shield color="#3b82f6" /> Honeywell SOC Assistant
        </div>
        
        {/* THEME TOGGLE */}
        <button 
          className="theme-toggle"
          onClick={() => setIsLightMode(!isLightMode)}
          title={isLightMode ? 'Switch to Dark Mode' : 'Switch to Light Mode'}
        >
          {isLightMode ? <Moon size={18} /> : <Sun size={18} />}
        </button>
      </div>

      <div className="app-container">
        {/* SIDEBAR: Alert Queue */}
        <div className="alert-sidebar fade-in">
          <div className="sidebar-header">
            <span style={{display: 'flex', alignItems: 'center', gap: '8px'}}><AlertTriangle size={18} color="#ef4444"/> Alert Queue</span>
            <span className="count">{alerts.length} Pending</span>
          </div>
          
          <div className="alert-list">
            {alerts.map(alert => (
              <div 
                key={alert.id} 
                className={`alert-card ${selectedAlert.id === alert.id ? 'selected' : ''} ${alert.chain_involved ? 'chain' : ''}`}
                onClick={() => handleSelectAlert(alert)}
              >
                <div className="alert-header">
                  <span className="alert-entity">{alert.entity_id}</span>
                  <span className={`risk-badge ${alert.adaptive_risk_score > 70 ? 'risk-high' : alert.adaptive_risk_score > 40 ? 'risk-med' : 'risk-low'}`}>
                    Risk: {alert.adaptive_risk_score}
                  </span>
                </div>
                <div style={{fontSize: '0.85rem', color: 'var(--text-muted)'}}>
                  {alert.chain_involved ? 'Chain Compromise (Critical)' : alert.predicted_attack_class.replace('_', ' ')}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* MAIN CONTENT */}
        <div className="main-content">
          
          {/* STAT CARDS */}
          <div className="stats-grid">
            <div className={`stat-card fade-in ${selectedAlert.chain_involved ? 'critical' : ''}`}>
              <div className="stat-title"><Cpu size={16} /> ML Prediction</div>
              <div className={`stat-value ${selectedAlert.chain_involved ? 'red' : ''}`}>
                {selectedAlert.chain_involved ? 'Chain Attack' : selectedAlert.predicted_attack_class.replace('_', ' ').toUpperCase()}
              </div>
              <div style={{marginTop: '0.75rem'}}>
                <div style={{fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '4px'}}>AI Confidence Level</div>
                <div className="meter-bg">
                  <div className="meter-fill" style={{width: `${(selectedAlert.attack_confidence * 100).toFixed(0)}%`}}></div>
                </div>
              </div>
            </div>

            <div className="stat-card fade-in" style={{animationDelay: '0.1s'}}>
              <div className="stat-title"><ShieldAlert size={16} /> MITRE ATT&CK Mapping</div>
              <div className="stat-value">{selectedAlert.mitre_mapping.id}</div>
              <div style={{color: 'var(--text-muted)', fontSize: '0.95rem', marginTop: '1rem'}}>
                Tactic: <strong style={{color: 'var(--text-main)'}}>{selectedAlert.mitre_mapping.tactic}</strong>
              </div>
            </div>

            <div className="stat-card fade-in" style={{animationDelay: '0.2s'}}>
              <div className="stat-title"><ShieldCheck size={16} /> Recommended Action</div>
              <div style={{fontSize: '1.1rem', fontWeight: 500, lineHeight: 1.4, color: selectedAlert.adaptive_risk_score > 70 ? (isLightMode ? '#dc2626' : '#fca5a5') : 'var(--text-main)'}}>
                {selectedAlert.recommendation}
              </div>
            </div>
          </div>

          {/* LOWER GRID: Graph vs Context */}
          <div className="details-grid">
            
            {/* Left: Vis Graph */}
            <div className="panel fade-in" style={{animationDelay: '0.3s'}}>
              <div className="panel-title"><Activity size={18} /> Attack Relationship Graph</div>
              <div 
                ref={graphRef} 
                style={{width: '100%', height: '400px', background: isLightMode ? '#f1f5f9' : 'rgba(0,0,0,0.3)', borderRadius: '8px', border: '1px solid var(--border-color)'}}
              ></div>
            </div>

            {/* Right: Context & Trend */}
            <div className="panel fade-in" style={{animationDelay: '0.4s'}}>
              <div className="panel-title"><Clock size={18} /> Alert Context & Reasons (SHAP)</div>
              
              <div className="context-grid">
                <span className="context-label">Time:</span> <span className="context-value">{selectedAlert.timestamp}</span>
                <span className="context-label">IP Address:</span> <span className="context-value">{selectedAlert.source_ip}</span>
                <span className="context-label">Geo Location:</span> <span className="context-value">{selectedAlert.geo_location}</span>
                <span className="context-label">Resource:</span> <span className="context-value">{selectedAlert.resource_accessed}</span>
              </div>

              <div className="shap-box">
                <h4>Why did the AI flag this?</h4>
                <ul>
                  {selectedAlert.reasons.split(' | ').map((r, i) => (
                    <li key={i}>{r}</li>
                  ))}
                </ul>
              </div>

              {/* Trend Chart */}
              <div style={{marginTop: '1.5rem', flexGrow: 1}}>
                <div style={{fontSize: '0.9rem', color: 'var(--text-muted)', marginBottom: '0.5rem'}}>Entity Risk Trend</div>
                <div style={{height: '140px', width: '100%'}}>
                  <ResponsiveContainer width="100%" height="100%">
                    <LineChart data={riskTrend}>
                      <CartesianGrid strokeDasharray="3 3" stroke={isLightMode ? "#e2e8f0" : "rgba(255,255,255,0.05)"} />
                      <XAxis dataKey="time" stroke={isLightMode ? "#64748b" : "#a1a1aa"} fontSize={11} />
                      <YAxis stroke={isLightMode ? "#64748b" : "#a1a1aa"} fontSize={11} domain={[0, 100]} />
                      <Tooltip contentStyle={{background: isLightMode ? '#ffffff' : '#18181b', border: `1px solid ${isLightMode ? '#e2e8f0' : '#3f3f46'}`, borderRadius: '8px', color: 'var(--text-main)'}} />
                      <Line type="monotone" dataKey="risk" stroke="#ef4444" strokeWidth={3} dot={{r: 4, fill: '#ef4444'}} />
                    </LineChart>
                  </ResponsiveContainer>
                </div>
              </div>
            </div>

          </div>

          {/* Action Bar */}
          <div className="action-bar fade-in" style={{animationDelay: '0.5s'}}>
            <span style={{marginRight: 'auto', color: 'var(--text-muted)', fontSize: '0.95rem'}}>
              Analyst Feedback Required for Alert #{selectedAlert.id}
            </span>
            <button className="btn btn-reject" onClick={() => handleFeedback('reject')}>
              Mark as False Positive
            </button>
            <button className="btn btn-accept" onClick={() => handleFeedback('accept')}>
              Confirm Threat (True Positive)
            </button>
          </div>

        </div>
      </div>
    </div>
  );
}
