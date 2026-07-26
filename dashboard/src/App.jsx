import React, { useState, useEffect, useRef } from 'react';
import { Network } from 'vis-network';
import jsPDF from 'jspdf';
import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from 'recharts';
import { ShieldAlert, User, Cpu, Activity, AlertTriangle, ShieldCheck, Clock, Shield, Sun, Moon, Download } from 'lucide-react';

export default function App() {
  const [alerts, setAlerts] = useState([]);
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [isLoading, setIsLoading] = useState(true);
  const [riskTrend, setRiskTrend] = useState([]);
  const [isLightMode, setIsLightMode] = useState(false);
  const [simulationMode, setSimulationMode] = useState(false);
  const [isSimRunning, setIsSimRunning] = useState(false);
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

  // 1. WebSocket Connection for Real-Time Alerts
  useEffect(() => {
    setIsLoading(true);
    setAlerts([]); // Clear UI while switching modes
    setSelectedAlert(null); // Clear stale selections from previous mode
    const modeStr = simulationMode ? "live" : "static";
    const ws = new WebSocket(`ws://127.0.0.1:8000/ws/alerts/${modeStr}`);
    
    // Also fetch current simulation status if entering live mode
    if (simulationMode) {
      fetch('http://127.0.0.1:8000/api/simulation/status')
        .then(res => res.json())
        .then(data => setIsSimRunning(data.is_running))
        .catch(console.error);
    }
    
    ws.onmessage = (event) => {
      const data = JSON.parse(event.data);
      if (data.status === 'success') {
        setAlerts(data.data);
        setIsLoading(false);
      }
    };

    ws.onerror = (err) => {
      console.error("WebSocket error:", err);
      setIsLoading(false);
    };

    return () => ws.close();
  }, [simulationMode]);

  // Auto-select first alert if current selection is resolved/missing, and keep it updated
  useEffect(() => {
    if (alerts.length > 0) {
      setSelectedAlert(prev => {
        const currentExists = prev && alerts.find(a => a.id === prev.id);
        return currentExists || alerts[0];
      });
    } else {
      setSelectedAlert(null);
    }
  }, [alerts]);

  // 2. Fetch Entity History & Render Graph
  const handleSelectAlert = (alert) => {
    setSelectedAlert(alert);
  };

  // Dynamically fetch risk trend when selection changes or new alerts arrive (live updates)
  useEffect(() => {
    if (!selectedAlert) return;
    
    const modeStr = simulationMode ? "live" : "static";
    fetch(`http://127.0.0.1:8000/api/entity/${selectedAlert.entity_id}/history?mode=${modeStr}`)
      .then(res => res.json())
      .then(data => {
        if (data.status === 'success') {
          const formatted = data.risk_trend.map((t) => ({
            time: t.timestamp,
            risk: t.risk_score
          }));
          setRiskTrend(formatted);
        }
      })
      .catch(err => console.error("Error fetching risk trend:", err));
  }, [selectedAlert, alerts, simulationMode]);

  // 3. Update Graph dynamically whenever selectedAlert OR isLightMode changes
  useEffect(() => {
    if (!selectedAlert || !graphRef.current) return;

    const nodeBg = isLightMode ? '#ffffff' : '#1e293b';
    const nodeFont = isLightMode ? '#0f172a' : 'white';
    const edgeFontBg = isLightMode ? '#f8fafc' : '#18181b';

    const nodes = [
      { id: 1, label: `Entity:\n${selectedAlert.entity_id}`, shape: 'circle', color: { background: nodeBg, border: '#3b82f6' }, font: { color: nodeFont } },
      { id: 2, label: `IP:\n${selectedAlert.source_ip}`, shape: 'box', color: { background: nodeBg, border: '#94a3b8' }, font: { color: nodeFont } },
      { id: 3, label: `Resource:\n${selectedAlert.resource_accessed}`, shape: 'diamond', color: { background: '#ef4444', border: '#dc2626' }, font: { color: nodeFont } }
    ];

    const edges = [
      { from: 1, to: 2, label: 'logged in from', color: '#94a3b8' },
      { from: 2, to: 3, label: 'accessed', color: '#ef4444', width: 2, dashes: true }
    ];

    if (selectedAlert.chain_involved) {
      nodes.push({ id: 4, label: 'Compromised\nSequence', shape: 'star', color: { background: '#ef4444', border: '#dc2626' }, font: { color: nodeFont } });
      edges.push({ from: 1, to: 4, color: '#ef4444', width: 2 });
      edges.push({ from: 4, to: 3, color: '#ef4444', width: 2 });
    }

    const data = { nodes, edges };
    const options = {
      layout: {
        randomSeed: 42
      },
      physics: { 
        enabled: true, 
        solver: 'repulsion',
        repulsion: {
          nodeDistance: 250,
          springLength: 200
        }
      },
      edges: { 
        font: { color: '#a1a1aa', size: 12, background: edgeFontBg, align: 'top', strokeWidth: 0 },
        smooth: { type: 'continuous' }
      },
      nodes: {
        margin: 15
      }
    };

    if (networkRef.current) networkRef.current.destroy();
    networkRef.current = new Network(graphRef.current, data, options);
  }, [selectedAlert, isLightMode]);

  // 4. Handle Feedback Action
  const handleFeedback = (decision) => {
    const modeStr = simulationMode ? "live" : "static";
    fetch(`http://127.0.0.1:8000/api/alerts/${selectedAlert.id}/feedback?mode=${modeStr}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ decision, notes: "Logged via Dashboard" })
    })
    .catch(err => console.error("Error logging feedback:", err));
    // Note: We no longer manually update local state. The backend WebSocket broadcast will automatically sync all clients.
  };

  // 5. Generate PDF Report
  const generatePDF = () => {
    if (!selectedAlert) return;
    const doc = new jsPDF();
    
    doc.setFontSize(22);
    doc.setTextColor(220, 38, 38);
    doc.text('SOC Incident Report', 20, 20);
    
    doc.setFontSize(12);
    doc.setTextColor(100);
    doc.text(`Generated on: ${new Date().toLocaleString()}`, 20, 30);
    
    doc.setDrawColor(200);
    doc.line(20, 35, 190, 35);
    
    doc.setFontSize(16);
    doc.setTextColor(0);
    doc.text('Alert Details', 20, 45);
    
    doc.setFontSize(12);
    doc.text(`Alert ID: ${selectedAlert.id}`, 20, 55);
    doc.text(`Entity ID: ${selectedAlert.entity_id}`, 20, 65);
    doc.text(`Timestamp: ${selectedAlert.timestamp}`, 20, 75);
    doc.text(`Source IP: ${selectedAlert.source_ip}`, 20, 85);
    doc.text(`Geo Location: ${selectedAlert.geo_location}`, 20, 95);
    doc.text(`Resource Accessed: ${selectedAlert.resource_accessed}`, 20, 105);
    
    doc.line(20, 115, 190, 115);
    
    doc.setFontSize(16);
    doc.text('Threat Analysis', 20, 125);
    
    doc.setFontSize(12);
    doc.text(`Predicted Attack Class: ${selectedAlert.predicted_attack_class}`, 20, 135);
    doc.text(`AI Confidence Level: ${(selectedAlert.attack_confidence * 100).toFixed(2)}%`, 20, 145);
    doc.text(`Adaptive Risk Score: ${selectedAlert.adaptive_risk_score}/100`, 20, 155);
    doc.text(`Chain Involved: ${selectedAlert.chain_involved ? 'Yes (Critical)' : 'No'}`, 20, 165);
    doc.text(`MITRE Mapping: ${selectedAlert.mitre_mapping.id} (${selectedAlert.mitre_mapping.tactic})`, 20, 175);
    
    doc.line(20, 185, 190, 185);
    
    doc.setFontSize(16);
    doc.text('AI Explanations (SHAP)', 20, 195);
    
    doc.setFontSize(12);
    const reasons = selectedAlert.reasons.split(' | ');
    let y = 205;
    reasons.forEach(r => {
      doc.text(`- ${r}`, 20, y);
      y += 10;
    });
    
    y += 5;
    doc.line(20, y, 190, y);
    y += 10;
    
    doc.setFontSize(16);
    doc.text('Recommended Action', 20, y);
    y += 10;
    
    doc.setFontSize(12);
    doc.setTextColor(220, 38, 38);
    const splitRec = doc.splitTextToSize(selectedAlert.recommendation, 170);
    doc.text(splitRec, 20, y);
    
    doc.save(`Incident_Report_${selectedAlert.entity_id}.pdf`);
  };

  if (isLoading) return <div style={{height: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center'}}>Loading Models...</div>;

  return (
    <div className={simulationMode ? 'simulation-mode-active' : ''}>
      {/* NAVBAR */}
      <div className="navbar" style={{ borderBottom: simulationMode ? '2px solid #ef4444' : '1px solid var(--border-color)', display: 'flex', justifyContent: 'space-between' }}>
        <div style={{ display: 'flex', alignItems: 'center' }}>
          <div className="nav-title" style={{ display: 'flex', alignItems: 'center', gap: '15px' }}>
            <Shield color={simulationMode ? "#ef4444" : "#3b82f6"} /> Honeywell SOC Assistant
          </div>
            
          <div style={{ display: 'flex', background: 'var(--bg-dark)', borderRadius: '6px', padding: '2px', border: '1px solid var(--border-color)', marginLeft: '2rem' }}>
            <button 
              onClick={() => setSimulationMode(false)}
              style={{ padding: '4px 12px', fontSize: '12px', borderRadius: '4px', background: !simulationMode ? '#3b82f6' : 'transparent', border: 'none', cursor: 'pointer', color: !simulationMode ? '#ffffff' : '#94a3b8' }}
            >
              <span style={{ fontWeight: '500', WebkitTextFillColor: 'initial' }}>Static DB</span>
            </button>
            <button 
              onClick={() => setSimulationMode(true)}
              style={{ padding: '4px 12px', fontSize: '12px', borderRadius: '4px', background: simulationMode ? '#ef4444' : 'transparent', border: 'none', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '6px', color: simulationMode ? '#ffffff' : '#94a3b8' }}
            >
              <Activity size={14} color={simulationMode ? '#ffffff' : '#94a3b8'} /> 
              <span style={{ fontWeight: '500', WebkitTextFillColor: 'initial' }}>Live Simulation</span>
            </button>
          </div>
          
          {simulationMode && (
            <div style={{ display: 'flex', gap: '10px', marginLeft: '2rem' }}>
              <button 
                onClick={() => {
                  fetch('http://127.0.0.1:8000/api/simulation/start', {method: 'POST'})
                    .then(() => setIsSimRunning(true))
                    .catch(console.error);
                }}
                disabled={isSimRunning}
                style={{ padding: '6px 16px', borderRadius: '4px', background: isSimRunning ? 'var(--bg-dark)' : '#10b981', border: '1px solid #10b981', color: isSimRunning ? 'var(--text-muted)' : '#fff', cursor: isSimRunning ? 'not-allowed' : 'pointer', fontWeight: 'bold' }}
              >
                ▶ Start
              </button>
              <button 
                onClick={() => {
                  fetch('http://127.0.0.1:8000/api/simulation/stop', {method: 'POST'})
                    .then(() => setIsSimRunning(false))
                    .catch(console.error);
                }}
                disabled={!isSimRunning}
                style={{ padding: '6px 16px', borderRadius: '4px', background: !isSimRunning ? 'var(--bg-dark)' : '#f59e0b', border: '1px solid #f59e0b', color: !isSimRunning ? 'var(--text-muted)' : '#fff', cursor: !isSimRunning ? 'not-allowed' : 'pointer', fontWeight: 'bold' }}
              >
                ⏸ Pause
              </button>
              <button 
                onClick={() => {
                  fetch('http://127.0.0.1:8000/api/simulation/reset', {method: 'POST'})
                    .then(() => setIsSimRunning(false))
                    .catch(console.error);
                }}
                style={{ padding: '6px 16px', borderRadius: '4px', background: 'transparent', border: '1px solid #ef4444', color: '#ef4444', cursor: 'pointer', fontWeight: 'bold' }}
              >
                🔄 Reset
              </button>
            </div>
          )}
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

      {alerts.length === 0 ? (
        <div style={{height: 'calc(100vh - 60px)', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', background: 'var(--bg-dark)', color: 'var(--text-main)'}}>
          {simulationMode ? (
            <>
              <Activity size={64} color={isSimRunning ? "#ef4444" : "#94a3b8"} style={{marginBottom: '1rem', animation: isSimRunning ? 'pulse 2s infinite' : 'none'}} />
              <h2>{isSimRunning ? "Streaming Live Events..." : "Simulation Ready"}</h2>
              <p style={{color: 'var(--text-muted)'}}>
                {isSimRunning ? "Waiting for the first event..." : <>Click <strong style={{color: '#10b981'}}>Start</strong> in the top menu to begin the feed.</>}
              </p>
            </>
          ) : (
            <>
              <ShieldCheck size={64} color="#10b981" style={{marginBottom: '1rem'}} />
              <h2>Zero Inbox</h2>
              <p style={{color: 'var(--text-muted)'}}>All clear! No pending alerts to review.</p>
            </>
          )}
        </div>
      ) : !selectedAlert ? null : (
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
            <span style={{color: 'var(--text-muted)', fontSize: '0.95rem'}}>
              Analyst Feedback Required for Alert #{selectedAlert.id}
            </span>
            <div style={{marginLeft: 'auto', display: 'flex', gap: '1rem'}}>
              <button 
                className="btn" 
                style={{background: 'transparent', border: '1px solid var(--border-color)', color: 'var(--text-main)'}}
                onClick={generatePDF}
              >
                <Download size={16} /> Download Report
              </button>
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
      )}
    </div>
  );
}
