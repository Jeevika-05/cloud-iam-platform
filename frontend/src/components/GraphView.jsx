import React, { useState, useEffect, useRef } from 'react';
import client from '../api/client';
import ForceGraph2D from 'react-force-graph-2d';

const Legend = ({ darkMode }) => (
  <div style={{
    position: 'absolute',
    right: 20,
    top: 20,
    background: darkMode ? '#0f172a' : '#fff',
    color: darkMode ? '#f8fafc' : '#000',
    padding: '10px',
    borderRadius: '8px',
    border: `1px solid ${darkMode ? '#334155' : 'transparent'}`,
    boxShadow: '0 2px 6px rgba(0,0,0,0.2)',
    zIndex: 10
  }}>
    <div><span style={{color:'#EF4444'}}>●</span> Attack</div>
    <div><span style={{color:'#10B981'}}>●</span> Defense</div>
    <div><span style={{color:'#A78BFA'}}>●</span> User</div>
    <div><span style={{color:'#60A5FA'}}>●</span> IP</div>
    <div><span style={{color:'#38BDF8'}}>●</span> Endpoint</div>
  </div>
);

const Spinner = () => (
  <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '100%', gap: '12px', padding: '40px' }}>
    <div style={{ width: '36px', height: '36px', border: '3px solid #f3f3f3', borderTop: '3px solid #3b82f6', borderRadius: '50%', animation: 'spin 1s linear infinite' }} />
    <style>{`@keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }`}</style>
    <p style={{ color: '#6b7280', fontWeight: 500, margin: 0 }}>Loading graph...</p>
  </div>
);

const ErrorBox = ({ message, onRetry }) => (
  <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '100%', gap: '12px', textAlign: 'center', padding: '40px' }}>
    <p style={{ color: '#ef4444', fontWeight: 600, margin: 0 }}>{message}</p>
    <button
      onClick={onRetry}
      style={{ padding: '8px 14px', borderRadius: '8px', border: '1px solid rgba(59, 130, 246, 0.35)', background: 'rgba(59, 130, 246, 0.08)', color: '#2563eb', cursor: 'pointer', fontWeight: 600 }}
    >
      Retry
    </button>
  </div>
);

const normalizeGraphResponse = (payload) => {
  const data = payload?.data ?? payload ?? {};
  const nodes = Array.isArray(data?.nodes) ? data.nodes : [];
  const edges = Array.isArray(data?.edges)
    ? data.edges
    : Array.isArray(data?.links)
      ? data.links
      : [];

  return { nodes, edges };
};

const GraphView = ({ darkMode = false, correlationId = '' }) => {
  const fgRef = useRef();
  // Existing state
  const [type, setType] = useState('attack-defense');
  
  // Filtering state
  const [severity, setSeverity] = useState('');
  const [limit, setLimit] = useState(50);
  
  const [graphData, setGraphData] = useState({ nodes: [], edges: [] });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [reloadKey, setReloadKey] = useState(0);

  // Selection state
  const [selectedNode, setSelectedNode] = useState(null);

  // Highlighting state
  const [highlightNodes, setHighlightNodes] = useState(new Set());
  const [highlightLinks, setHighlightLinks] = useState(new Set());

  useEffect(() => {
    let active = true;

    const fetchGraph = async () => {
      setLoading(true);
      setError('');
      try {
        const params = new URLSearchParams();
        params.set('type', type);
        params.set('limit', String(limit));
        if (severity) {
          params.set('severity', severity);
        }
        if (correlationId) {
          params.set('correlation_id', correlationId);
        }

        const response = await client.get(`/graph?${params.toString()}`);
        if (active) {
          const nextGraph = normalizeGraphResponse(response.data);
          setGraphData(nextGraph);
          setSelectedNode(null);
          setHighlightNodes(new Set());
          setHighlightLinks(new Set());
        }
      } catch (err) {
        if (active) {
          console.error('Failed to fetch graph data:', err);
          setGraphData({ nodes: [], edges: [] });
          setError('Unable to load the attack graph right now. Please retry in a moment.');
        }
      } finally {
        if (active) {
          setLoading(false);
        }
      }
    };

    fetchGraph();

    return () => {
      active = false;
    };
  }, [type, limit, severity, correlationId, reloadKey]);

  const handleNodeClick = (node) => {
    if (fgRef.current) {
      fgRef.current.centerAt(node.x, node.y, 1000);
      fgRef.current.zoom(2, 1000);
    }

    const newHighlightNodes = new Set();
    const newHighlightLinks = new Set();

    newHighlightNodes.add(node);

    graphData.edges.forEach(link => {
      const sourceId = typeof link.source === 'object' ? link.source.id : link.source;
      const targetId = typeof link.target === 'object' ? link.target.id : link.target;

      if (sourceId === node.id || targetId === node.id) {
        newHighlightLinks.add(link);
        if (typeof link.source === 'object') newHighlightNodes.add(link.source);
        if (typeof link.target === 'object') newHighlightNodes.add(link.target);
      }
    });

    setHighlightNodes(newHighlightNodes);
    setHighlightLinks(newHighlightLinks);
    setSelectedNode(node);
  };

  const hasGraphData = graphData.nodes.length > 0 || graphData.edges.length > 0;

  const fetchGraph = () => setReloadKey((current) => current + 1);

  if (loading) return <Spinner />;
  if (error) return <ErrorBox message={error} onRetry={fetchGraph} />;

  return (
    <div className="graph-container" style={{ display: 'flex', flexDirection: 'column', height: '100%', gap: '20px', color: darkMode ? '#f8fafc' : 'inherit' }}>
      <div className="graph-controls" style={{ display: 'flex', gap: '15px', padding: '20px', backgroundColor: darkMode ? '#0f172a' : '#f8f9fa', borderRadius: '8px', border: `1px solid ${darkMode ? '#334155' : 'transparent'}`, flexWrap: 'wrap' }}>
        <div>
          <label style={{ marginRight: '8px', fontWeight: 'bold' }}>View Type: </label>
          <select value={type} onChange={(e) => setType(e.target.value)} style={{ padding: '4px 8px' }} disabled={loading}>
            <option value="attack-defense">Attack & Defense</option>
            <option value="attack-chain">Attack Chain</option>
            <option value="user-attack">User Attack Paths</option>
            <option value="recent">Recent Events</option>
          </select>
        </div>
        
        <div>
          <label style={{ marginRight: '8px', fontWeight: 'bold' }}>Severity: </label>
          <select value={severity} onChange={(e) => setSeverity(e.target.value)} style={{ padding: '4px 8px' }} disabled={loading}>
            <option value="">All</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>
        </div>

        <div>
          <label style={{ marginRight: '8px', fontWeight: 'bold' }}>Limit (Max 100): </label>
          <input 
            type="number" 
            value={limit} 
            onChange={(e) => {
              const val = Math.min(Math.max(parseInt(e.target.value) || 1, 1), 100);
              setLimit(val);
            }} 
            max={100}
            min={1}
            disabled={loading}
            style={{ width: '60px', padding: '4px 8px' }}
          />
        </div>
      </div>

      <div style={{ display: 'flex', gap: '20px', flex: 1, flexWrap: 'wrap' }}>
        <div className="graph-visualization" style={{ 
          flex: '2 1 640px', 
          border: `1px solid ${darkMode ? '#334155' : '#e0e0e0'}`, 
          borderRadius: '8px',
          minHeight: '500px',
          backgroundColor: darkMode ? '#0f172a' : '#fff',
          overflow: 'hidden',
          display: 'flex',
          justifyContent: 'center',
          alignItems: 'center',
          position: 'relative'
        }}>
          <Legend darkMode={darkMode} />
          {hasGraphData ? (
            <ForceGraph2D
              ref={fgRef}
                graphData={{ nodes: graphData.nodes, links: graphData.edges }}
                width={800}
                height={500}
                onNodeClick={handleNodeClick}
                onBackgroundClick={() => {
                  setHighlightNodes(new Set());
                  setHighlightLinks(new Set());
                  setSelectedNode(null);
                }}
                nodeCanvasObject={(node, ctx) => {
                  const isHighlighted = highlightNodes.has(node);

                  ctx.beginPath();
                  ctx.arc(node.x, node.y, isHighlighted ? 8 : 5, 0, 2 * Math.PI);
                  ctx.fillStyle = node.color || '#999';
                  ctx.fill();

                  if (isHighlighted) {
                    ctx.strokeStyle = '#000';
                    ctx.lineWidth = 2;
                    ctx.stroke();
                  }
                  
                  // Label rendering option as bonus usability
                  const rawLabel = node.display || node.label || '';
if (rawLabel && (isHighlighted || highlightNodes.size === 0)) {
  // Only show full label on highlighted nodes; truncate others to prevent clutter
  const MAX_CHARS = isHighlighted ? 32 : 14;
  const label = rawLabel.length > MAX_CHARS
    ? rawLabel.slice(0, MAX_CHARS - 1) + '…'
    : rawLabel;

  const fontSize = isHighlighted ? 5 : 3.5;
  ctx.font = `${fontSize}px Sans-Serif`;
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  ctx.fillStyle = isHighlighted ? '#1e293b' : '#64748b';

  // Draw a semi-transparent background pill behind label for readability
  if (isHighlighted) {
    const textWidth = ctx.measureText(label).width;
    const padding = 1.5;
    ctx.fillStyle = 'rgba(255,255,255,0.82)';
    ctx.fillRect(
      node.x - textWidth / 2 - padding,
      node.y + 6,
      textWidth + padding * 2,
      fontSize + padding * 2
    );
  }

  ctx.fillStyle = isHighlighted ? '#1e293b' : '#64748b';
  ctx.fillText(label, node.x, node.y + 8);
}
                }}
                linkWidth={link => highlightLinks.has(link) ? 3 : 1}
                linkColor={link => highlightLinks.has(link) ? '#ff0000' : '#999'}
              />
            ) : (
              <div className="empty-state" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '10px', textAlign: 'center', padding: '24px', color: '#6b7280' }}>
                <p style={{ margin: 0, fontWeight: 600 }}>No events found for this attack trace.</p>
                <p style={{ margin: 0, fontSize: '13px' }}>
                  Try clearing the correlation filter or widening the graph filters.
                </p>
              </div>
            )
          }
        </div>

        {/* Node Details Panel */}
        <div className="node-details" style={{ 
          flex: '1 1 320px', 
          border: `1px solid ${darkMode ? '#334155' : '#e0e0e0'}`, 
          borderRadius: '8px', 
          padding: '20px',
          backgroundColor: darkMode ? '#0f172a' : '#f8f9fa',
          minHeight: '500px',
          overflowY: 'auto'
        }}>
          <h3 style={{ marginTop: 0, borderBottom: `2px solid ${darkMode ? '#334155' : '#ddd'}`, paddingBottom: '10px' }}>Node Details</h3>
          {selectedNode ? (
            <div>
              <p><strong>ID:</strong> {selectedNode.id || selectedNode.identity}</p>
              <p><strong>Primary Label:</strong> {selectedNode.label}</p>
              <p><strong>Display:</strong> {selectedNode.display || 'N/A'}</p>
              {selectedNode.group && <p><strong>Group:</strong> {selectedNode.group}</p>}
              
              <h4 style={{ marginTop: '20px', marginBottom: '10px' }}>Properties</h4>
              <div style={{ backgroundColor: darkMode ? '#1e293b' : '#fff', padding: '15px', borderRadius: '4px', border: `1px solid ${darkMode ? '#334155' : '#ddd'}` }}>
                {Object.keys(selectedNode).filter(k => !['id', 'label', 'display', 'group', 'color', 'index', 'x', 'y', 'vx', 'vy', 'fx', 'fy'].includes(k)).length > 0 ? (
                  <ul style={{ margin: 0, paddingLeft: '20px' }}>
                    {Object.entries(selectedNode)
                      .filter(([key]) => !['id', 'label', 'display', 'group', 'color', 'index', 'x', 'y', 'vx', 'vy', 'fx', 'fy'].includes(key))
                      .map(([key, value]) => (
                        <li key={key} style={{ marginBottom: '8px', wordBreak: 'break-word' }}>
                          <span style={{ fontWeight: 600, color: darkMode ? '#cbd5e1' : '#444' }}>{key}:</span>{' '}
                          <span style={{ color: darkMode ? '#60a5fa' : '#0066cc' }}>
                            {typeof value === 'object' ? JSON.stringify(value) : String(value)}
                          </span>
                        </li>
                      ))}
                  </ul>
                ) : (
                  <p style={{ color: '#888', margin: 0 }}>No additional properties available.</p>
                )}
              </div>
            </div>
          ) : (
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '80%', color: '#666' }}>
              <p>Select a node to view its detailed properties.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default GraphView;
