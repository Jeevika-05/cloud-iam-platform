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

const GraphView = ({ darkMode = false }) => {
  const fgRef = useRef();
  // Existing state
  const [type, setType] = useState('attack-defense');
  
  // Filtering state
  const [severity, setSeverity] = useState('');
  const [limit, setLimit] = useState(50);
  
  const [graphData, setGraphData] = useState({ nodes: [], edges: [] });
  const [loading, setLoading] = useState(false);

  // Selection state
  const [selectedNode, setSelectedNode] = useState(null);

  // Highlighting state
  const [highlightNodes, setHighlightNodes] = useState(new Set());
  const [highlightLinks, setHighlightLinks] = useState(new Set());

  useEffect(() => {
    const fetchGraph = async () => {
      setLoading(true);
      try {
        const response = await client.get(`/graph?type=${type}&limit=${limit}&severity=${severity}`);
        if (response.data.success) {
          setGraphData({
            nodes: response.data.data.nodes || [],
            edges: response.data.data.edges || []
          });
          // Clear selection when data changes
          setSelectedNode(null);
          setHighlightNodes(new Set());
          setHighlightLinks(new Set());
        }
      } catch (err) {
        console.error('Failed to fetch graph data:', err);
      } finally {
        setLoading(false);
      }
    };

    fetchGraph();
  }, [type, limit, severity]); // Update graph automatically on change

  const handleNodeClick = (node) => {
    if (fgRef.current) {
      fgRef.current.centerAt(node.x, node.y, 1000);
      fgRef.current.zoom(2, 1000);
    }

    const newHighlightNodes = new Set();
    const newHighlightLinks = new Set();

    newHighlightNodes.add(node);

    graphData.edges.forEach(link => {
      if (link.source.id === node.id || link.target.id === node.id) {
        newHighlightLinks.add(link);
        newHighlightNodes.add(link.source);
        newHighlightNodes.add(link.target);
      }
    });

    setHighlightNodes(newHighlightNodes);
    setHighlightLinks(newHighlightLinks);
    setSelectedNode(node);
  };

  return (
    <div className="graph-container" style={{ display: 'flex', flexDirection: 'column', height: '100%', gap: '20px', color: darkMode ? '#f8fafc' : 'inherit' }}>
      <div className="graph-controls" style={{ display: 'flex', gap: '15px', padding: '20px', backgroundColor: darkMode ? '#0f172a' : '#f8f9fa', borderRadius: '8px', border: `1px solid ${darkMode ? '#334155' : 'transparent'}` }}>
        <div>
          <label style={{ marginRight: '8px', fontWeight: 'bold' }}>View Type: </label>
          <select value={type} onChange={(e) => setType(e.target.value)} style={{ padding: '4px 8px' }}>
            <option value="attack-defense">Attack & Defense</option>
            <option value="attack-chain">Attack Chain</option>
            <option value="user-attack">User Attack Paths</option>
            <option value="recent">Recent Events</option>
          </select>
        </div>
        
        <div>
          <label style={{ marginRight: '8px', fontWeight: 'bold' }}>Severity: </label>
          <select value={severity} onChange={(e) => setSeverity(e.target.value)} style={{ padding: '4px 8px' }}>
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
            style={{ width: '60px', padding: '4px 8px' }}
          />
        </div>
      </div>

      <div style={{ display: 'flex', gap: '20px', flex: 1 }}>
        <div className="graph-visualization" style={{ 
          flex: 2, 
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
          {loading ? (
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '12px' }}>
              <div style={{
                width: '36px',
                height: '36px',
                border: '3px solid #f3f3f3',
                borderTop: '3px solid #3b82f6',
                borderRadius: '50%',
                animation: 'spin 1s linear infinite'
              }} />
              <style>
                {`
                  @keyframes spin {
                    0% { transform: rotate(0deg); }
                    100% { transform: rotate(360deg); }
                  }
                `}
              </style>
              <p style={{ color: '#6b7280', fontWeight: 500, margin: 0 }}>Loading graph...</p>
            </div>
          ) : (
            graphData.nodes.length > 0 ? (
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
                  const label = node.display || node.label || '';
                  if (label && (isHighlighted || highlightNodes.size === 0)) {
                    ctx.font = '4px Sans-Serif';
                    ctx.textAlign = 'center';
                    ctx.textBaseline = 'middle';
                    ctx.fillStyle = isHighlighted ? '#000' : '#333';
                    ctx.fillText(label, node.x, node.y + 8);
                  }
                }}
                linkWidth={link => highlightLinks.has(link) ? 3 : 1}
                linkColor={link => highlightLinks.has(link) ? '#ff0000' : '#999'}
              />
            ) : (
              <p style={{ color: '#888' }}>No nodes available to display.</p>
            )
          )}
        </div>

        {/* Node Details Panel */}
        <div className="node-details" style={{ 
          flex: 1, 
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
