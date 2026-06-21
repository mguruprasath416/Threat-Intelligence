// ============================================================
// pages/RelationshipGraph.jsx — INTERACTIVE RELATIONSHIP GRAPH
// ============================================================
// Visualizes relationships between IOCs, threat actors, and campaigns
// using Cytoscape.js. Supports click-to-pivot functionality.
// ============================================================

import { useEffect, useRef, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import cytoscape from 'cytoscape';
import axios from 'axios';
import Loader from '../components/Loader/Loader';
import './RelationshipGraph.css';

const RelationshipGraph = () => {
  const { id } = useParams();
  const navigate = useNavigate();
  const containerRef = useRef(null);
  const cyRef = useRef(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [graphData, setGraphData] = useState(null);
  const [selectedNode, setSelectedNode] = useState(null);
  const [searchValue, setSearchValue] = useState('');
  const [searching, setSearching] = useState(false);
  const [searchError, setSearchError] = useState(null);

  // Fetch graph data from backend
  useEffect(() => {
    const fetchGraphData = async () => {
      try {
        const token = localStorage.getItem('token');
        const response = await axios.get(`/ioc/${id}/graph`, {
          headers: { Authorization: `Bearer ${token}` }
        });
        setGraphData(response.data.data);
        setLoading(false);
      } catch (err) {
        setError(err.response?.data?.message || 'Failed to load graph data');
        setLoading(false);
      }
    };

    if (id) {
      fetchGraphData();
    } else {
      setLoading(false);
    }
  }, [id]);

  // Handle IOC search
  const handleSearch = async (e) => {
    e.preventDefault();
    if (!searchValue.trim()) return;

    setSearching(true);
    setSearchError(null);

    try {
      const token = localStorage.getItem('token');

      // First try to search by indicator value
      const searchResponse = await axios.post('/ioc/search',
        { indicator: searchValue.trim() },
        { headers: { Authorization: `Bearer ${token}` } }
      );

      if (searchResponse.data.data && searchResponse.data.data._id) {
        // Navigate to graph with the IOC ID
        navigate(`/graph/${searchResponse.data.data._id}`);
      } else {
        setSearchError('IOC not found. Please check the indicator value.');
      }
    } catch (err) {
      setSearchError(err.response?.data?.message || 'Failed to find IOC');
    } finally {
      setSearching(false);
    }
  };

  // Initialize Cytoscape.js graph
  useEffect(() => {
    if (!graphData || !containerRef.current) return;

    // Convert backend data to Cytoscape format
    const elements = [
      ...graphData.nodes.map(node => ({
        data: {
          id: node.id,
          label: node.label,
          type: node.type,
          iocType: node.iocType,
          severity: node.severity,
          threatScore: node.threatScore,
          originalData: node.data
        }
      })),
      ...graphData.edges.map(edge => ({
        data: {
          id: `${edge.source}-${edge.target}`,
          source: edge.source,
          target: edge.target,
          label: edge.label,
          type: edge.type
        }
      }))
    ];

    // Initialize Cytoscape
    cyRef.current = cytoscape({
      container: containerRef.current,
      elements: elements,
      style: [
        {
          selector: 'node',
          style: {
            'background-color': '#666',
            'label': 'data(label)',
            'font-size': '12px',
            'text-valign': 'center',
            'text-halign': 'center',
            'color': '#fff',
            'text-outline-color': '#000',
            'text-outline-width': '2px',
            'width': '40px',
            'height': '40px',
            'border-width': '2px',
            'border-color': '#333'
          }
        },
        {
          selector: 'node[type="ioc"]',
          style: {
            'background-color': '#3b82f6',
            'border-color': '#1d4ed8'
          }
        },
        {
          selector: 'node[type="ioc"][iocType="ip"]',
          style: {
            'background-color': '#ef4444',
            'border-color': '#b91c1c',
            'shape': 'ellipse'
          }
        },
        {
          selector: 'node[type="ioc"][iocType="domain"]',
          style: {
            'background-color': '#f59e0b',
            'border-color': '#d97706',
            'shape': 'ellipse'
          }
        },
        {
          selector: 'node[type="ioc"][iocType="url"]',
          style: {
            'background-color': '#8b5cf6',
            'border-color': '#6d28d9',
            'shape': 'ellipse'
          }
        },
        {
          selector: 'node[type="ioc"][iocType="hash"]',
          style: {
            'background-color': '#10b981',
            'border-color': '#059669',
            'shape': 'ellipse'
          }
        },
        {
          selector: 'node[type="ioc"][severity="Critical"]',
          style: {
            'border-width': '4px',
            'border-color': '#dc2626'
          }
        },
        {
          selector: 'node[type="ioc"][severity="High"]',
          style: {
            'border-width': '3px',
            'border-color': '#ea580c'
          }
        },
        {
          selector: 'node[type="threat_actor"]',
          style: {
            'background-color': '#dc2626',
            'border-color': '#991b1b',
            'shape': 'diamond',
            'width': '50px',
            'height': '50px'
          }
        },
        {
          selector: 'node[type="campaign"]',
          style: {
            'background-color': '#7c3aed',
            'border-color': '#5b21b6',
            'shape': 'hexagon',
            'width': '45px',
            'height': '45px'
          }
        },
        {
          selector: 'node:selected',
          style: {
            'border-width': '4px',
            'border-color': '#fbbf24',
            'background-color': '#fcd34d'
          }
        },
        {
          selector: 'edge',
          style: {
            'width': '2px',
            'line-color': '#999',
            'target-arrow-color': '#999',
            'target-arrow-shape': 'triangle',
            'curve-style': 'bezier',
            'label': 'data(label)',
            'font-size': '10px',
            'color': '#666',
            'text-rotation': 'autorotate',
            'text-margin-y': '-10px'
          }
        },
        {
          selector: 'edge[type="attribution"]',
          style: {
            'line-color': '#ef4444',
            'target-arrow-color': '#ef4444',
            'width': '3px'
          }
        },
        {
          selector: 'edge[type="mitre"]',
          style: {
            'line-color': '#8b5cf6',
            'target-arrow-color': '#8b5cf6',
            'width': '2px',
            'line-style': 'dashed'
          }
        },
        {
          selector: 'edge[type="tag"]',
          style: {
            'line-color': '#10b981',
            'target-arrow-color': '#10b981',
            'width': '2px'
          }
        },
        {
          selector: 'edge[type="campaign"]',
          style: {
            'line-color': '#7c3aed',
            'target-arrow-color': '#7c3aed',
            'width': '2px'
          }
        }
      ],
      layout: {
        name: 'cose',
        animate: true,
        animationDuration: 1000,
        idealEdgeLength: 100,
        nodeOverlap: 20,
        refresh: 20,
        fit: true,
        padding: 50,
        randomize: false,
        componentSpacing: 100,
        nodeRepulsion: 400000,
        edgeElasticity: 100,
        nestingFactor: 5,
        gravity: 80,
        numIter: 1000,
        initialTemp: 200,
        coolingFactor: 0.95,
        minTemp: 1.0
      },
      wheelSensitivity: 0.3,
      minZoom: 0.3,
      maxZoom: 3
    });

    // Click-to-pivot functionality
    cyRef.current.on('tap', 'node', (evt) => {
      const node = evt.target;
      const nodeData = node.data();
      
      // Center on the clicked node
      cyRef.current.animate({
        center: { eles: node },
        zoom: 1.5
      }, {
        duration: 500
      });

      // Select the node
      cyRef.current.$('node').unselect();
      node.select();

      // Update selected node state
      setSelectedNode(nodeData);
    });

    // Click on background to deselect
    cyRef.current.on('tap', (evt) => {
      if (evt.target === cyRef.current) {
        cyRef.current.$('node').unselect();
        setSelectedNode(null);
      }
    });

    // Cleanup on unmount
    return () => {
      if (cyRef.current) {
        cyRef.current.destroy();
      }
    };
  }, [graphData]);

  // Handle pivot to new IOC
  const handlePivot = (nodeId) => {
    if (nodeId.startsWith('campaign-')) return; // Can't pivot to campaign
    navigate(`/graph/${nodeId}`);
    setSelectedNode(null);
  };

  // Handle navigate to IOC details
  const handleViewDetails = () => {
    if (selectedNode && selectedNode.type === 'ioc') {
      navigate(`/ioc/${selectedNode.id}`);
    }
  };

  // Show search UI when no ID is present
  if (!id) {
    return (
      <div className="relationship-graph-page">
        <div className="page-header">
          <div>
            <h1 className="page-title">RELATIONSHIP GRAPH</h1>
            <p className="page-subtitle">Visualizing IOC connections and threat actor relationships</p>
          </div>
        </div>

        <div className="graph-search-container">
          <div className="graph-search-box">
            <h2>Select an IOC to View Relationships</h2>
            <p className="search-subtitle">Enter an IOC indicator (IP, domain, URL, or hash) to load its relationship graph</p>
            
            <form onSubmit={handleSearch} className="search-form">
              <input
                type="text"
                value={searchValue}
                onChange={(e) => setSearchValue(e.target.value)}
                placeholder="e.g., 192.168.1.1, example.com, https://evil.com, or file hash"
                className="search-input"
                disabled={searching}
              />
              <button type="submit" className="btn btn-primary" disabled={searching || !searchValue.trim()}>
                {searching ? 'Searching...' : 'Load Graph'}
              </button>
            </form>

            {searchError && (
              <div className="search-error">
                {searchError}
              </div>
            )}

            <div className="search-hint">
              <strong>Tip:</strong> You can also navigate to the graph from any IOC details page by clicking "View Relationship Graph"
            </div>
          </div>
        </div>
      </div>
    );
  }

  if (loading) {
    return (
      <div className="relationship-graph-page">
        <div className="page-header">
          <h1 className="page-title">RELATIONSHIP GRAPH</h1>
          <p className="page-subtitle">Visualizing IOC connections and threat actor relationships</p>
        </div>
        <Loader message="Loading graph data..." />
      </div>
    );
  }

  if (error) {
    return (
      <div className="relationship-graph-page">
        <div className="page-header">
          <h1 className="page-title">RELATIONSHIP GRAPH</h1>
          <p className="page-subtitle">Visualizing IOC connections and threat actor relationships</p>
        </div>
        <div className="error-message">
          <p>{error}</p>
          <button className="btn" onClick={() => navigate('/search')}>
            Back to Search
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="relationship-graph-page">
      {/* Page Header */}
      <div className="page-header">
        <div>
          <h1 className="page-title">RELATIONSHIP GRAPH</h1>
          <p className="page-subtitle">Visualizing IOC connections and threat actor relationships</p>
        </div>
        <div className="graph-controls">
          <button className="btn" onClick={() => navigate('/search')}>
            Back to Search
          </button>
        </div>
      </div>

      {/* Legend */}
      <div className="graph-legend">
        <div className="legend-title">NODE TYPES</div>
        <div className="legend-items">
          <div className="legend-item">
            <span className="legend-color" style={{ backgroundColor: '#ef4444' }}></span>
            <span>IP Address</span>
          </div>
          <div className="legend-item">
            <span className="legend-color" style={{ backgroundColor: '#f59e0b' }}></span>
            <span>Domain</span>
          </div>
          <div className="legend-item">
            <span className="legend-color" style={{ backgroundColor: '#8b5cf6' }}></span>
            <span>URL</span>
          </div>
          <div className="legend-item">
            <span className="legend-color" style={{ backgroundColor: '#10b981' }}></span>
            <span>File Hash</span>
          </div>
          <div className="legend-item">
            <span className="legend-color diamond" style={{ backgroundColor: '#dc2626' }}></span>
            <span>Threat Actor</span>
          </div>
          <div className="legend-item">
            <span className="legend-color hexagon" style={{ backgroundColor: '#7c3aed' }}></span>
            <span>Campaign</span>
          </div>
        </div>
        <div className="legend-title" style={{ marginTop: '10px' }}>EDGE TYPES</div>
        <div className="legend-items">
          <div className="legend-item">
            <span className="legend-line" style={{ borderColor: '#ef4444' }}></span>
            <span>Attribution</span>
          </div>
          <div className="legend-item">
            <span className="legend-line dashed" style={{ borderColor: '#8b5cf6' }}></span>
            <span>MITRE Technique</span>
          </div>
          <div className="legend-item">
            <span className="legend-line" style={{ borderColor: '#10b981' }}></span>
            <span>Shared Tag</span>
          </div>
          <div className="legend-item">
            <span className="legend-line" style={{ borderColor: '#7c3aed' }}></span>
            <span>Campaign</span>
          </div>
        </div>
      </div>

      {/* Graph Container */}
      <div className="graph-container">
        <div ref={containerRef} className="cytoscape-container" />
        
        {/* Selected Node Panel */}
        {selectedNode && (
          <div className="node-panel">
            <div className="node-panel-header">
              <h3>Selected Node</h3>
              <button className="close-btn" onClick={() => setSelectedNode(null)}>
                ✕
              </button>
            </div>
            <div className="node-panel-content">
              <div className="node-info-row">
                <span className="node-info-label">Type:</span>
                <span className="node-info-value">{selectedNode.type}</span>
              </div>
              <div className="node-info-row">
                <span className="node-info-label">Label:</span>
                <span className="node-info-value">{selectedNode.label}</span>
              </div>
              {selectedNode.iocType && (
                <div className="node-info-row">
                  <span className="node-info-label">IOC Type:</span>
                  <span className="node-info-value">{selectedNode.iocType}</span>
                </div>
              )}
              {selectedNode.severity && (
                <div className="node-info-row">
                  <span className="node-info-label">Severity:</span>
                  <span className={`node-info-value severity-${selectedNode.severity.toLowerCase()}`}>
                    {selectedNode.severity}
                  </span>
                </div>
              )}
              {selectedNode.threatScore !== undefined && (
                <div className="node-info-row">
                  <span className="node-info-label">Threat Score:</span>
                  <span className="node-info-value">{selectedNode.threatScore}/100</span>
                </div>
              )}
            </div>
            <div className="node-panel-actions">
              {selectedNode.type === 'ioc' && (
                <>
                  <button className="btn btn-primary" onClick={handleViewDetails}>
                    View Details
                  </button>
                  <button className="btn btn-secondary" onClick={() => handlePivot(selectedNode.id)}>
                    Pivot to This Node
                  </button>
                </>
              )}
            </div>
          </div>
        )}
      </div>

      {/* Instructions */}
      <div className="graph-instructions">
        <p><strong>Instructions:</strong> Click on any node to center the graph on it. Double-click to pivot the graph to that IOC. Use scroll to zoom, drag to pan.</p>
      </div>
    </div>
  );
};

export default RelationshipGraph;
