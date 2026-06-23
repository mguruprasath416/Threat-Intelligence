// ============================================================
// pages/RelationshipGraph.jsx — IOC RELATIONSHIP GRAPH PAGE
// ============================================================
// Uses Cytoscape.js + cytoscape-cola (layout) + cytoscape-popper
// for interactive multi-hop BFS threat intelligence exploration.
// ============================================================

import React, { useEffect, useRef, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import cytoscape from 'cytoscape';
import cola from 'cytoscape-cola';
import popper from 'cytoscape-popper';
import api from '../api/axios';
import Loader from '../components/Loader/Loader';
import './RelationshipGraph.css';

// Safely register Cytoscape extensions
try {
  cytoscape.use(cola);
  cytoscape.use(popper);
} catch (e) {
  console.warn('Cytoscape extensions already registered or failed to register:', e);
}

const RelationshipGraph = () => {
  const { id } = useParams(); // /graph/:id
  const navigate = useNavigate();

  // Refs
  const containerRef = useRef(null);
  const cyRef = useRef(null);
  const isPivotRef = useRef(false);
  const freshLoadRef = useRef(true);

  // States
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [data, setData] = useState(null); // { nodes: [], edges: [] }
  const [searchQuery, setSearchQuery] = useState('');
  const [stats, setStats] = useState({ nodes: 0, edges: 0 });

  // Filtering States
  const [nodeFilters, setNodeFilters] = useState({
    ip: true,
    domain: true,
    url: true,
    hash: true,
    email: true
  });

  const [edgeFilters, setEdgeFilters] = useState({
    sharedTag: true,
    mitreTechnique: true,
    threatActor: true,
    campaign: true,
    sharedSource: true
  });

  // Context Menu State
  const [contextMenu, setContextMenu] = useState({
    visible: false,
    x: 0,
    y: 0,
    nodeId: null,
    nodeType: null,
    nodeValue: null,
    nodeData: null
  });

  // Helper to merge new BFS data into state (Pivot)
  const mergeGraphData = (newNodes, newEdges) => {
    setData(prev => {
      if (!prev) return { nodes: newNodes, edges: newEdges };

      // Deduplicate nodes
      const nodeMap = new Map();
      prev.nodes.forEach(n => nodeMap.set(n.id, n));
      newNodes.forEach(n => nodeMap.set(n.id, n));

      // Deduplicate edges
      const edgeMap = new Map();
      prev.edges.forEach(e => {
        const key = `${e.source}-${e.target}-${e.relationship}`;
        edgeMap.set(key, e);
      });
      newEdges.forEach(e => {
        const key = `${e.source}-${e.target}-${e.relationship}`;
        edgeMap.set(key, e);
      });

      return {
        nodes: Array.from(nodeMap.values()),
        edges: Array.from(edgeMap.values())
      };
    });
  };

  // Fetch Graph Data
  const fetchGraph = async (iocId, isPivot = false) => {
    if (!iocId) return;
    try {
      setLoading(true);
      setError(null);
      
      const response = await api.get(`/graph/${iocId}`);
      const graphData = response.data;

      if (isPivot) {
        freshLoadRef.current = false;
        mergeGraphData(graphData.nodes, graphData.edges);
      } else {
        freshLoadRef.current = true;
        setData({
          nodes: graphData.nodes,
          edges: graphData.edges
        });
      }
    } catch (err) {
      console.error('Fetch graph data failed:', err);
      setError(err.userMessage || 'Failed to retrieve relationship graph data');
    } finally {
      setLoading(false);
    }
  };

  // Load graph when URL parameter 'id' changes
  useEffect(() => {
    if (id) {
      if (isPivotRef.current) {
        fetchGraph(id, true);
        isPivotRef.current = false;
      } else {
        fetchGraph(id, false);
      }
    } else {
      setData(null);
      if (cyRef.current) {
        cyRef.current.destroy();
        cyRef.current = null;
      }
    }
  }, [id]);

  // Apply filters in Cytoscape
  const applyFilters = () => {
    if (!cyRef.current) return;
    const cy = cyRef.current;

    cy.batch(() => {
      // 1. Show all nodes/edges initially
      cy.elements().removeClass('filtered-out');

      // 2. Filter nodes
      cy.nodes().forEach(node => {
        const type = node.data('type');
        let isVisible = true;

        if (type === 'ip') isVisible = nodeFilters.ip;
        else if (type === 'domain') isVisible = nodeFilters.domain;
        else if (type === 'url') isVisible = nodeFilters.url;
        else if (type === 'hash') isVisible = nodeFilters.hash;
        else if (type === 'email') isVisible = nodeFilters.email;
        // threat-actor and campaign are always visible unless we decide to hide orphan nodes
        
        if (!isVisible) {
          node.addClass('filtered-out');
        }
      });

      // 3. Filter edges
      cy.edges().forEach(edge => {
        const relationship = edge.data('relationship');
        let isVisible = true;

        if (relationship === 'shared-tag') isVisible = edgeFilters.sharedTag;
        else if (relationship === 'mitre-technique') isVisible = edgeFilters.mitreTechnique;
        else if (relationship === 'threat-actor') isVisible = edgeFilters.threatActor;
        else if (relationship === 'campaign') isVisible = edgeFilters.campaign;
        else if (relationship === 'shared-source') isVisible = edgeFilters.sharedSource;

        if (!isVisible) {
          edge.addClass('filtered-out');
        }
      });
    });

    // Update visible count stats
    const visibleNodes = cy.nodes().filter(n => !n.hasClass('filtered-out')).size();
    const visibleEdges = cy.edges().filter(e => !e.hasClass('filtered-out')).size();
    setStats({ nodes: visibleNodes, edges: visibleEdges });
  };

  // Re-run filter application when filter state changes
  useEffect(() => {
    applyFilters();
  }, [nodeFilters, edgeFilters, data]);

  // Close context menu on click anywhere
  useEffect(() => {
    const handleWindowClick = () => {
      setContextMenu(prev => prev.visible ? { ...prev, visible: false } : prev);
    };
    window.addEventListener('click', handleWindowClick);
    return () => window.removeEventListener('click', handleWindowClick);
  }, []);

  // Initialize and Update Cytoscape.js Instance
  useEffect(() => {
    if (!containerRef.current || !data) return;

    let cy = cyRef.current;

    if (!cy) {
      cy = cytoscape({
        container: containerRef.current,
        elements: [],
        style: [
          {
            selector: 'node',
            style: {
              'content': 'data(label)',
              'font-family': 'Share Tech Mono, monospace',
              'font-size': '10px',
              'color': '#e8f4f8',
              'text-valign': 'bottom',
              'text-halign': 'center',
              'text-margin-y': '5px',
              'text-wrap': 'wrap',
              'text-max-width': '80px',
              'background-color': '#080f1a',
              'border-width': '2px',
              'border-color': '#00d4ff',
              'width': '35px',
              'height': '35px',
              'text-outline-width': '2px',
              'text-outline-color': '#0F1923',
              'transition-property': 'background-color, border-color, width, height',
              'transition-duration': '0.3s'
            }
          },
          {
            selector: 'node[type="ip"]',
            style: {
              'background-color': '#FF3B5C',
              'border-color': '#FF3B5C'
            }
          },
          {
            selector: 'node[type="domain"]',
            style: {
              'background-color': '#F5A623',
              'border-color': '#F5A623'
            }
          },
          {
            selector: 'node[type="url"]',
            style: {
              'background-color': '#A855F7',
              'border-color': '#A855F7'
            }
          },
          {
            selector: 'node[type="hash"]',
            style: {
              'background-color': '#00D4B4',
              'border-color': '#00D4B4'
            }
          },
          {
            selector: 'node[type="email"]',
            style: {
              'background-color': '#3B9EFF',
              'border-color': '#3B9EFF'
            }
          },
          {
            selector: 'node[type="threat-actor"]',
            style: {
              'shape': 'diamond',
              'background-color': '#FF3B5C',
              'border-color': '#FF3B5C',
              'width': '40px',
              'height': '40px'
            }
          },
          {
            selector: 'node[type="campaign"]',
            style: {
              'shape': 'hexagon',
              'background-color': '#A855F7',
              'border-color': '#A855F7',
              'width': '40px',
              'height': '40px'
            }
          },
          // Severity Border Glow
          {
            selector: 'node[severity="Critical"]',
            style: {
              'border-width': '5px',
              'border-color': '#ff3355'
            }
          },
          {
            selector: 'node[severity="High"]',
            style: {
              'border-width': '4px',
              'border-color': '#ff8800'
            }
          },
          {
            selector: 'node[severity="Medium"]',
            style: {
              'border-width': '3px',
              'border-color': '#ffcc00'
            }
          },
          {
            selector: 'node[severity="Low"]',
            style: {
              'border-width': '2px',
              'border-color': '#00ff88'
            }
          },
          // Edges
          {
            selector: 'edge',
            style: {
              'width': 2,
              'line-color': '#3d5a6e',
              'curve-style': 'bezier',
              'target-arrow-shape': 'triangle',
              'target-arrow-color': '#3d5a6e',
              'label': 'data(label)',
              'font-family': 'Share Tech Mono, monospace',
              'font-size': '8px',
              'color': '#7a9bb5',
              'text-background-opacity': 0.8,
              'text-background-color': '#0F1923',
              'text-background-padding': '2px',
              'text-rotation': 'autorotate'
            }
          },
          {
            selector: 'edge[relationship="threat-actor"]',
            style: {
              'line-color': '#FF3B5C',
              'target-arrow-color': '#FF3B5C',
              'line-style': 'dashed'
            }
          },
          {
            selector: 'edge[relationship="mitre-technique"]',
            style: {
              'line-color': '#F5A623',
              'target-arrow-color': '#F5A623',
              'line-style': 'solid'
            }
          },
          {
            selector: 'edge[relationship="shared-tag"]',
            style: {
              'line-color': '#00D4B4',
              'target-arrow-color': '#00D4B4',
              'line-style': 'dotted'
            }
          },
          {
            selector: 'edge[relationship="campaign"]',
            style: {
              'line-color': '#A855F7',
              'target-arrow-color': '#A855F7',
              'line-style': 'dashed'
            }
          },
          {
            selector: 'edge[relationship="shared-source"]',
            style: {
              'line-color': '#3B9EFF',
              'target-arrow-color': '#3B9EFF',
              'line-style': 'solid'
            }
          },
          {
            selector: '.filtered-out',
            style: {
              'display': 'none'
            }
          }
        ]
      });

      cyRef.current = cy;

      // Click to pivot
      cy.on('tap', 'node', (evt) => {
        const node = evt.target;
        const type = node.data('type');
        if (type !== 'threat-actor' && type !== 'campaign') {
          const nodeId = node.id();
          isPivotRef.current = true;
          navigate(`/graph/${nodeId}`);
        }
      });

      // Right-click context menu (cxttap)
      cy.on('cxttap', 'node', (evt) => {
        const node = evt.target;
        const originalEvent = evt.originalEvent;
        originalEvent.preventDefault();

        setContextMenu({
          visible: true,
          x: originalEvent.clientX,
          y: originalEvent.clientY,
          nodeId: node.id(),
          nodeType: node.data('type'),
          nodeValue: node.data('value'),
          nodeData: node.data('data')
        });
      });

      // Hover Tooltips (Popper.js)
      cy.on('mouseover', 'node', (evt) => {
        const node = evt.target;
        const type = node.data('type');
        const value = node.data('value');
        const severity = node.data('severity') || 'N/A';
        const dataObj = node.data('data') || {};

        let tooltipContent = '';
        if (type === 'threat-actor') {
          tooltipContent = `
            <strong>Type:</strong> Threat Actor<br/>
            <strong>Name:</strong> ${value}<br/>
            <strong>Country:</strong> ${dataObj.country || 'Unknown'}<br/>
            <strong>Motivation:</strong> ${dataObj.motivation || 'Unknown'}<br/>
            <strong>Confidence:</strong> ${dataObj.confidence || 'N/A'}/100
          `;
        } else if (type === 'campaign') {
          tooltipContent = `
            <strong>Type:</strong> Campaign<br/>
            <strong>Name:</strong> ${value}<br/>
            <strong>Status:</strong> ${dataObj.status || 'Unknown'}<br/>
            <strong>Targets:</strong> ${dataObj.targets?.join(', ') || 'N/A'}
          `;
        } else {
          tooltipContent = `
            <strong>Type:</strong> ${type.toUpperCase()}<br/>
            <strong>Value:</strong> ${value}<br/>
            <strong>Severity:</strong> ${severity}<br/>
            <strong>Source:</strong> ${dataObj.source || 'N/A'}<br/>
            <strong>Date Added:</strong> ${dataObj.createdAt ? new Date(dataObj.createdAt).toLocaleDateString() : 'N/A'}
          `;
        }

        const popperInstance = node.popper({
          content: () => {
            const div = document.createElement('div');
            div.className = 'cy-tooltip';
            div.innerHTML = tooltipContent;
            document.body.appendChild(div);
            return div;
          },
          popper: {
            placement: 'top',
            modifiers: [
              {
                name: 'preventOverflow',
                options: {
                  boundary: 'viewport',
                },
              },
            ],
          }
        });

        node.scratch('popper', popperInstance);
      });

      cy.on('mouseout', 'node', (evt) => {
        const node = evt.target;
        const popperInstance = node.scratch('popper');
        if (popperInstance) {
          popperInstance.state.elements.popper.remove();
          popperInstance.destroy();
          node.removeScratch('popper');
        }
      });
    }

    // Sync elements
    const currentNodes = cy.nodes().map(n => n.id());
    const currentEdgeKeys = cy.edges().map(e => `${e.data('source')}-${e.data('target')}-${e.data('relationship')}`);

    const elementsToAdd = [];

    data.nodes.forEach(n => {
      if (!currentNodes.includes(n.id)) {
        elementsToAdd.push({
          group: 'nodes',
          data: {
            id: n.id,
            label: n.label,
            type: n.type,
            severity: n.severity,
            value: n.value,
            data: n.data
          }
        });
      }
    });

    data.edges.forEach(e => {
      const key = `${e.source}-${e.target}-${e.relationship}`;
      if (!currentEdgeKeys.includes(key)) {
        elementsToAdd.push({
          group: 'edges',
          data: {
            source: e.source,
            target: e.target,
            relationship: e.relationship,
            label: e.label
          }
        });
      }
    });

    if (elementsToAdd.length > 0) {
      cy.add(elementsToAdd);
    }

    // Run layout.
    // If it's a pivot, don't randomize or fit so we keep current node position stability!
    const layout = cy.layout({
      name: 'cola',
      animate: true,
      fit: freshLoadRef.current,
      randomize: freshLoadRef.current,
      maxSimulationTime: 2000,
      nodeSpacing: 50,
      edgeLength: 100
    });
    layout.run();

    // Reapply filters to new elements
    applyFilters();

    return () => {
      if (cyRef.current) {
        cyRef.current.nodes().forEach(n => {
          const popperInstance = n.scratch('popper');
          if (popperInstance) {
            popperInstance.state.elements.popper.remove();
            popperInstance.destroy();
          }
        });
      }
    };
  }, [data]);

  // Clean up Cytoscape on unmount
  useEffect(() => {
    return () => {
      if (cyRef.current) {
        cyRef.current.destroy();
        cyRef.current = null;
      }
    };
  }, []);

  // Actions
  const handleSearchSubmit = async (e) => {
    e.preventDefault();
    if (!searchQuery.trim()) return;

    try {
      setLoading(true);
      setError(null);

      // Query database for matched IOC
      const response = await api.get(`/ioc?search=${encodeURIComponent(searchQuery.trim())}`);
      const iocs = response.data?.data?.iocs || [];

      if (iocs.length > 0) {
        const matched = iocs.find(i => i.indicator.toLowerCase() === searchQuery.trim().toLowerCase()) || iocs[0];
        setSearchQuery('');
        navigate(`/graph/${matched.id || matched._id}`);
      } else {
        setError('No matching IOC found in database');
      }
    } catch (err) {
      setError(err.userMessage || 'Failed to search IOC');
    } finally {
      setLoading(false);
    }
  };

  const handleResetView = () => {
    if (!cyRef.current) return;
    cyRef.current.fit();
  };

  const handleExportPNG = () => {
    if (!cyRef.current) return;
    const cy = cyRef.current;
    const pngData = cy.png({
      bg: '#0F1923',
      full: true
    });

    const link = document.createElement('a');
    link.href = pngData;
    link.download = `ioc-relationship-graph-${id || 'export'}.png`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const handlePivot = (nodeId) => {
    isPivotRef.current = true;
    navigate(`/graph/${nodeId}`);
  };

  const handleCopyValue = (value) => {
    navigator.clipboard.writeText(value);
  };

  // Rendering Helper States
  const handleNodeFilterChange = (type) => {
    setNodeFilters(prev => ({ ...prev, [type]: !prev[type] }));
  };

  const handleEdgeFilterChange = (relationship) => {
    setEdgeFilters(prev => ({ ...prev, [relationship]: !prev[relationship] }));
  };

  return (
    <div className="relationship-graph-container">
      {/* ── Left Control Panel (280px) ── */}
      <aside className="graph-left-panel">
        <h2 className="graph-title">Threat Graph</h2>

        {/* Search */}
        <form className="graph-search-form" onSubmit={handleSearchSubmit}>
          <div className="graph-search-input-wrapper">
            <input
              type="text"
              className="input"
              placeholder="Search IOC value..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
            <button type="submit" className="btn btn-primary" style={{ padding: '8px 12px' }}>
              🔎
            </button>
          </div>
        </form>

        {/* Live Stats */}
        <div className="graph-stats">
          <div className="graph-stats-title">Live Statistics</div>
          <div className="graph-stats-grid">
            <div className="graph-stat-item">
              <span className="graph-stat-label">Nodes</span>
              <span className="graph-stat-value">{stats.nodes}</span>
            </div>
            <div className="graph-stat-item">
              <span className="graph-stat-label">Edges</span>
              <span className="graph-stat-value">{stats.edges}</span>
            </div>
          </div>
        </div>

        {/* Node Filters */}
        <div className="graph-filter-section">
          <div className="graph-filter-title">Filter Node Types</div>
          <div className="graph-filter-list">
            <label className="graph-filter-item">
              <input
                type="checkbox"
                className="graph-filter-checkbox"
                checked={nodeFilters.ip}
                onChange={() => handleNodeFilterChange('ip')}
              />
              IP Address (#FF3B5C)
            </label>
            <label className="graph-filter-item">
              <input
                type="checkbox"
                className="graph-filter-checkbox"
                checked={nodeFilters.domain}
                onChange={() => handleNodeFilterChange('domain')}
              />
              Domain (#F5A623)
            </label>
            <label className="graph-filter-item">
              <input
                type="checkbox"
                className="graph-filter-checkbox"
                checked={nodeFilters.url}
                onChange={() => handleNodeFilterChange('url')}
              />
              URL (#A855F7)
            </label>
            <label className="graph-filter-item">
              <input
                type="checkbox"
                className="graph-filter-checkbox"
                checked={nodeFilters.hash}
                onChange={() => handleNodeFilterChange('hash')}
              />
              Hash (#00D4B4)
            </label>
            <label className="graph-filter-item">
              <input
                type="checkbox"
                className="graph-filter-checkbox"
                checked={nodeFilters.email}
                onChange={() => handleNodeFilterChange('email')}
              />
              Email (#3B9EFF)
            </label>
          </div>
        </div>

        {/* Edge/Relationship Filters */}
        <div className="graph-filter-section">
          <div className="graph-filter-title">Filter Relationships</div>
          <div className="graph-filter-list">
            <label className="graph-filter-item">
              <input
                type="checkbox"
                className="graph-filter-checkbox"
                checked={edgeFilters.threatActor}
                onChange={() => handleEdgeFilterChange('threatActor')}
              />
              Threat Actor (Dashed)
            </label>
            <label className="graph-filter-item">
              <input
                type="checkbox"
                className="graph-filter-checkbox"
                checked={edgeFilters.campaign}
                onChange={() => handleEdgeFilterChange('campaign')}
              />
              Campaign (Dashed)
            </label>
            <label className="graph-filter-item">
              <input
                type="checkbox"
                className="graph-filter-checkbox"
                checked={edgeFilters.mitreTechnique}
                onChange={() => handleEdgeFilterChange('mitreTechnique')}
              />
              MITRE Technique (Solid)
            </label>
            <label className="graph-filter-item">
              <input
                type="checkbox"
                className="graph-filter-checkbox"
                checked={edgeFilters.sharedTag}
                onChange={() => handleEdgeFilterChange('sharedTag')}
              />
              Shared Tag (Dotted)
            </label>
            <label className="graph-filter-item">
              <input
                type="checkbox"
                className="graph-filter-checkbox"
                checked={edgeFilters.sharedSource}
                onChange={() => handleEdgeFilterChange('sharedSource')}
              />
              Shared Source (Solid)
            </label>
          </div>
        </div>

        {/* Controls */}
        <div className="graph-controls">
          <button className="btn" onClick={handleResetView}>
            Reset View
          </button>
          <button className="btn" onClick={handleExportPNG}>
            Export PNG
          </button>
        </div>
      </aside>

      {/* ── Graph Viewport Area ── */}
      <main className="graph-viewport-container">
        {loading && !data && (
          <div style={{ height: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <Loader message="FETCHING THREAT RELATIONSHIPS..." />
          </div>
        )}

        {error && (
          <div className="graph-error-state">
            <div className="graph-error-icon">⚠️</div>
            <div className="graph-error-msg">
              <h3>Error Occurred</h3>
              <p>{error}</p>
            </div>
          </div>
        )}

        {!id && !loading && !error && (
          <div className="graph-empty-state">
            <div className="graph-empty-icon">⬡</div>
            <div className="graph-empty-msg">
              <h3>No Target Selected</h3>
              <p>Search an indicator in the left panel or click "View in Graph" from any IOC details page to map threat intelligence relationships.</p>
            </div>
          </div>
        )}

        {id && data && <div className="cy-viewport" ref={containerRef} />}

        {/* Legend */}
        {data && (
          <div className="graph-legend-panel">
            <div className="graph-legend-title">Legend</div>
            <div className="graph-legend-item">
              <span className="legend-color-dot" style={{ backgroundColor: '#FF3B5C' }} />
              <span>IP Address</span>
            </div>
            <div className="graph-legend-item">
              <span className="legend-color-dot" style={{ backgroundColor: '#F5A623' }} />
              <span>Domain</span>
            </div>
            <div className="graph-legend-item">
              <span className="legend-color-dot" style={{ backgroundColor: '#A855F7' }} />
              <span>URL</span>
            </div>
            <div className="graph-legend-item">
              <span className="legend-color-dot" style={{ backgroundColor: '#00D4B4' }} />
              <span>Hash</span>
            </div>
            <div className="graph-legend-item">
              <span className="legend-color-dot" style={{ backgroundColor: '#3B9EFF' }} />
              <span>Email</span>
            </div>
            <div className="graph-legend-item">
              <span className="legend-shape diamond" style={{ borderColor: '#FF3B5C', backgroundColor: '#FF3B5C' }} />
              <span>Threat Actor</span>
            </div>
            <div className="graph-legend-item">
              <span className="legend-shape hexagon" style={{ borderColor: '#A855F7', backgroundColor: '#A855F7' }} />
              <span>Campaign</span>
            </div>
          </div>
        )}
      </main>

      {/* ── Custom Node Context Menu ── */}
      {contextMenu.visible && (
        <div
          className="graph-context-menu"
          style={{ top: contextMenu.y, left: contextMenu.x }}
        >
          {contextMenu.nodeType !== 'threat-actor' && contextMenu.nodeType !== 'campaign' ? (
            <>
              <div
                className="graph-context-menu-item"
                onClick={() => navigate(`/ioc/${contextMenu.nodeId}`)}
              >
                View IOC Details
              </div>
              <div
                className="graph-context-menu-item"
                onClick={() => handlePivot(contextMenu.nodeId)}
              >
                Pivot from here
              </div>
            </>
          ) : contextMenu.nodeType === 'threat-actor' && contextMenu.nodeData?._id ? (
            <div
              className="graph-context-menu-item"
              onClick={() => navigate(`/threat-actors/${contextMenu.nodeData._id}`)}
            >
              View Actor Details
            </div>
          ) : null}
          <div className="graph-context-menu-separator" />
          <div
            className="graph-context-menu-item"
            onClick={() => handleCopyValue(contextMenu.nodeValue)}
          >
            Copy Value
          </div>
        </div>
      )}
    </div>
  );
};

export default RelationshipGraph;
