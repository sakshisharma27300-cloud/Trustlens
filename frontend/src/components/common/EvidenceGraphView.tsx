import React, { useState } from 'react';
import { IntelligenceGraph, GraphNode } from '../../types';
import { Network, ZoomIn, ZoomOut, Info, ShieldAlert, Globe, Server, Key, Mail, Cpu } from 'lucide-react';

interface EvidenceGraphProps {
  graph: IntelligenceGraph;
}

export const EvidenceGraphView: React.FC<EvidenceGraphProps> = ({ graph }) => {
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [filterType, setFilterType] = useState<string>('all');

  const nodes = graph?.nodes || [];
  const edges = graph?.edges || [];

  const getNodeColor = (node: GraphNode) => {
    switch (node.risk_level) {
      case 'malicious':
        return '#ef4444'; // Red
      case 'suspicious':
        return '#f59e0b'; // Amber
      case 'safe':
        return '#10b981'; // Green
      default:
        return '#3b82f6'; // Cobalt Blue
    }
  };

  const getNodeIcon = (type: string) => {
    switch (type) {
      case 'domain':
      case 'website':
        return <Globe className="w-4 h-4 text-cobalt-400" />;
      case 'ip':
        return <Server className="w-4 h-4 text-cyan-400" />;
      case 'certificate':
        return <Key className="w-4 h-4 text-emerald-400" />;
      case 'email':
      case 'email_domain':
        return <Mail className="w-4 h-4 text-indigo-400" />;
      case 'indicator':
        return <ShieldAlert className="w-4 h-4 text-rose-400" />;
      default:
        return <Cpu className="w-4 h-4 text-slate-400" />;
    }
  };

  // Filter nodes
  const filteredNodes = filterType === 'all' 
    ? nodes 
    : nodes.filter(n => n.node_type === filterType || (filterType === 'threats' && (n.risk_level === 'malicious' || n.risk_level === 'suspicious')));

  // Calculate layout coordinates in a circular or force-directed representation
  const width = 760;
  const height = 440;
  const centerX = width / 2;
  const centerY = height / 2;

  const nodePositions: Record<string, { x: number; y: number }> = {};
  filteredNodes.forEach((node, idx) => {
    if (node.id === 'root_target') {
      nodePositions[node.id] = { x: centerX, y: centerY };
    } else {
      const angle = (idx / Math.max(filteredNodes.length - 1, 1)) * 2 * Math.PI;
      const radius = 140 + (idx % 2 === 0 ? 30 : -20);
      nodePositions[node.id] = {
        x: centerX + radius * Math.cos(angle),
        y: centerY + radius * Math.sin(angle),
      };
    }
  });

  return (
    <div className="bg-slate-900/60 border border-slate-800 rounded-xl overflow-hidden">
      {/* Graph Toolbar */}
      <div className="px-5 py-3 border-b border-slate-800 flex flex-wrap items-center justify-between gap-3 bg-slate-950/40">
        <div className="flex items-center space-x-2">
          <Network className="w-4 h-4 text-cobalt-400" />
          <span className="text-xs font-semibold uppercase tracking-wider text-slate-200">
            TrustLens Correlation Intelligence Graph
          </span>
          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300">
            {nodes.length} Nodes · {edges.length} Edges
          </span>
        </div>

        {/* Filters */}
        <div className="flex items-center space-x-1 text-xs">
          {['all', 'domain', 'ip', 'indicator', 'threats'].map(f => (
            <button
              key={f}
              onClick={() => setFilterType(f)}
              className={`px-2.5 py-1 rounded text-[11px] font-mono capitalize transition-colors ${
                filterType === f
                  ? 'bg-cobalt-600 text-white font-medium'
                  : 'bg-slate-800/80 text-slate-400 hover:text-slate-200'
              }`}
            >
              {f}
            </button>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3">
        {/* SVG Interactive Canvas */}
        <div className="lg:col-span-2 relative h-[440px] bg-slate-950/80 border-r border-slate-800/80 flex items-center justify-center overflow-hidden">
          <svg className="w-full h-full" viewBox={`0 0 ${width} ${height}`}>
            {/* Render Edges */}
            {edges.map((edge, i) => {
              const srcPos = nodePositions[edge.source];
              const tgtPos = nodePositions[edge.target];
              if (!srcPos || !tgtPos) return null;

              return (
                <g key={`edge-${i}`}>
                  <line
                    x1={srcPos.x}
                    y1={srcPos.y}
                    x2={tgtPos.x}
                    y2={tgtPos.y}
                    stroke={edge.is_inferred ? '#64748b' : '#334155'}
                    strokeWidth={edge.is_inferred ? 1.5 : 2}
                    strokeDasharray={edge.is_inferred ? '4,4' : undefined}
                    opacity={0.7}
                  />
                  {/* Midpoint Label */}
                  <text
                    x={(srcPos.x + tgtPos.x) / 2}
                    y={(srcPos.y + tgtPos.y) / 2 - 4}
                    fill="#64748b"
                    fontSize="9"
                    fontFamily="monospace"
                    textAnchor="middle"
                  >
                    {edge.label}
                  </text>
                </g>
              );
            })}

            {/* Render Nodes */}
            {filteredNodes.map((node) => {
              const pos = nodePositions[node.id];
              if (!pos) return null;
              const isSelected = selectedNode?.id === node.id;
              const color = getNodeColor(node);

              return (
                <g
                  key={node.id}
                  transform={`translate(${pos.x}, ${pos.y})`}
                  className="cursor-pointer transition-transform hover:scale-110"
                  onClick={() => setSelectedNode(node)}
                >
                  <circle
                    r={node.id === 'root_target' ? 22 : 16}
                    fill="#0f172a"
                    stroke={isSelected ? '#60a5fa' : color}
                    strokeWidth={isSelected ? 3 : 2}
                  />
                  <circle
                    r={node.id === 'root_target' ? 17 : 11}
                    fill={color}
                    fillOpacity={0.25}
                  />
                  <text
                    y={node.id === 'root_target' ? 32 : 26}
                    fill="#cbd5e1"
                    fontSize="10"
                    fontFamily="monospace"
                    textAnchor="middle"
                  >
                    {node.label.length > 18 ? node.label.slice(0, 16) + '...' : node.label}
                  </text>
                </g>
              );
            })}
          </svg>

          {/* Canvas Legend */}
          <div className="absolute bottom-3 left-3 bg-slate-900/90 border border-slate-800 p-2 rounded text-[10px] font-mono flex items-center space-x-3 text-slate-400">
            <span className="flex items-center space-x-1">
              <span className="w-2 h-2 rounded-full bg-red-500 inline-block"></span>
              <span>Malicious</span>
            </span>
            <span className="flex items-center space-x-1">
              <span className="w-2 h-2 rounded-full bg-amber-500 inline-block"></span>
              <span>Suspicious</span>
            </span>
            <span className="flex items-center space-x-1">
              <span className="w-2 h-2 rounded-full bg-cobalt-500 inline-block"></span>
              <span>Neutral / Direct</span>
            </span>
          </div>
        </div>

        {/* Node Inspector Panel */}
        <div className="p-5 flex flex-col justify-between bg-slate-950/40">
          <div>
            <div className="flex items-center space-x-2 text-xs font-semibold text-slate-300 pb-3 border-b border-slate-800">
              <Info className="w-4 h-4 text-cobalt-400" />
              <span>Node Forensic Inspector</span>
            </div>

            {selectedNode ? (
              <div className="mt-4 space-y-3.5">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    {getNodeIcon(selectedNode.node_type)}
                    <span className="text-xs font-bold text-slate-200">{selectedNode.label}</span>
                  </div>
                  <span
                    className={`text-[10px] font-mono px-2 py-0.5 rounded capitalize ${
                      selectedNode.risk_level === 'malicious'
                        ? 'bg-red-500/20 text-red-300 border border-red-500/40'
                        : selectedNode.risk_level === 'suspicious'
                        ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
                        : 'bg-cobalt-500/20 text-cobalt-300 border border-cobalt-500/40'
                    }`}
                  >
                    {selectedNode.risk_level}
                  </span>
                </div>

                <div className="text-xs text-slate-400 font-mono space-y-1 bg-slate-900/60 p-3 rounded-lg border border-slate-800/80">
                  <p><span className="text-slate-400">Type:</span> {selectedNode.node_type}</p>
                  <p><span className="text-slate-400">Identifier:</span> {selectedNode.id}</p>
                </div>

                {selectedNode.details && Object.keys(selectedNode.details).length > 0 && (
                  <div>
                    <span className="text-[11px] font-mono uppercase text-slate-400">Inspected Telemetry</span>
                    <pre className="mt-1.5 p-3 rounded bg-slate-900 text-[11px] font-mono text-slate-300 overflow-x-auto max-h-48 border border-slate-800">
                      {JSON.stringify(selectedNode.details, null, 2)}
                    </pre>
                  </div>
                )}
              </div>
            ) : (
              <div className="py-16 text-center text-slate-400 text-xs">
                <Network className="w-8 h-8 text-slate-700 mx-auto mb-2" />
                <p>Click any node in the graph above to inspect raw forensic properties and cross-layer relationships.</p>
              </div>
            )}
          </div>

          <div className="pt-3 border-t border-slate-800 text-[11px] text-slate-400">
            Tip: Red and amber nodes represent corroborated threat indicators or structural anomalies discovered during the pipeline run.
          </div>
        </div>
      </div>
    </div>
  );
};
