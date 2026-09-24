/**
 * Attack graph — models assets, identities, capabilities, trust boundaries,
 * and weak signals as a directed graph. Chain hypotheses are synthesized
 * by finding paths through this graph that cross trust boundaries.
 */

import type {
  AttackGraph,
  AttackGraphNode,
  AttackGraphEdge,
  WeakSignal,
} from './contracts.js';

// ---------------------------------------------------------------------------
// Graph construction
// ---------------------------------------------------------------------------

export function addNode(graph: AttackGraph, node: AttackGraphNode): void {
  if (!graph.nodes.some((n) => n.id === node.id)) {
    graph.nodes.push(node);
  }
}

export function addEdge(graph: AttackGraph, edge: AttackGraphEdge): void {
  const existing = graph.edges.find(
    (e) => e.from === edge.from && e.to === edge.to && e.type === edge.type,
  );
  if (existing) {
    // Strengthen existing edge
    existing.weight = Math.min(1, existing.weight + edge.weight * 0.5);
    if (edge.evidence) {
      existing.evidence = existing.evidence
        ? `${existing.evidence}; ${edge.evidence}`
        : edge.evidence;
    }
  } else {
    graph.edges.push(edge);
  }
}

/**
 * Ingest a weak signal into the attack graph as nodes and edges.
 */
export function ingestSignal(graph: AttackGraph, signal: WeakSignal): void {
  // Add signal node
  addNode(graph, {
    id: `signal:${signal.id}`,
    type: signal.status === 'dormant' ? 'dormant_correlation' : 'weak_signal',
    label: signal.description,
    metadata: {
      surface: signal.surface,
      confidence: signal.confidence,
      status: signal.status,
    },
  });

  // Add edges for related assets
  for (const asset of signal.relatedAssets) {
    const assetNodeId = `asset:${asset}`;
    addNode(graph, {
      id: assetNodeId,
      type: 'asset',
      label: asset,
      metadata: {},
    });
    addEdge(graph, {
      from: `signal:${signal.id}`,
      to: assetNodeId,
      type: 'leaks',
      weight: signal.confidence,
      evidence: signal.description,
    });
    addEdge(graph, {
      from: assetNodeId,
      to: `signal:${signal.id}`,
      type: 'suggests',
      weight: Math.max(0.2, signal.confidence * 0.5),
      evidence: signal.description,
    });
  }

  // Add edges for potential capabilities
  for (const cap of signal.potentialCapabilities) {
    const capNodeId = `capability:${cap}`;
    addNode(graph, {
      id: capNodeId,
      type: 'capability',
      label: cap,
      metadata: {},
    });
    addEdge(graph, {
      from: `signal:${signal.id}`,
      to: capNodeId,
      type: 'enables',
      weight: signal.confidence * 0.7,
      evidence: signal.description,
    });
    addEdge(graph, {
      from: capNodeId,
      to: `signal:${signal.id}`,
      type: 'suggests',
      weight: Math.max(0.2, signal.confidence * 0.4),
      evidence: signal.description,
    });
  }

  // Add correlation edges
  for (const corrId of signal.correlatedWith) {
    addEdge(graph, {
      from: `signal:${signal.id}`,
      to: `signal:${corrId}`,
      type: 'co_occurs_with',
      weight: 0.5,
    });
  }

  for (const corrId of signal.unresolvedCorrelations) {
    addEdge(graph, {
      from: `signal:${signal.id}`,
      to: `signal:${corrId}`,
      type: 'suggests',
      weight: 0.3,
    });
  }

  for (const boundary of inferTrustBoundaries(signal)) {
    const boundaryNodeId = `trust_boundary:${boundary.id}`;
    addNode(graph, {
      id: boundaryNodeId,
      type: 'trust_boundary',
      label: boundary.label,
      metadata: {
        signalId: signal.id,
        surface: signal.surface,
      },
    });
    addEdge(graph, {
      from: `signal:${signal.id}`,
      to: boundaryNodeId,
      type: 'crosses_boundary',
      weight: boundary.weight,
      evidence: boundary.evidence,
    });
  }
}

// ---------------------------------------------------------------------------
// Chain discovery — find paths that cross trust boundaries
// ---------------------------------------------------------------------------

/**
 * Find potential chain paths in the graph — sequences of signals
 * connected by edges that accumulate capabilities leading to
 * a trust boundary crossing.
 */
export function findChainCandidates(
  graph: AttackGraph,
  maxDepth: number = 5,
): ChainCandidate[] {
  const candidates: ChainCandidate[] = [];
  const signalNodes = graph.nodes.filter(
    (n) => n.type === 'weak_signal' || n.type === 'dormant_correlation',
  );

  for (const startNode of signalNodes) {
    const paths = findPaths(graph, startNode.id, maxDepth, new Set());
    for (const path of paths) {
      const signalIds = path
        .filter((id) => id.startsWith('signal:'))
        .map((id) => id.replace('signal:', ''));

      if (signalIds.length >= 2) {
        const totalWeight = computePathWeight(graph, path);
        const crossesBoundary = path.some((nodeId) => {
          const node = graph.nodes.find((n) => n.id === nodeId);
          return node?.type === 'trust_boundary';
        });

        const involvesDormant = path.some((nodeId) => {
          const node = graph.nodes.find((n) => n.id === nodeId);
          return node?.type === 'dormant_correlation';
        });

        candidates.push({
          signalIds,
          path,
          totalWeight,
          crossesBoundary,
          involvesDormant,
        });
      }
    }
  }

  // Sort by weight descending, boundary-crossing first
  candidates.sort((a, b) => {
    if (a.crossesBoundary !== b.crossesBoundary) {
      return a.crossesBoundary ? -1 : 1;
    }
    return b.totalWeight - a.totalWeight;
  });

  return candidates;
}

export interface ChainCandidateNeighborhoodOptions {
  /**
   * Maximum traversal depth from each trigger node when building the
   * focused subgraph. Keeps mid-round synthesis tied to the local
   * runtime evidence instead of recomputing the whole graph.
   */
  neighborhoodDepth?: number;
  /**
   * Hard cap on the number of graph nodes included in the focused
   * subgraph. Prevents trigger-driven synthesis from exploding on
   * large graphs during local-live rounds.
   */
  nodeBudget?: number;
  /**
   * Maximum path depth used once the focused subgraph is built.
   */
  maxDepth?: number;
}

/**
 * Find chain candidates in a bounded neighborhood around a set of trigger
 * signals. This is used by local-live mid-round synthesis so runtime signal
 * bursts refine the nearby chain graph rather than recursively exploring the
 * entire campaign graph on every round.
 */
export function findChainCandidatesNearSignals(
  graph: AttackGraph,
  triggerSignalIds: string[],
  options: ChainCandidateNeighborhoodOptions = {},
): ChainCandidate[] {
  if (triggerSignalIds.length === 0) {
    return [];
  }

  const neighborhoodDepth = Math.max(1, options.neighborhoodDepth ?? 3);
  const nodeBudget = Math.max(8, options.nodeBudget ?? 64);
  const maxDepth = Math.max(2, options.maxDepth ?? 4);
  const triggerNodeIds = triggerSignalIds
    .map((signalId) => `signal:${signalId}`)
    .filter((nodeId) => graph.nodes.some((node) => node.id === nodeId));

  if (triggerNodeIds.length === 0) {
    return [];
  }

  const relevantNodeIds = collectNeighborhoodNodeIds(graph, triggerNodeIds, neighborhoodDepth, nodeBudget);
  const subgraph: AttackGraph = {
    nodes: graph.nodes.filter((node) => relevantNodeIds.has(node.id)),
    edges: graph.edges.filter((edge) => relevantNodeIds.has(edge.from) && relevantNodeIds.has(edge.to)),
  };

  return findChainCandidates(subgraph, maxDepth).filter((candidate) =>
    candidate.signalIds.some((signalId) => triggerSignalIds.includes(signalId)),
  );
}

export interface ChainCandidate {
  signalIds: string[];
  path: string[];
  totalWeight: number;
  crossesBoundary: boolean;
  involvesDormant: boolean;
}

// ---------------------------------------------------------------------------
// Graph traversal helpers
// ---------------------------------------------------------------------------

function findPaths(
  graph: AttackGraph,
  startId: string,
  maxDepth: number,
  visited: Set<string>,
): string[][] {
  if (maxDepth <= 0) return [[startId]];
  if (visited.has(startId)) return [];

  visited.add(startId);
  const paths: string[][] = [[startId]];

  const outEdges = graph.edges.filter((e) => e.from === startId);
  for (const edge of outEdges) {
    const subPaths = findPaths(graph, edge.to, maxDepth - 1, new Set(visited));
    for (const subPath of subPaths) {
      paths.push([startId, ...subPath]);
    }
  }

  return paths;
}

function computePathWeight(graph: AttackGraph, path: string[]): number {
  let weight = 0;
  for (let i = 0; i < path.length - 1; i++) {
    const edge = graph.edges.find((e) => e.from === path[i] && e.to === path[i + 1]);
    if (edge) weight += edge.weight;
  }
  return weight;
}

function collectNeighborhoodNodeIds(
  graph: AttackGraph,
  startNodeIds: string[],
  maxDepth: number,
  nodeBudget: number,
): Set<string> {
  const undirectedNeighbors = new Map<string, Set<string>>();
  for (const edge of graph.edges) {
    const from = undirectedNeighbors.get(edge.from) ?? new Set<string>();
    from.add(edge.to);
    undirectedNeighbors.set(edge.from, from);

    const to = undirectedNeighbors.get(edge.to) ?? new Set<string>();
    to.add(edge.from);
    undirectedNeighbors.set(edge.to, to);
  }

  const seen = new Set<string>();
  const queue = startNodeIds.map((nodeId) => ({ nodeId, depth: 0 }));

  while (queue.length > 0 && seen.size < nodeBudget) {
    const current = queue.shift();
    if (!current) {
      continue;
    }
    if (seen.has(current.nodeId)) {
      continue;
    }

    seen.add(current.nodeId);
    if (current.depth >= maxDepth) {
      continue;
    }

    const neighbors = undirectedNeighbors.get(current.nodeId);
    if (!neighbors) {
      continue;
    }
    for (const neighbor of neighbors) {
      if (seen.has(neighbor)) {
        continue;
      }
      queue.push({ nodeId: neighbor, depth: current.depth + 1 });
      if (queue.length + seen.size >= nodeBudget * 2) {
        break;
      }
    }
  }

  return seen;
}

interface BoundaryHint {
  id: string;
  label: string;
  weight: number;
  evidence: string;
}

function inferTrustBoundaries(signal: WeakSignal): BoundaryHint[] {
  const text = [
    signal.surface,
    signal.description,
    ...signal.potentialCapabilities,
    ...signal.relatedAssets,
  ]
    .join(' ')
    .toLowerCase();

  const boundaries = new Map<string, BoundaryHint>();
  const addBoundary = (id: string, label: string, weight: number, evidence: string): void => {
    const existing = boundaries.get(id);
    if (existing) {
      existing.weight = Math.max(existing.weight, weight);
      existing.evidence = `${existing.evidence}; ${evidence}`;
      return;
    }
    boundaries.set(id, { id, label, weight, evidence });
  };

  if (/(unauth|public|proxy|external|outsider|prompt injection|prompt-smuggle|proof leak|webhook)/.test(text)) {
    addBoundary('external_to_internal', 'external -> internal service', 0.8, signal.description);
  }
  if (/(sql|queryraw|executeraw|database|gdpr|backup|pii|export|rls|organization_id)/.test(text)) {
    addBoundary('application_to_data', 'application -> data store', 0.75, signal.description);
  }
  if (/(supply_chain|install script|postinstall|dependency|registry|lockfile|build)/.test(text)) {
    addBoundary('build_to_runtime', 'build -> runtime', 0.7, signal.description);
  }
  if (/(tenant|cross-tenant|organization|impersonation|api key|scope)/.test(text)) {
    addBoundary('tenant_to_tenant', 'tenant -> tenant boundary', 0.72, signal.description);
  }
  if (/(process|proc|fd|credential|secret|cron|launchd|background process|persistence|startup)/.test(text)) {
    addBoundary('runtime_to_host', 'runtime -> host/process boundary', 0.78, signal.description);
  }

  return [...boundaries.values()];
}

// ---------------------------------------------------------------------------
// Serialization (for model context)
// ---------------------------------------------------------------------------

export function summarizeGraph(graph: AttackGraph): string {
  const lines: string[] = [
    `Attack graph: ${graph.nodes.length} nodes, ${graph.edges.length} edges`,
    '',
    '## Nodes by type',
  ];

  const byType = new Map<string, AttackGraphNode[]>();
  for (const node of graph.nodes) {
    const list = byType.get(node.type) ?? [];
    list.push(node);
    byType.set(node.type, list);
  }

  for (const [type, nodes] of byType) {
    lines.push(`  ${type}: ${nodes.length} (${nodes.slice(0, 5).map((n) => n.label).join(', ')}${nodes.length > 5 ? '...' : ''})`);
  }

  lines.push('', '## Strongest edges');
  const sorted = [...graph.edges].sort((a, b) => b.weight - a.weight);
  for (const edge of sorted.slice(0, 20)) {
    lines.push(`  ${edge.from} --[${edge.type} w=${edge.weight.toFixed(2)}]--> ${edge.to}`);
  }

  return lines.join('\n');
}
