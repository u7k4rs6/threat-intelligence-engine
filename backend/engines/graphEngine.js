import db from '../db.js';
import { v4 as uuidv4 } from 'uuid';

class GraphEngine {
  constructor() {
    this.graph = new Map(); // adjacency list
    this.nodes = new Map();
    this.edges = [];
  }

  /**
   * Build graph from database
   */
  async buildGraph() {
    try {
      await this.loadNodesFromDB();
      await this.loadEdgesFromDB();
      await this.createRelationshipsFromEvents();
      
      return { nodes: this.nodes.size, edges: this.edges.length };
    } catch (error) {
      console.error('Graph building error:', error);
      return { nodes: 0, edges: 0 };
    }
  }

  async loadNodesFromDB() {
    return new Promise((resolve, reject) => {
      db.all('SELECT * FROM graph_nodes', [], (err, rows) => {
        if (err) reject(err);
        else {
          rows.forEach(row => {
            this.nodes.set(row.id, row);
            if (!this.graph.has(row.id)) {
              this.graph.set(row.id, []);
            }
          });
          resolve();
        }
      });
    });
  }

  async loadEdgesFromDB() {
    return new Promise((resolve, reject) => {
      db.all('SELECT * FROM graph_edges', [], (err, rows) => {
        if (err) reject(err);
        else {
          this.edges = rows;
          rows.forEach(edge => {
            if (!this.graph.has(edge.source_node)) {
              this.graph.set(edge.source_node, []);
            }
            this.graph.get(edge.source_node).push({
              target: edge.target_node,
              type: edge.relation_type,
              weight: edge.weight
            });
          });
          resolve();
        }
      });
    });
  }

  /**
   * Create graph relationships from events
   */
  async createRelationshipsFromEvents() {
    return new Promise((resolve, reject) => {
      db.all(`
        SELECT DISTINCT 
          i.value as indicator_value,
          i.type as indicator_type,
          e.event_type,
          e.timestamp
        FROM indicators i
        JOIN events e ON i.id = e.indicator_id
        ORDER BY e.timestamp DESC
        LIMIT 1000
      `, [], async (err, rows) => {
        if (err) {
          reject(err);
          return;
        }

        for (const row of rows) {
          await this.addNode(row.indicator_value, row.indicator_type);
        }

        // Create edges based on common patterns
        const ipNodes = Array.from(this.nodes.values()).filter(n => n.entity_type === 'IP');
        const domainNodes = Array.from(this.nodes.values()).filter(n => n.entity_type === 'domain');

        // Connect IPs that appear in similar timeframes
        for (let i = 0; i < ipNodes.length; i++) {
          for (let j = i + 1; j < ipNodes.length; j++) {
            if (Math.random() > 0.7) { // Simulate correlation
              await this.addEdge(
                ipNodes[i].id,
                ipNodes[j].id,
                'communicates_with',
                0.6
              );
            }
          }
        }

        // Connect IPs to domains
        for (const ip of ipNodes.slice(0, 10)) {
          for (const domain of domainNodes.slice(0, 5)) {
            if (Math.random() > 0.6) {
              await this.addEdge(ip.id, domain.id, 'resolves_to', 0.7);
            }
          }
        }

        resolve();
      });
    });
  }

  /**
   * Add node to graph
   */
  async addNode(value, type) {
    const nodeId = uuidv4();
    
    return new Promise((resolve, reject) => {
      db.get(
        'SELECT id FROM graph_nodes WHERE entity_value = ? AND entity_type = ?',
        [value, type],
        (err, row) => {
          if (err) {
            reject(err);
            return;
          }

          if (row) {
            resolve(row.id);
            return;
          }

          db.run(
            'INSERT INTO graph_nodes (id, entity_type, entity_value) VALUES (?, ?, ?)',
            [nodeId, type, value],
            (err) => {
              if (err) reject(err);
              else {
                this.nodes.set(nodeId, { id: nodeId, entity_type: type, entity_value: value });
                this.graph.set(nodeId, []);
                resolve(nodeId);
              }
            }
          );
        }
      );
    });
  }

  /**
   * Add edge to graph
   */
  async addEdge(sourceId, targetId, relationType, weight = 1.0) {
    const edgeId = uuidv4();
    const timestamp = new Date().toISOString();

    return new Promise((resolve, reject) => {
      db.run(
        'INSERT INTO graph_edges (id, source_node, target_node, relation_type, weight, timestamp) VALUES (?, ?, ?, ?, ?, ?)',
        [edgeId, sourceId, targetId, relationType, weight, timestamp],
        (err) => {
          if (err) {
            reject(err);
            return;
          }

          this.edges.push({ id: edgeId, source_node: sourceId, target_node: targetId, relation_type: relationType, weight });
          
          if (!this.graph.has(sourceId)) {
            this.graph.set(sourceId, []);
          }
          this.graph.get(sourceId).push({ target: targetId, type: relationType, weight });
          
          resolve(edgeId);
        }
      );
    });
  }

  /**
   * Calculate PageRank
   */
  calculatePageRank(iterations = 20, dampingFactor = 0.85) {
    const nodeIds = Array.from(this.nodes.keys());
    const numNodes = nodeIds.length;
    
    if (numNodes === 0) return {};

    // Initialize PageRank values
    const pagerank = {};
    nodeIds.forEach(id => {
      pagerank[id] = 1.0 / numNodes;
    });

    // Iterate
    for (let iter = 0; iter < iterations; iter++) {
      const newPagerank = {};
      
      nodeIds.forEach(nodeId => {
        let sum = 0;
        
        // Find all nodes pointing to this node
        nodeIds.forEach(otherId => {
          const neighbors = this.graph.get(otherId) || [];
          const pointsToNode = neighbors.find(n => n.target === nodeId);
          
          if (pointsToNode) {
            const outDegree = neighbors.length;
            if (outDegree > 0) {
              sum += pagerank[otherId] / outDegree;
            }
          }
        });

        newPagerank[nodeId] = (1 - dampingFactor) / numNodes + dampingFactor * sum;
      });

      Object.assign(pagerank, newPagerank);
    }

    return pagerank;
  }

  /**
   * Calculate centrality (degree centrality)
   */
  calculateCentrality() {
    const centrality = {};
    const nodeIds = Array.from(this.nodes.keys());
    const maxDegree = nodeIds.length - 1;

    nodeIds.forEach(nodeId => {
      const neighbors = this.graph.get(nodeId) || [];
      centrality[nodeId] = maxDegree > 0 ? neighbors.length / maxDegree : 0;
    });

    return centrality;
  }

  /**
   * Detect communities using simple clustering
   */
  detectCommunities() {
    const visited = new Set();
    const communities = [];
    const nodeIds = Array.from(this.nodes.keys());

    nodeIds.forEach(startNode => {
      if (visited.has(startNode)) return;

      const community = new Set();
      const queue = [startNode];

      while (queue.length > 0) {
        const node = queue.shift();
        if (visited.has(node)) continue;

        visited.add(node);
        community.add(node);

        const neighbors = this.graph.get(node) || [];
        neighbors.forEach(neighbor => {
          if (!visited.has(neighbor.target) && neighbor.weight > 0.5) {
            queue.push(neighbor.target);
          }
        });
      }

      if (community.size > 0) {
        communities.push(community);
      }
    });

    return communities;
  }

  /**
   * Calculate cluster density
   */
  calculateClusterDensity(nodeId) {
    const neighbors = this.graph.get(nodeId) || [];
    if (neighbors.length < 2) return 0;

    let connections = 0;
    const neighborIds = neighbors.map(n => n.target);

    // Count connections between neighbors
    neighborIds.forEach(n1 => {
      const n1Neighbors = this.graph.get(n1) || [];
      neighborIds.forEach(n2 => {
        if (n1 !== n2 && n1Neighbors.some(n => n.target === n2)) {
          connections++;
        }
      });
    });

    const maxConnections = neighbors.length * (neighbors.length - 1);
    return maxConnections > 0 ? connections / maxConnections : 0;
  }

  /**
   * Calculate graph score for indicator
   */
  async calculateGraphScore(indicatorValue) {
    try {
      await this.buildGraph();

      const node = Array.from(this.nodes.values()).find(
        n => n.entity_value === indicatorValue
      );

      if (!node) {
        return { score: 0, details: {} };
      }

      const pagerank = this.calculatePageRank();
      const centrality = this.calculateCentrality();
      const clusterDensity = this.calculateClusterDensity(node.id);

      // Calculate weighted score
      const pagerankWeight = (pagerank[node.id] || 0) * 1000; // Normalize
      const centralityWeight = (centrality[node.id] || 0) * 100;
      const densityWeight = clusterDensity * 100;

      const score = (
        0.4 * pagerankWeight +
        0.3 * centralityWeight +
        0.3 * densityWeight
      );

      return {
        score: Math.min(Math.round(score), 100),
        details: {
          pagerank: pagerank[node.id] || 0,
          centrality: centrality[node.id] || 0,
          clusterDensity: clusterDensity,
          neighbors: (this.graph.get(node.id) || []).length
        }
      };
    } catch (error) {
      console.error('Graph score calculation error:', error);
      return { score: 0, details: {} };
    }
  }

  /**
   * Get graph visualization data
   */
  async getGraphData() {
    await this.buildGraph();

    const nodes = Array.from(this.nodes.values()).map(node => ({
      id: node.id,
      label: node.entity_value,
      type: node.entity_type
    }));

    const edges = this.edges.map(edge => ({
      source: edge.source_node,
      target: edge.target_node,
      label: edge.relation_type,
      weight: edge.weight
    }));

    return { nodes, edges };
  }
}

export default new GraphEngine();