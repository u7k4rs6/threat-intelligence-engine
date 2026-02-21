import express from 'express';
import cors from 'cors';
import { v4 as uuidv4 } from 'uuid';
import db from './db.js';
import IngestionService from './services/ingestion.js';
import FeatureExtractor from './services/features.js';
import RuleEngine from './services/rules.js';
import MLEngine from './services/ml.js';
import GraphEngine from './services/graph.js';
import RiskAggregator from './services/risk.js';
import MitreMapper from './services/mitre.js';
import ForecastEngine from './services/forecast.js';

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
const corsOptions = {
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
  allowedHeaders: ['*'],
  credentials: true,
  optionsSuccessStatus: 200
};

app.use(cors(corsOptions));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Initialize services
const ingestionService = new IngestionService();
const featureExtractor = new FeatureExtractor();
const ruleEngine = new RuleEngine();
const mlEngine = new MLEngine();
const graphEngine = new GraphEngine();
const riskAggregator = new RiskAggregator();
const mitreMapper = new MitreMapper();
const forecastEngine = new ForecastEngine();

// Request logging middleware
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
  next();
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ status: 'healthy', timestamp: new Date().toISOString() });
});

// Get all alerts
app.get('/alerts', (req, res) => {
  const limit = parseInt(req.query.limit) || 100;
  const offset = parseInt(req.query.offset) || 0;
  
  const query = `
    SELECT a.*, i.type as indicator_type, i.value as indicator_value, 
           e.event_type, e.geo_location
    FROM alerts a
    LEFT JOIN indicators i ON a.indicator_id = i.id
    LEFT JOIN events e ON a.indicator_id = e.indicator_id
    ORDER BY a.created_at DESC
    LIMIT ? OFFSET ?
  `;
  
  db.all(query, [limit, offset], (err, rows) => {
    if (err) {
      console.error('Error fetching alerts:', err);
      return res.status(500).json({ error: 'Failed to fetch alerts' });
    }
    res.json(rows || []);
  });
});

// Get specific indicator details
app.get('/indicator/:value', (req, res) => {
  const { value } = req.params;
  
  const query = `
    SELECT i.*, 
           COUNT(DISTINCT e.id) as event_count,
           COUNT(DISTINCT a.id) as alert_count,
           MAX(a.final_risk_score) as max_risk_score
    FROM indicators i
    LEFT JOIN events e ON i.id = e.indicator_id
    LEFT JOIN alerts a ON i.id = a.indicator_id
    WHERE i.value = ?
    GROUP BY i.id
  `;
  
  db.get(query, [value], (err, indicator) => {
    if (err) {
      console.error('Error fetching indicator:', err);
      return res.status(500).json({ error: 'Failed to fetch indicator' });
    }
    
    if (!indicator) {
      return res.status(404).json({ error: 'Indicator not found' });
    }
    
    // Get recent events for this indicator
    const eventsQuery = `
      SELECT * FROM events 
      WHERE indicator_id = ? 
      ORDER BY timestamp DESC 
      LIMIT 10
    `;
    
    db.all(eventsQuery, [indicator.id], (err, events) => {
      if (err) {
        console.error('Error fetching events:', err);
        return res.json(indicator);
      }
      
      res.json({
        ...indicator,
        recent_events: events || []
      });
    });
  });
});

// Analyze new event
app.post('/analyze', async (req, res) => {
  try {
    const rawEvent = req.body;
    
    // Step 1: Normalize event
    const normalizedEvent = ingestionService.normalizeEvent(rawEvent);
    
    // Step 2: Extract features
    const features = await featureExtractor.extractFeatures(normalizedEvent);
    
    // Step 3: Store or update indicator
    const indicatorId = await storeIndicator(normalizedEvent);
    
    // Step 4: Store event
    const eventId = await storeEvent(normalizedEvent, indicatorId, features);
    
    // Step 5: Run correlation engines
    const ruleScore = await ruleEngine.evaluate(normalizedEvent, features);
    const mlScore = await mlEngine.detectAnomaly(features);
    const graphScore = await graphEngine.calculateRisk(normalizedEvent, indicatorId);
    
    // Step 6: Aggregate risk
    const riskResult = riskAggregator.aggregate(ruleScore, mlScore, graphScore);
    
    // Step 7: Map to MITRE ATT&CK
    const mitreStage = mitreMapper.mapEventToMitre(normalizedEvent);
    
    // Step 8: Store alert
    const alertId = await storeAlert(
      indicatorId,
      ruleScore,
      mlScore,
      graphScore,
      riskResult,
      mitreStage
    );
    
    // Step 9: Update graph
    await graphEngine.updateGraph(normalizedEvent, indicatorId);
    
    res.json({
      alert_id: alertId,
      indicator_value: normalizedEvent.indicator_value,
      event_type: normalizedEvent.event_type,
      rule_score: ruleScore.score,
      ml_score: mlScore.score,
      graph_score: graphScore.score,
      final_risk_score: riskResult.final_score,
      severity: riskResult.severity,
      mitre_stage: mitreStage,
      triggered_rules: ruleScore.triggered_rules,
      features: features
    });
    
  } catch (error) {
    console.error('Error analyzing event:', error);
    res.status(500).json({ error: 'Failed to analyze event', details: error.message });
  }
});

// Get threat forecast
app.get('/forecast', async (req, res) => {
  try {
    const days = parseInt(req.query.days) || 7;
    const forecast = await forecastEngine.generateForecast(days);
    res.json(forecast);
  } catch (error) {
    console.error('Error generating forecast:', error);
    res.status(500).json({ error: 'Failed to generate forecast' });
  }
});

// Get dashboard statistics
app.get('/stats', (req, res) => {
  const queries = {
    total_alerts: 'SELECT COUNT(*) as count FROM alerts',
    critical_alerts: "SELECT COUNT(*) as count FROM alerts WHERE severity = 'Critical'",
    active_indicators: 'SELECT COUNT(*) as count FROM indicators',
    avg_risk_score: 'SELECT AVG(final_risk_score) as avg FROM alerts'
  };
  
  const stats = {};
  let completed = 0;
  const total = Object.keys(queries).length;
  
  Object.entries(queries).forEach(([key, query]) => {
    db.get(query, [], (err, row) => {
      if (!err) {
        stats[key] = row?.count !== undefined ? row.count : (row?.avg || 0);
      } else {
        stats[key] = 0;
      }
      
      completed++;
      if (completed === total) {
        res.json(stats);
      }
    });
  });
});

// Get graph data for visualization
app.get('/graph', (req, res) => {
  const limit = parseInt(req.query.limit) || 50;
  
  const nodesQuery = 'SELECT * FROM graph_nodes LIMIT ?';
  const edgesQuery = `
    SELECT e.*, 
           n1.entity_value as source_value,
           n2.entity_value as target_value
    FROM graph_edges e
    LEFT JOIN graph_nodes n1 ON e.source_node = n1.id
    LEFT JOIN graph_nodes n2 ON e.target_node = n2.id
    LIMIT ?
  `;
  
  db.all(nodesQuery, [limit], (err, nodes) => {
    if (err) {
      console.error('Error fetching nodes:', err);
      return res.status(500).json({ error: 'Failed to fetch graph data' });
    }
    
    db.all(edgesQuery, [limit], (err, edges) => {
      if (err) {
        console.error('Error fetching edges:', err);
        return res.json({ nodes: nodes || [], edges: [] });
      }
      
      res.json({
        nodes: nodes || [],
        edges: edges || []
      });
    });
  });
});

// Batch ingest events
app.post('/ingest/batch', async (req, res) => {
  try {
    const events = req.body.events;
    
    if (!Array.isArray(events)) {
      return res.status(400).json({ error: 'Events must be an array' });
    }
    
    const results = [];
    
    for (const event of events) {
      try {
        const normalized = ingestionService.normalizeEvent(event);
        const features = await featureExtractor.extractFeatures(normalized);
        const indicatorId = await storeIndicator(normalized);
        const eventId = await storeEvent(normalized, indicatorId, features);
        
        const ruleScore = await ruleEngine.evaluate(normalized, features);
        const mlScore = await mlEngine.detectAnomaly(features);
        const graphScore = await graphEngine.calculateRisk(normalized, indicatorId);
        const riskResult = riskAggregator.aggregate(ruleScore, mlScore, graphScore);
        const mitreStage = mitreMapper.mapEventToMitre(normalized);
        
        const alertId = await storeAlert(
          indicatorId,
          ruleScore,
          mlScore,
          graphScore,
          riskResult,
          mitreStage
        );
        
        await graphEngine.updateGraph(normalized, indicatorId);
        
        results.push({ success: true, alert_id: alertId });
      } catch (error) {
        results.push({ success: false, error: error.message });
      }
    }
    
    res.json({
      total: events.length,
      successful: results.filter(r => r.success).length,
      failed: results.filter(r => !r.success).length,
      results
    });
    
  } catch (error) {
    console.error('Error in batch ingest:', error);
    res.status(500).json({ error: 'Failed to process batch' });
  }
});

// Helper functions for database operations
function storeIndicator(event) {
  return new Promise((resolve, reject) => {
    const { indicator_type, indicator_value, source } = event;
    const now = new Date().toISOString();
    
    // Check if indicator exists
    db.get(
      'SELECT id FROM indicators WHERE value = ? AND type = ?',
      [indicator_value, indicator_type],
      (err, row) => {
        if (err) return reject(err);
        
        if (row) {
          // Update last_seen
          db.run(
            'UPDATE indicators SET last_seen = ? WHERE id = ?',
            [now, row.id],
            (err) => {
              if (err) return reject(err);
              resolve(row.id);
            }
          );
        } else {
          // Insert new indicator
          const id = uuidv4();
          db.run(
            `INSERT INTO indicators (id, type, value, source, confidence, first_seen, last_seen)
             VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [id, indicator_type, indicator_value, source, 0.5, now, now],
            (err) => {
              if (err) return reject(err);
              resolve(id);
            }
          );
        }
      }
    );
  });
}

function storeEvent(event, indicatorId, features) {
  return new Promise((resolve, reject) => {
    const id = uuidv4();
    const { event_type, timestamp, metadata } = event;
    
    db.run(
      `INSERT INTO events 
       (id, indicator_id, event_type, timestamp, frequency, port, geo_location, payload_size)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        id,
        indicatorId,
        event_type,
        timestamp || new Date().toISOString(),
        features.frequency || 1,
        metadata?.port || null,
        metadata?.geo || null,
        metadata?.payload_size || null
      ],
      (err) => {
        if (err) return reject(err);
        resolve(id);
      }
    );
  });
}

function storeAlert(indicatorId, ruleScore, mlScore, graphScore, riskResult, mitreStage) {
  return new Promise((resolve, reject) => {
    const id = uuidv4();
    
    db.run(
      `INSERT INTO alerts 
       (id, indicator_id, rule_score, ml_score, graph_score, final_risk_score, severity, mitre_stage, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        id,
        indicatorId,
        ruleScore.score,
        mlScore.score,
        graphScore.score,
        riskResult.final_score,
        riskResult.severity,
        mitreStage,
        new Date().toISOString()
      ],
      (err) => {
        if (err) return reject(err);
        resolve(id);
      }
    );
  });
}

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error', details: err.message });
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
  console.log('==============================================');
  console.log('  ThreatSim Intelligence Engine - Backend');
  console.log('==============================================');
  console.log(`Server running on http://0.0.0.0:${PORT}`);
  console.log(`Health check: http://0.0.0.0:${PORT}/health`);
  console.log('==============================================');
  
  // Generate some sample data on startup
  setTimeout(() => {
    console.log('Generating sample threat data...');
    generateSampleData();
  }, 2000);
});

// Generate sample threat data
async function generateSampleData() {
  const sampleEvents = [
    {
      indicator_type: 'IP',
      indicator_value: '192.168.1.100',
      event_type: 'failed_login',
      timestamp: new Date().toISOString(),
      source: 'auth_log',
      metadata: { port: 22, geo: 'RU', attempts: 350 }
    },
    {
      indicator_type: 'IP',
      indicator_value: '10.0.0.50',
      event_type: 'port_scan',
      timestamp: new Date().toISOString(),
      source: 'firewall',
      metadata: { port: 445, geo: 'CN', attempts: 500 }
    },
    {
      indicator_type: 'Domain',
      indicator_value: 'malicious-c2.example.com',
      event_type: 'dns_beacon',
      timestamp: new Date().toISOString(),
      source: 'dns_log',
      metadata: { geo: 'US', attempts: 120 }
    },
    {
      indicator_type: 'IP',
      indicator_value: '172.16.0.25',
      event_type: 'data_exfiltration',
      timestamp: new Date().toISOString(),
      source: 'netflow',
      metadata: { port: 443, geo: 'KP', payload_size: 50000000 }
    },
    {
      indicator_type: 'Hash',
      indicator_value: 'a3f5e9c8d1b2f4e6c7a8b9d0e1f2a3b4',
      event_type: 'malware_execution',
      timestamp: new Date().toISOString(),
      source: 'edr',
      metadata: { geo: 'IR' }
    }
  ];
  
  for (const event of sampleEvents) {
    try {
      const normalized = ingestionService.normalizeEvent(event);
      const features = await featureExtractor.extractFeatures(normalized);
      const indicatorId = await storeIndicator(normalized);
      await storeEvent(normalized, indicatorId, features);
      
      const ruleScore = await ruleEngine.evaluate(normalized, features);
      const mlScore = await mlEngine.detectAnomaly(features);
      const graphScore = await graphEngine.calculateRisk(normalized, indicatorId);
      const riskResult = riskAggregator.aggregate(ruleScore, mlScore, graphScore);
      const mitreStage = mitreMapper.mapEventToMitre(normalized);
      
      await storeAlert(indicatorId, ruleScore, mlScore, graphScore, riskResult, mitreStage);
      await graphEngine.updateGraph(normalized, indicatorId);
      
      console.log(`✓ Generated alert for ${event.indicator_value}`);
    } catch (error) {
      console.error(`✗ Error generating sample for ${event.indicator_value}:`, error.message);
    }
  }
  
  console.log('Sample data generation complete');
}

export default app;