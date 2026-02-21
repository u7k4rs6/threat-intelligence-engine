import sqlite3 from 'sqlite3';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const dbPath = path.join(__dirname, 'database.db');

const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    console.error('Error opening database:', err);
  } else {
    console.log('Connected to SQLite database');
    initializeTables();
  }
});

function initializeTables() {
  db.serialize(() => {
    // Indicators table
    db.run(`
      CREATE TABLE IF NOT EXISTS indicators (
        id TEXT PRIMARY KEY,
        type TEXT NOT NULL,
        value TEXT NOT NULL,
        source TEXT NOT NULL,
        confidence REAL DEFAULT 0.5,
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        metadata TEXT
      )
    `);

    // Events table
    db.run(`
      CREATE TABLE IF NOT EXISTS events (
        id TEXT PRIMARY KEY,
        indicator_id TEXT,
        event_type TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        frequency INTEGER DEFAULT 1,
        port INTEGER,
        geo_location TEXT,
        payload_size INTEGER,
        metadata TEXT,
        FOREIGN KEY (indicator_id) REFERENCES indicators(id)
      )
    `);

    // Alerts table
    db.run(`
      CREATE TABLE IF NOT EXISTS alerts (
        id TEXT PRIMARY KEY,
        indicator_id TEXT,
        rule_score REAL DEFAULT 0,
        ml_score REAL DEFAULT 0,
        graph_score REAL DEFAULT 0,
        final_risk_score REAL NOT NULL,
        severity TEXT NOT NULL,
        mitre_stage TEXT,
        event_types TEXT,
        explanation TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY (indicator_id) REFERENCES indicators(id)
      )
    `);

    // Graph nodes table
    db.run(`
      CREATE TABLE IF NOT EXISTS graph_nodes (
        id TEXT PRIMARY KEY,
        entity_type TEXT NOT NULL,
        entity_value TEXT NOT NULL,
        pagerank REAL DEFAULT 0,
        centrality REAL DEFAULT 0,
        cluster_id INTEGER
      )
    `);

    // Graph edges table
    db.run(`
      CREATE TABLE IF NOT EXISTS graph_edges (
        id TEXT PRIMARY KEY,
        source_node TEXT NOT NULL,
        target_node TEXT NOT NULL,
        relation_type TEXT NOT NULL,
        weight REAL DEFAULT 1.0,
        timestamp TEXT NOT NULL,
        FOREIGN KEY (source_node) REFERENCES graph_nodes(id),
        FOREIGN KEY (target_node) REFERENCES graph_nodes(id)
      )
    `);

    // Time series data for forecasting
    db.run(`
      CREATE TABLE IF NOT EXISTS threat_timeseries (
        id TEXT PRIMARY KEY,
        date TEXT NOT NULL,
        alert_count INTEGER DEFAULT 0,
        critical_count INTEGER DEFAULT 0,
        high_count INTEGER DEFAULT 0,
        medium_count INTEGER DEFAULT 0,
        low_count INTEGER DEFAULT 0,
        attack_types TEXT
      )
    `);

    // Create indexes
    db.run('CREATE INDEX IF NOT EXISTS idx_indicators_value ON indicators(value)');
    db.run('CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)');
    db.run('CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)');
    db.run('CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at)');

    console.log('Database tables initialized');
  });
}

export default db;