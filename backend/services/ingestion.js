import db from '../db.js';
import { v4 as uuidv4 } from 'uuid';
import normalizer from './normalizer.js';

class IngestionService {
  constructor() {
    this.eventQueue = [];
    this.batchSize = 100;
    this.flushInterval = 5000; // 5 seconds
    this.startBatchProcessing();
  }

  /**
   * Ingest raw event data
   */
  async ingestEvent(rawEvent) {
    try {
      const normalizedEvent = normalizer.normalizeEvent(rawEvent);
      
      // Store indicator
      const indicatorId = await this.storeIndicator(normalizedEvent);
      
      // Store event
      await this.storeEvent(normalizedEvent, indicatorId);
      
      return { success: true, indicator_id: indicatorId };
    } catch (error) {
      console.error('Ingestion error:', error);
      return { success: false, error: error.message };
    }
  }

  /**
   * Batch ingest multiple events
   */
  async ingestEvents(rawEvents) {
    const results = [];
    for (const event of rawEvents) {
      const result = await this.ingestEvent(event);
      results.push(result);
    }
    return results;
  }

  /**
   * Store or update indicator
   */
  storeIndicator(normalizedEvent) {
    return new Promise((resolve, reject) => {
      const indicatorId = uuidv4();
      const now = new Date().toISOString();

      // Check if indicator already exists
      db.get(
        'SELECT id, first_seen FROM indicators WHERE value = ? AND type = ?',
        [normalizedEvent.indicator_value, normalizedEvent.indicator_type],
        (err, row) => {
          if (err) {
            reject(err);
            return;
          }

          if (row) {
            // Update existing indicator
            db.run(
              `UPDATE indicators 
               SET last_seen = ?, 
                   confidence = MAX(confidence, ?),
                   metadata = ?
               WHERE id = ?`,
              [
                now,
                normalizedEvent.metadata?.confidence || 0.5,
                JSON.stringify(normalizedEvent.metadata),
                row.id
              ],
              (err) => {
                if (err) reject(err);
                else resolve(row.id);
              }
            );
          } else {
            // Insert new indicator
            db.run(
              `INSERT INTO indicators 
               (id, type, value, source, confidence, first_seen, last_seen, metadata)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
              [
                indicatorId,
                normalizedEvent.indicator_type,
                normalizedEvent.indicator_value,
                normalizedEvent.source,
                normalizedEvent.metadata?.confidence || 0.5,
                now,
                now,
                JSON.stringify(normalizedEvent.metadata)
              ],
              (err) => {
                if (err) reject(err);
                else resolve(indicatorId);
              }
            );
          }
        }
      );
    });
  }

  /**
   * Store event
   */
  storeEvent(normalizedEvent, indicatorId) {
    return new Promise((resolve, reject) => {
      const eventId = uuidv4();
      
      db.run(
        `INSERT INTO events 
         (id, indicator_id, event_type, timestamp, frequency, port, geo_location, payload_size, metadata)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          eventId,
          indicatorId,
          normalizedEvent.event_type,
          normalizedEvent.timestamp,
          normalizedEvent.metadata?.attempts || 1,
          normalizedEvent.metadata?.port || null,
          normalizedEvent.metadata?.geo || null,
          normalizedEvent.metadata?.payload_size || null,
          JSON.stringify(normalizedEvent.metadata)
        ],
        (err) => {
          if (err) reject(err);
          else resolve(eventId);
        }
      );
    });
  }

  /**
   * Queue event for batch processing
   */
  queueEvent(event) {
    this.eventQueue.push(event);
    if (this.eventQueue.length >= this.batchSize) {
      this.flushQueue();
    }
  }

  /**
   * Flush event queue
   */
  async flushQueue() {
    if (this.eventQueue.length === 0) return;

    const batch = [...this.eventQueue];
    this.eventQueue = [];

    await this.ingestEvents(batch);
  }

  /**
   * Start batch processing timer
   */
  startBatchProcessing() {
    setInterval(() => {
      this.flushQueue();
    }, this.flushInterval);
  }

  /**
   * Simulate threat feed ingestion
   */
  async simulateThreatFeed() {
    const mockEvents = [
      {
        ip: '192.168.1.100',
        event_type: 'failed_login',
        port: 22,
        attempts: 250,
        geo: 'RU',
        timestamp: new Date().toISOString()
      },
      {
        ip: '10.0.0.50',
        event_type: 'port_scan',
        port: 443,
        geo: 'CN',
        timestamp: new Date().toISOString()
      },
      {
        domain: 'malicious-c2.com',
        event_type: 'c2_communication',
        geo: 'RU',
        timestamp: new Date().toISOString()
      },
      {
        ip: '172.16.0.20',
        event_type: 'data_exfiltration',
        payload_size: 104857600, // 100MB
        geo: 'US',
        timestamp: new Date().toISOString()
      }
    ];

    await this.ingestEvents(mockEvents);
    return mockEvents.length;
  }
}

export default new IngestionService();