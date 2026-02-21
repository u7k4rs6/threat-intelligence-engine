import db from '../db.js';

class FeatureExtractionEngine {
  /**
   * Extract features from events for a given indicator
   */
  async extractFeatures(indicatorId) {
    try {
      const events = await this.getIndicatorEvents(indicatorId);
      const indicator = await this.getIndicator(indicatorId);

      const features = {
        // Temporal features
        event_frequency: this.calculateEventFrequency(events),
        time_between_events: this.calculateTimeBetweenEvents(events),
        event_rate_per_minute: this.calculateEventRate(events, 60),
        event_rate_per_hour: this.calculateEventRate(events, 3600),
        
        // Behavioral features
        unique_event_types: this.countUniqueEventTypes(events),
        event_type_diversity: this.calculateEventTypeDiversity(events),
        port_scan_entropy: this.calculatePortEntropy(events),
        
        // Geographic features
        geo_risk_score: this.calculateGeoRiskScore(events),
        unique_geolocations: this.countUniqueGeolocations(events),
        
        // Network features
        unique_ports: this.countUniquePorts(events),
        avg_payload_size: this.calculateAvgPayloadSize(events),
        payload_variance: this.calculatePayloadVariance(events),
        
        // Statistical features
        event_count_zscore: this.calculateZScore(events.length),
        confidence_score: indicator.confidence,
        
        // Threat indicators
        blacklist_score: this.calculateBlacklistScore(indicator),
        dns_entropy: this.calculateDNSEntropy(indicator, events)
      };

      return features;
    } catch (error) {
      console.error('Feature extraction error:', error);
      return null;
    }
  }

  getIndicatorEvents(indicatorId) {
    return new Promise((resolve, reject) => {
      db.all(
        'SELECT * FROM events WHERE indicator_id = ? ORDER BY timestamp DESC LIMIT 1000',
        [indicatorId],
        (err, rows) => {
          if (err) reject(err);
          else resolve(rows || []);
        }
      );
    });
  }

  getIndicator(indicatorId) {
    return new Promise((resolve, reject) => {
      db.get(
        'SELECT * FROM indicators WHERE id = ?',
        [indicatorId],
        (err, row) => {
          if (err) reject(err);
          else resolve(row);
        }
      );
    });
  }

  calculateEventFrequency(events) {
    return events.length;
  }

  calculateTimeBetweenEvents(events) {
    if (events.length < 2) return 0;

    const times = events.map(e => new Date(e.timestamp).getTime()).sort();
    const differences = [];
    
    for (let i = 1; i < times.length; i++) {
      differences.push((times[i] - times[i - 1]) / 1000); // seconds
    }

    const avg = differences.reduce((a, b) => a + b, 0) / differences.length;
    return avg;
  }

  calculateEventRate(events, windowSeconds) {
    if (events.length === 0) return 0;

    const now = new Date().getTime();
    const windowMs = windowSeconds * 1000;
    const recentEvents = events.filter(e => 
      now - new Date(e.timestamp).getTime() < windowMs
    );

    return recentEvents.length / windowSeconds * 60; // events per minute
  }

  countUniqueEventTypes(events) {
    const types = new Set(events.map(e => e.event_type));
    return types.size;
  }

  calculateEventTypeDiversity(events) {
    if (events.length === 0) return 0;

    const typeCounts = {};
    events.forEach(e => {
      typeCounts[e.event_type] = (typeCounts[e.event_type] || 0) + 1;
    });

    // Calculate Shannon entropy
    return this.calculateEntropy(Object.values(typeCounts));
  }

  calculatePortEntropy(events) {
    const ports = events.filter(e => e.port).map(e => e.port);
    if (ports.length === 0) return 0;

    const portCounts = {};
    ports.forEach(p => {
      portCounts[p] = (portCounts[p] || 0) + 1;
    });

    return this.calculateEntropy(Object.values(portCounts));
  }

  calculateEntropy(values) {
    const total = values.reduce((a, b) => a + b, 0);
    if (total === 0) return 0;

    let entropy = 0;
    values.forEach(count => {
      const p = count / total;
      if (p > 0) {
        entropy -= p * Math.log2(p);
      }
    });

    return entropy;
  }

  calculateGeoRiskScore(events) {
    const highRiskCountries = ['RU', 'CN', 'KP', 'IR'];
    const geoEvents = events.filter(e => e.geo_location);
    
    if (geoEvents.length === 0) return 0;

    const highRiskCount = geoEvents.filter(e => 
      highRiskCountries.includes(e.geo_location)
    ).length;

    return (highRiskCount / geoEvents.length) * 100;
  }

  countUniqueGeolocations(events) {
    const geos = new Set(events.filter(e => e.geo_location).map(e => e.geo_location));
    return geos.size;
  }

  countUniquePorts(events) {
    const ports = new Set(events.filter(e => e.port).map(e => e.port));
    return ports.size;
  }

  calculateAvgPayloadSize(events) {
    const payloads = events.filter(e => e.payload_size).map(e => e.payload_size);
    if (payloads.length === 0) return 0;

    return payloads.reduce((a, b) => a + b, 0) / payloads.length;
  }

  calculatePayloadVariance(events) {
    const payloads = events.filter(e => e.payload_size).map(e => e.payload_size);
    if (payloads.length < 2) return 0;

    const mean = this.calculateAvgPayloadSize(events);
    const squaredDiffs = payloads.map(p => Math.pow(p - mean, 2));
    return squaredDiffs.reduce((a, b) => a + b, 0) / payloads.length;
  }

  calculateZScore(value, mean = 50, stdDev = 20) {
    return (value - mean) / stdDev;
  }

  calculateBlacklistScore(indicator) {
    // Simulate blacklist checking
    // In production, this would query external threat feeds
    const blacklistedValues = ['192.168.1.100', 'malicious-c2.com', '10.0.0.50'];
    
    if (blacklistedValues.includes(indicator.value)) {
      return 90;
    }

    // Check metadata for existing reputation
    try {
      const metadata = JSON.parse(indicator.metadata || '{}');
      if (metadata.reputation) {
        return 100 - metadata.reputation; // Lower reputation = higher risk
      }
    } catch (e) {}

    return 0;
  }

  calculateDNSEntropy(indicator, events) {
    if (indicator.type !== 'domain') return 0;

    const dnsEvents = events.filter(e => e.event_type === 'dns_query');
    if (dnsEvents.length === 0) return 0;

    // Calculate character entropy of domain
    const domain = indicator.value;
    const charCounts = {};
    
    for (const char of domain) {
      charCounts[char] = (charCounts[char] || 0) + 1;
    }

    return this.calculateEntropy(Object.values(charCounts));
  }

  /**
   * Create feature vector for ML
   */
  async createFeatureVector(indicatorId) {
    const features = await this.extractFeatures(indicatorId);
    if (!features) return null;

    // Normalize features to 0-1 range for ML
    return {
      event_frequency_norm: Math.min(features.event_frequency / 1000, 1),
      event_rate_norm: Math.min(features.event_rate_per_minute / 100, 1),
      unique_event_types_norm: Math.min(features.unique_event_types / 10, 1),
      event_diversity_norm: Math.min(features.event_type_diversity / 5, 1),
      port_entropy_norm: Math.min(features.port_scan_entropy / 10, 1),
      geo_risk_norm: features.geo_risk_score / 100,
      blacklist_norm: features.blacklist_score / 100,
      dns_entropy_norm: Math.min(features.dns_entropy / 5, 1),
      payload_variance_norm: Math.min(features.payload_variance / 1000000, 1),
      time_between_events_inv: 1 / (1 + features.time_between_events)
    };
  }
}

export default new FeatureExtractionEngine();