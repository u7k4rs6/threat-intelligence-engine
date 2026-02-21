import db from '../db.js';
import featureEngine from '../services/features.js';

class RuleEngine {
  constructor() {
    this.rules = this.initializeRules();
  }

  initializeRules() {
    return [
      {
        id: 'brute_force_ssh',
        name: 'SSH Brute Force Detection',
        severity: 'high',
        score: 30,
        condition: (features, events) => {
          const sshEvents = events.filter(e => 
            e.event_type === 'failed_login' && e.port === 22
          );
          const recentAttempts = sshEvents.reduce((sum, e) => sum + e.frequency, 0);
          return recentAttempts > 200;
        }
      },
      {
        id: 'port_scan_detection',
        name: 'Port Scan Detection',
        severity: 'medium',
        score: 25,
        condition: (features, events) => {
          return features.unique_ports >= 20 && features.port_scan_entropy > 3;
        }
      },
      {
        id: 'c2_communication',
        name: 'Command and Control Communication',
        severity: 'critical',
        score: 40,
        condition: (features, events) => {
          const c2Events = events.filter(e => e.event_type === 'c2_communication');
          return c2Events.length > 0 || 
                 (features.dns_entropy > 4 && features.event_frequency > 50);
        }
      },
      {
        id: 'multi_vector_attack',
        name: 'Multi-Vector Attack',
        severity: 'critical',
        score: 35,
        condition: (features, events) => {
          return features.unique_event_types >= 3;
        }
      },
      {
        id: 'data_exfiltration',
        name: 'Data Exfiltration',
        severity: 'critical',
        score: 45,
        condition: (features, events) => {
          const exfilEvents = events.filter(e => e.event_type === 'data_exfiltration');
          return exfilEvents.length > 0 || features.avg_payload_size > 10000000;
        }
      },
      {
        id: 'geo_anomaly',
        name: 'Geographic Anomaly',
        severity: 'medium',
        score: 20,
        condition: (features, events) => {
          return features.geo_risk_score > 70 || features.unique_geolocations > 10;
        }
      },
      {
        id: 'rapid_succession',
        name: 'Rapid Event Succession',
        severity: 'medium',
        score: 22,
        condition: (features, events) => {
          return features.time_between_events < 2 && features.event_frequency > 100;
        }
      },
      {
        id: 'blacklist_match',
        name: 'Blacklist Match',
        severity: 'high',
        score: 35,
        condition: (features, events) => {
          return features.blacklist_score > 50;
        }
      },
      {
        id: 'privilege_escalation',
        name: 'Privilege Escalation Attempt',
        severity: 'high',
        score: 38,
        condition: (features, events) => {
          const privEscEvents = events.filter(e => 
            e.event_type === 'privilege_escalation' || 
            e.event_type === 'script_execution'
          );
          return privEscEvents.length > 0;
        }
      },
      {
        id: 'dns_tunneling',
        name: 'DNS Tunneling',
        severity: 'high',
        score: 33,
        condition: (features, events) => {
          const dnsEvents = events.filter(e => e.event_type === 'dns_query');
          return dnsEvents.length > 100 && features.dns_entropy > 4.5;
        }
      },
      {
        id: 'scanning_activity',
        name: 'Network Scanning Activity',
        severity: 'medium',
        score: 20,
        condition: (features, events) => {
          const scanEvents = events.filter(e => e.event_type === 'port_scan');
          return scanEvents.length > 10;
        }
      },
      {
        id: 'malware_detection',
        name: 'Malware Detected',
        severity: 'critical',
        score: 50,
        condition: (features, events) => {
          return events.some(e => e.event_type === 'malware_detected');
        }
      }
    ];
  }

  /**
   * Evaluate all rules for a given indicator
   */
  async evaluateRules(indicatorId) {
    try {
      const features = await featureEngine.extractFeatures(indicatorId);
      const events = await this.getIndicatorEvents(indicatorId);

      if (!features || !events) {
        return { score: 0, matchedRules: [], explanation: [] };
      }

      let totalScore = 0;
      const matchedRules = [];
      const explanation = [];

      for (const rule of this.rules) {
        try {
          if (rule.condition(features, events)) {
            totalScore += rule.score;
            matchedRules.push({
              id: rule.id,
              name: rule.name,
              severity: rule.severity,
              score: rule.score
            });
            explanation.push(`${rule.name} (${rule.severity}, +${rule.score})`);
          }
        } catch (error) {
          console.error(`Error evaluating rule ${rule.id}:`, error);
        }
      }

      // Normalize score to 0-100
      const normalizedScore = Math.min(totalScore, 100);

      return {
        score: normalizedScore,
        matchedRules,
        explanation,
        ruleCount: matchedRules.length
      };
    } catch (error) {
      console.error('Rule evaluation error:', error);
      return { score: 0, matchedRules: [], explanation: [] };
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

  /**
   * Get rule by ID
   */
  getRule(ruleId) {
    return this.rules.find(r => r.id === ruleId);
  }

  /**
   * Get all rules
   */
  getAllRules() {
    return this.rules.map(r => ({
      id: r.id,
      name: r.name,
      severity: r.severity,
      score: r.score
    }));
  }

  /**
   * Add custom rule
   */
  addRule(rule) {
    if (!rule.id || !rule.name || !rule.condition) {
      throw new Error('Invalid rule: must have id, name, and condition');
    }
    this.rules.push(rule);
    return rule;
  }

  /**
   * Remove rule
   */
  removeRule(ruleId) {
    const index = this.rules.findIndex(r => r.id === ruleId);
    if (index > -1) {
      this.rules.splice(index, 1);
      return true;
    }
    return false;
  }
}

export default new RuleEngine();