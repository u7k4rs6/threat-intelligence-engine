import { v4 as uuidv4 } from 'uuid';

class DataNormalizer {
  /**
   * Normalize raw event data into standardized schema
   */
  normalizeEvent(rawEvent) {
    const normalized = {
      id: uuidv4(),
      indicator_type: this.detectIndicatorType(rawEvent),
      indicator_value: this.extractIndicatorValue(rawEvent),
      event_type: this.normalizeEventType(rawEvent.event_type || rawEvent.type),
      timestamp: this.normalizeTimestamp(rawEvent.timestamp || rawEvent.time),
      source: rawEvent.source || 'unknown',
      metadata: this.extractMetadata(rawEvent)
    };

    return normalized;
  }

  detectIndicatorType(event) {
    if (event.indicator_type) return event.indicator_type;
    if (event.ip || this.isIPAddress(event.value)) return 'IP';
    if (event.domain || this.isDomain(event.value)) return 'domain';
    if (event.hash || this.isHash(event.value)) return 'hash';
    if (event.user || event.username) return 'user';
    if (event.file) return 'file';
    return 'unknown';
  }

  extractIndicatorValue(event) {
    return event.indicator_value || 
           event.value || 
           event.ip || 
           event.domain || 
           event.hash || 
           event.user || 
           event.username ||
           event.file ||
           'unknown';
  }

  normalizeEventType(type) {
    const eventTypeMap = {
      'failed_login': 'failed_login',
      'login_failure': 'failed_login',
      'authentication_failure': 'failed_login',
      'successful_login': 'successful_login',
      'login_success': 'successful_login',
      'port_scan': 'port_scan',
      'scan': 'port_scan',
      'dns_query': 'dns_query',
      'dns': 'dns_query',
      'http_request': 'http_request',
      'web_request': 'http_request',
      'file_download': 'file_download',
      'download': 'file_download',
      'malware_detected': 'malware_detected',
      'virus': 'malware_detected',
      'data_exfiltration': 'data_exfiltration',
      'exfil': 'data_exfiltration',
      'c2_communication': 'c2_communication',
      'command_control': 'c2_communication',
      'privilege_escalation': 'privilege_escalation',
      'script_execution': 'script_execution'
    };

    return eventTypeMap[type?.toLowerCase()] || type || 'unknown';
  }

  normalizeTimestamp(timestamp) {
    if (!timestamp) return new Date().toISOString();
    
    try {
      const date = new Date(timestamp);
      return date.toISOString();
    } catch (error) {
      return new Date().toISOString();
    }
  }

  extractMetadata(rawEvent) {
    const metadata = {
      port: rawEvent.port || rawEvent.destination_port || null,
      geo: rawEvent.geo || rawEvent.country || rawEvent.geo_location || null,
      attempts: rawEvent.attempts || rawEvent.count || 1,
      protocol: rawEvent.protocol || null,
      user_agent: rawEvent.user_agent || null,
      payload_size: rawEvent.payload_size || rawEvent.bytes || null,
      severity: rawEvent.severity || null,
      confidence: rawEvent.confidence || 0.5
    };

    // Remove null values
    return Object.fromEntries(
      Object.entries(metadata).filter(([_, v]) => v !== null)
    );
  }

  isIPAddress(value) {
    const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
    const ipv6Regex = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
    return ipv4Regex.test(value) || ipv6Regex.test(value);
  }

  isDomain(value) {
    const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?\.[a-zA-Z]{2,}$/;
    return domainRegex.test(value);
  }

  isHash(value) {
    // MD5: 32 chars, SHA1: 40 chars, SHA256: 64 chars
    return /^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/.test(value);
  }

  /**
   * Batch normalize multiple events
   */
  normalizeEvents(rawEvents) {
    if (!Array.isArray(rawEvents)) {
      return [this.normalizeEvent(rawEvents)];
    }
    return rawEvents.map(event => this.normalizeEvent(event));
  }
}

export default new DataNormalizer();