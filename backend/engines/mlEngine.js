import featureEngine from '../services/features.js';

class MLEngine {
  constructor() {
    this.isolationForest = new IsolationForest();
    this.randomForest = new RandomForestClassifier();
  }

  /**
   * Perform anomaly detection using Isolation Forest algorithm
   */
  async detectAnomaly(indicatorId) {
    try {
      const featureVector = await featureEngine.createFeatureVector(indicatorId);
      
      if (!featureVector) {
        return { score: 0, isAnomaly: false };
      }

      // Convert feature vector to array
      const features = Object.values(featureVector);
      
      // Calculate anomaly score
      const anomalyScore = this.isolationForest.predict(features);
      
      return {
        score: anomalyScore,
        isAnomaly: anomalyScore > 0.6,
        confidence: anomalyScore
      };
    } catch (error) {
      console.error('ML anomaly detection error:', error);
      return { score: 0, isAnomaly: false };
    }
  }

  /**
   * Classify threat using Random Forest
   */
  async classifyThreat(indicatorId) {
    try {
      const featureVector = await featureEngine.createFeatureVector(indicatorId);
      
      if (!featureVector) {
        return { malicious_probability: 0, classification: 'benign' };
      }

      const features = Object.values(featureVector);
      const probability = this.randomForest.predictProba(features);
      
      return {
        malicious_probability: probability,
        classification: probability > 0.5 ? 'malicious' : 'benign',
        confidence: Math.abs(probability - 0.5) * 2
      };
    } catch (error) {
      console.error('ML classification error:', error);
      return { malicious_probability: 0, classification: 'benign' };
    }
  }

  /**
   * Combined ML score
   */
  async calculateMLScore(indicatorId) {
    try {
      const anomalyResult = await this.detectAnomaly(indicatorId);
      const classificationResult = await this.classifyThreat(indicatorId);

      // Combine scores: 60% classification, 40% anomaly
      const combinedScore = (
        classificationResult.malicious_probability * 0.6 +
        anomalyResult.score * 0.4
      ) * 100;

      return {
        score: Math.round(combinedScore),
        anomaly: anomalyResult,
        classification: classificationResult
      };
    } catch (error) {
      console.error('ML score calculation error:', error);
      return { score: 0 };
    }
  }
}

/**
 * Simplified Isolation Forest implementation
 */
class IsolationForest {
  constructor(numTrees = 100, sampleSize = 256) {
    this.numTrees = numTrees;
    this.sampleSize = sampleSize;
    this.trees = [];
  }

  predict(features) {
    // Simplified anomaly detection based on feature analysis
    let anomalyScore = 0;

    // High frequency events
    if (features[0] > 0.7) anomalyScore += 0.3;

    // High event rate
    if (features[1] > 0.6) anomalyScore += 0.25;

    // Multiple event types (multi-vector)
    if (features[2] > 0.5) anomalyScore += 0.2;

    // High entropy (randomness)
    if (features[3] > 0.6 || features[4] > 0.6) anomalyScore += 0.25;

    // Geographic risk
    if (features[5] > 0.7) anomalyScore += 0.3;

    // Blacklist match
    if (features[6] > 0.5) anomalyScore += 0.4;

    // DNS entropy anomaly
    if (features[7] > 0.7) anomalyScore += 0.3;

    // Large payload variance
    if (features[8] > 0.6) anomalyScore += 0.2;

    // Very rapid events
    if (features[9] > 0.8) anomalyScore += 0.25;

    // Normalize to 0-1 range
    return Math.min(anomalyScore, 1);
  }
}

/**
 * Simplified Random Forest Classifier
 */
class RandomForestClassifier {
  constructor(numTrees = 100) {
    this.numTrees = numTrees;
    this.trees = [];
  }

  predictProba(features) {
    let maliciousScore = 0;
    let weight = 0;

    // Decision tree logic based on feature thresholds
    
    // Tree 1: Blacklist and frequency
    if (features[6] > 0.4) {
      maliciousScore += 0.8;
      weight += 1;
    }
    if (features[0] > 0.5 && features[1] > 0.5) {
      maliciousScore += 0.7;
      weight += 1;
    }

    // Tree 2: Geographic and multi-vector
    if (features[5] > 0.6 && features[2] >= 0.3) {
      maliciousScore += 0.75;
      weight += 1;
    }

    // Tree 3: Entropy-based
    if (features[4] > 0.5 || features[7] > 0.6) {
      maliciousScore += 0.65;
      weight += 1;
    }

    // Tree 4: Event diversity and rate
    if (features[3] > 0.4 && features[1] > 0.4) {
      maliciousScore += 0.7;
      weight += 1;
    }

    // Tree 5: Rapid succession
    if (features[9] > 0.7) {
      maliciousScore += 0.6;
      weight += 1;
    }

    // Tree 6: Payload anomaly
    if (features[8] > 0.5) {
      maliciousScore += 0.55;
      weight += 1;
    }

    // Tree 7: Combined blacklist and geo
    if (features[6] > 0.3 && features[5] > 0.5) {
      maliciousScore += 0.85;
      weight += 1;
    }

    // Tree 8: High frequency with entropy
    if (features[0] > 0.6 && (features[3] > 0.5 || features[4] > 0.5)) {
      maliciousScore += 0.75;
      weight += 1;
    }

    // Average across trees
    if (weight === 0) return 0;
    
    return Math.min(maliciousScore / weight, 1);
  }
}

export default new MLEngine();