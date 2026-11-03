/**
 * Isolation Forest (iForest) Anomaly Detection Engine
 * Genuine mathematical implementation based on Liu, Ting & Zhou (2008).
 * Calibrated for Zero-Trust network traffic telemetry and attack pattern identification.
 */

import { AttackType, IsolationForestMetrics, TelemetryVector } from '../types/network';

export interface FeatureVector {
  packetLength: number;    // bytes (40 - 1500)
  entropy: number;         // Shannon entropy (0.0 - 8.0)
  synAckRatio: number;     // SYN / ACK imbalance (0.0 - 12.0)
  jitterMs: number;        // Inter-arrival variance (0 - 500ms)
  burstVelocity: number;   // Packets per millisecond (1 - 500)
  destDispersion: number;  // Destination port divergence count (1 - 100)
}

interface TreeNode {
  isLeaf: boolean;
  size: number;
  splitFeature?: number;
  splitValue?: number;
  left?: TreeNode;
  right?: TreeNode;
}

export class IsolationTree {
  root: TreeNode;
  maxHeight: number;

  constructor(maxHeight: number) {
    this.maxHeight = maxHeight;
    this.root = { isLeaf: true, size: 0 };
  }

  fit(data: number[][], currentHeight = 0): TreeNode {
    const n = data.length;
    if (currentHeight >= this.maxHeight || n <= 1) {
      return { isLeaf: true, size: n };
    }

    const numFeatures = data[0].length;
    // Choose a random feature that has varying values
    const featureIndices = Array.from({ length: numFeatures }, (_, i) => i)
      .sort(() => Math.random() - 0.5);

    let selectedFeature = -1;
    let minVal = 0;
    let maxVal = 0;

    for (const f of featureIndices) {
      let min = Infinity;
      let max = -Infinity;
      for (let i = 0; i < n; i++) {
        const val = data[i][f];
        if (val < min) min = val;
        if (val > max) max = val;
      }
      if (max > min) {
        selectedFeature = f;
        minVal = min;
        maxVal = max;
        break;
      }
    }

    if (selectedFeature === -1) {
      return { isLeaf: true, size: n };
    }

    // Uniform random split value between min and max
    const splitValue = minVal + Math.random() * (maxVal - minVal);

    const leftData: number[][] = [];
    const rightData: number[][] = [];

    for (let i = 0; i < n; i++) {
      if (data[i][selectedFeature] < splitValue) {
        leftData.push(data[i]);
      } else {
        rightData.push(data[i]);
      }
    }

    return {
      isLeaf: false,
      size: n,
      splitFeature: selectedFeature,
      splitValue,
      left: this.fit(leftData, currentHeight + 1),
      right: this.fit(rightData, currentHeight + 1),
    };
  }

  pathLength(point: number[], node: TreeNode, currentDepth = 0): number {
    if (node.isLeaf || !node.left || !node.right || node.splitFeature === undefined || node.splitValue === undefined) {
      return currentDepth + IsolationForest.c(node.size);
    }

    if (point[node.splitFeature] < node.splitValue) {
      return this.pathLength(point, node.left, currentDepth + 1);
    } else {
      return this.pathLength(point, node.right, currentDepth + 1);
    }
  }
}

export class IsolationForest {
  trees: IsolationTree[] = [];
  numTrees: number;
  subsampleSize: number;
  maxHeight: number;
  threshold: number;
  isTrained = false;

  constructor(numTrees = 100, subsampleSize = 256, threshold = 0.62) {
    this.numTrees = numTrees;
    this.subsampleSize = subsampleSize;
    this.maxHeight = Math.ceil(Math.log2(Math.max(subsampleSize, 2)));
    this.threshold = threshold;
  }

  /**
   * Average path length of unsuccessful search in a Binary Search Tree (BST)
   * Euler-Mascheroni constant = 0.5772156649
   */
  static c(n: number): number {
    if (n <= 1) return 0;
    if (n === 2) return 1;
    const euler = 0.5772156649;
    return 2 * (Math.log(n - 1) + euler) - (2 * (n - 1)) / n;
  }

  fit(data: number[][]): void {
    this.trees = [];
    const n = data.length;
    const sampleSize = Math.min(this.subsampleSize, n);

    for (let i = 0; i < this.numTrees; i++) {
      // Subsample without replacement
      const sampleIndices = new Set<number>();
      while (sampleIndices.size < sampleSize) {
        sampleIndices.add(Math.floor(Math.random() * n));
      }

      const sample = Array.from(sampleIndices).map(idx => data[idx]);
      const tree = new IsolationTree(this.maxHeight);
      tree.root = tree.fit(sample);
      this.trees.push(tree);
    }

    this.isTrained = true;
  }

  predictScore(point: number[]): { score: number; avgPath: number } {
    if (!this.isTrained || this.trees.length === 0) {
      return { score: 0.5, avgPath: this.maxHeight };
    }

    let totalPath = 0;
    for (const tree of this.trees) {
      totalPath += tree.pathLength(point, tree.root);
    }

    const avgPath = totalPath / this.trees.length;
    const cFactor = IsolationForest.c(this.subsampleSize);
    // Anomaly score formula: s(x, n) = 2^(-E(h(x)) / c(n))
    const score = Math.pow(2, -avgPath / (cFactor > 0 ? cFactor : 1));

    return {
      score: Math.min(Math.max(score, 0.0), 1.0),
      avgPath,
    };
  }

  isAnomaly(point: number[]): boolean {
    return this.predictScore(point).score >= this.threshold;
  }
}

/**
 * Normalizes raw network metrics into a standard numerical array for iForest
 */
export function featureVectorToArray(features: FeatureVector): number[] {
  return [
    features.packetLength,
    features.entropy,
    features.synAckRatio,
    features.jitterMs,
    features.burstVelocity,
    features.destDispersion,
  ];
}

/**
 * Generate baseline normal corporate network telemetry (VLAN 10/20 users)
 */
export function generateNormalTelemetry(): FeatureVector {
  // Gaussian-like distributions for typical web, email, internal service traffic
  const randNorm = (mean: number, std: number) => {
    const u1 = Math.random();
    const u2 = Math.random();
    const z = Math.sqrt(-2.0 * Math.log(u1 || 0.0001)) * Math.cos(2.0 * Math.PI * u2);
    return Math.max(0, mean + z * std);
  };

  return {
    packetLength: Math.round(Math.min(1500, Math.max(64, randNorm(580, 220)))),
    entropy: Math.min(7.2, Math.max(3.2, randNorm(5.1, 0.6))),
    synAckRatio: Math.min(2.2, Math.max(0.6, randNorm(1.05, 0.18))), // Balanced TCP handshakes
    jitterMs: Math.min(180, Math.max(12, randNorm(45, 18))),          // Typical user human jitter
    burstVelocity: Math.min(65, Math.max(2, randNorm(14, 8))),       // Reasonable packet rate
    destDispersion: Math.min(15, Math.max(1, Math.round(randNorm(4, 2)))), // Contacts 1-6 internal services
  };
}

/**
 * Generate targeted attack vectors mapped to MITRE ATT&CK
 */
export function generateAttackTelemetry(type: AttackType): FeatureVector {
  switch (type) {
    case '8021X_BYPASS':
      // MITRE T1078 - EAP-TLS / Supplicant session hijack or credential manipulation
      // Rigid packet timing, abnormal non-human entropy on control channels, severe SYN/ACK asymmetry
      return {
        packetLength: 980 + Math.random() * 480,
        entropy: 7.78 + Math.random() * 0.18,      // High encrypted payload packing
        synAckRatio: 6.4 + Math.random() * 3.8,     // Severe handshake anomalies
        jitterMs: 0.8 + Math.random() * 1.5,       // Machine scripted precision jitter
        burstVelocity: 140 + Math.random() * 80,    // High authentication storm
        destDispersion: 18 + Math.random() * 14,
      };

    case 'ARP_SPOOF':
      // MITRE T1557 - Adversary-in-the-Middle gratuitous ARP cache poisoning
      // Floods subnet with rapid small packets, zero normal TCP handshake, high broadcast velocity
      return {
        packetLength: 64 + Math.random() * 28,     // Fixed small ARP frames
        entropy: 1.4 + Math.random() * 0.8,        // Low entropy repetitive Ethernet headers
        synAckRatio: 0.05 + Math.random() * 0.1,   // No normal TCP completion
        jitterMs: 0.2 + Math.random() * 0.6,       // Microsecond burst interval
        burstVelocity: 360 + Math.random() * 120,  // Massive packet storm
        destDispersion: 45 + Math.random() * 35,   // Probing every host on VLAN
      };

    case 'MAC_CLONE':
      // MITRE T1036 - Masquerading cloned physical adapter
      // Alternating switchport flappings, high collision burst, abnormal dispersion
      return {
        packetLength: 420 + Math.random() * 600,
        entropy: 6.9 + Math.random() * 0.8,
        synAckRatio: 4.8 + Math.random() * 2.5,
        jitterMs: 2.1 + Math.random() * 3.5,
        burstVelocity: 210 + Math.random() * 70,
        destDispersion: 62 + Math.random() * 25,
      };

    case 'C2_BEACON':
      // MITRE T1071 - Application Layer Command & Control beaconing
      // Rigid periodicity (zero variance jitter), constant encrypted length, distinct entropy signature
      return {
        packetLength: 512 + Math.random() * 12,    // Fixed payload envelope
        entropy: 7.92 + Math.random() * 0.06,      // Maximum AES-CBC/GCM payload randomness
        synAckRatio: 1.0 + Math.random() * 0.1,
        jitterMs: 0.1 + Math.random() * 0.3,       // Ultra-rigid periodic pulse
        burstVelocity: 85 + Math.random() * 25,
        destDispersion: 2 + Math.random() * 2,     // Hardcoded single C2 IP
      };
  }
}

/**
 * Singleton ML service managing training, evaluations, and accuracy validation
 */
class MLService {
  model: IsolationForest;
  metrics: IsolationForestMetrics;

  constructor() {
    this.model = new IsolationForest(100, 256, 0.62);
    this.metrics = {
      totalEvaluated: 0,
      truePositives: 0,
      falsePositives: 0,
      trueNegatives: 0,
      falseNegatives: 0,
      precision: 0.992,
      recall: 0.995,
      f1Score: 0.993,
      accuracy: 0.994,
      decisionThreshold: 0.62,
      numberOfTrees: 100,
      subsampleSize: 256,
    };
    this.trainModel();
  }

  trainModel(): void {
    const trainingData: number[][] = [];
    // Generate 1200 normal samples for baseline training
    for (let i = 0; i < 1200; i++) {
      trainingData.push(featureVectorToArray(generateNormalTelemetry()));
    }
    this.model.fit(trainingData);
    this.calibrateAccuracy();
  }

  calibrateAccuracy(): void {
    // Run an empirical validation of 1000 mixed samples (800 normal + 200 attacks)
    let tp = 0;
    let fp = 0;
    let tn = 0;
    let fn = 0;

    // Normal samples
    for (let i = 0; i < 800; i++) {
      const feat = generateNormalTelemetry();
      const arr = featureVectorToArray(feat);
      const isAnomaly = this.model.isAnomaly(arr);
      if (isAnomaly) {
        fp++;
      } else {
        tn++;
      }
    }

    // Attack samples across all 4 MITRE vectors
    const attackTypes: AttackType[] = ['8021X_BYPASS', 'ARP_SPOOF', 'MAC_CLONE', 'C2_BEACON'];
    for (let i = 0; i < 200; i++) {
      const type = attackTypes[i % attackTypes.length];
      const feat = generateAttackTelemetry(type);
      const arr = featureVectorToArray(feat);
      const isAnomaly = this.model.isAnomaly(arr);
      if (isAnomaly) {
        tp++;
      } else {
        fn++;
      }
    }

    const total = tp + fp + tn + fn;
    const precision = tp / (tp + fp || 1);
    const recall = tp / (tp + fn || 1);
    const accuracy = (tp + tn) / total;
    const f1Score = (2 * (precision * recall)) / (precision + recall || 1);

    this.metrics = {
      totalEvaluated: total,
      truePositives: tp,
      falsePositives: fp,
      trueNegatives: tn,
      falseNegatives: fn,
      precision: Math.round(precision * 1000) / 1000,
      recall: Math.round(recall * 1000) / 1000,
      f1Score: Math.round(f1Score * 1000) / 1000,
      accuracy: Math.round(accuracy * 1000) / 1000,
      decisionThreshold: this.model.threshold,
      numberOfTrees: this.model.numTrees,
      subsampleSize: this.model.subsampleSize,
    };
  }

  evaluateTelemetry(vector: FeatureVector): { score: number; isAnomaly: boolean; avgPath: number } {
    const arr = featureVectorToArray(vector);
    const { score, avgPath } = this.model.predictScore(arr);
    return {
      score: Math.round(score * 1000) / 1000,
      isAnomaly: score >= this.model.threshold,
      avgPath: Math.round(avgPath * 10) / 10,
    };
  }
}

export const mlService = new MLService();
