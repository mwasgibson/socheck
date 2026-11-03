/**
 * Zero-Trust Network Access (ZTNA) Architecture Types
 * Enforcing 802.1X/RADIUS, Isolation Forest ML Threat Detection,
 * Multi-Vendor Switch Netmiko Orchestration, and Disaster Recovery.
 */

export type VendorType = 'cisco_ios' | 'juniper_junos' | 'arista_eos';

export type EapMethod = 'EAP-TLS' | 'PEAP-MSCHAPv2' | 'EAP-TTLS';

export type PortState = 'AUTHORIZED' | 'AUTHENTICATING' | 'QUARANTINED' | 'UNAUTHORIZED' | 'DISABLED';

export type AttackType = '8021X_BYPASS' | 'ARP_SPOOF' | 'MAC_CLONE' | 'C2_BEACON';

export type UserRole = 'SUPER_ADMIN' | 'SECOPS_ANALYST' | 'NETWORK_AUDITOR';

export interface MitreTechnique {
  id: string;
  name: string;
  tactic: string;
  description: string;
}

export interface SwitchDevice {
  id: string;
  name: string;
  ip: string;
  vendor: VendorType;
  model: string;
  managementPort: number;
  firmwareVersion: string;
  status: 'ONLINE' | 'DEGRADED' | 'OFFLINE';
  uptimeDays: number;
  location: string;
  totalPorts: number;
  quarantinedPortsCount: number;
}

export interface SwitchPort {
  id: string;
  switchId: string;
  portName: string; // e.g. "Gi1/0/1", "ge-0/0/1", "Ethernet1"
  state: PortState;
  vlan: number;
  normalVlan: number;
  quarantineVlan: number;
  macAddress: string;
  ipAddress: string;
  deviceType: string;
  authMethod: EapMethod;
  eapIdentity: string;
  certThumbprint: string;
  rxPackets: number;
  txPackets: number;
  bytesTransferred: number;
  lastAuthTime: string;
  quarantineTimestamp?: string;
  quarantineReason?: string;
  quarantineJobId?: string;
  aclApplied?: string;
}

export interface TelemetryVector {
  id: string;
  timestamp: string;
  portId: string;
  sourceMac: string;
  sourceIp: string;
  destIp: string;
  destPort: number;
  protocol: 'TCP' | 'UDP' | 'ICMP' | 'EAPOL';
  // 6 Core Features extracted for Isolation Forest
  packetLength: number;       // bytes (e.g. 64 - 1500)
  entropy: number;            // Shannon entropy (0.0 - 8.0)
  synAckRatio: number;        // SYN-to-ACK asymmetry ratio (0.0 - 10.0+)
  jitterMs: number;           // Inter-arrival time variance in ms
  burstVelocity: number;      // Packets per millisecond (1 - 500)
  destDispersion: number;     // Unique destination ports contacted in window
  // Isolation Forest computation results
  anomalyScore: number;       // 0.0 - 1.0 (threshold ~0.60)
  pathLength: number;         // Average isolation tree depth
  isAnomaly: boolean;         // true if score >= threshold
  groundTruth: 'NORMAL' | 'ATTACK';
  attackType?: AttackType;
}

export interface NetmikoJob {
  id: string;
  timestamp: string;
  switchId: string;
  switchName: string;
  vendor: VendorType;
  action: 'QUARANTINE_PORT' | 'RESTORE_PORT' | 'DISASTER_RECOVERY_ROLLBACK';
  portName: string;
  targetVlan: number;
  aclName: string;
  netmikoScript: string;
  terminalOutput: string;
  status: 'SUCCESS' | 'FAILED' | 'EXECUTING';
  durationMs: number;
  triggeredBy: string;
}

export interface AuditLog {
  id: string;
  timestamp: string;
  actor: string;
  role: UserRole;
  action: string;
  category: '802.1X_AUTH' | 'ML_DETECTION' | 'NETMIKO_MITIGATION' | 'DISASTER_RECOVERY' | 'SECURITY_ADMIN';
  severity: 'INFORMATIONAL' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  target: string;
  mitreId?: string;
  details: string;
  checksum: string;
}

export interface DisasterRecoverySnapshot {
  id: string;
  timestamp: string;
  description: string;
  version: string;
  createdBy: string;
  checksum: string;
  encrypted: boolean;
  switchCount: number;
  portCount: number;
  activeQuarantines: number;
  payload: string; // JSON encoded switch & port state
}

export interface IsolationForestMetrics {
  totalEvaluated: number;
  truePositives: number;
  falsePositives: number;
  trueNegatives: number;
  falseNegatives: number;
  precision: number;
  recall: number;
  f1Score: number;
  accuracy: number;
  decisionThreshold: number;
  numberOfTrees: number;
  subsampleSize: number;
}
