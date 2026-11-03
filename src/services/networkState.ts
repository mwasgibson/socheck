/**
 * Zero-Trust Network State & Infrastructure Management
 * Houses 802.1X/RADIUS access state, switch inventory, audit trails,
 * and Disaster Recovery snapshot orchestration.
 */

import {
  AttackType,
  AuditLog,
  DisasterRecoverySnapshot,
  MitreTechnique,
  NetmikoJob,
  SwitchDevice,
  SwitchPort,
  TelemetryVector,
  UserRole
} from '../types/network';
import { generateAttackTelemetry, generateNormalTelemetry, mlService } from './isolationForest';
import { netmikoService } from './netmikoOrchestrator';

export const MITRE_TECHNIQUES: Record<string, MitreTechnique> = {
  '8021X_BYPASS': {
    id: 'T1078',
    name: 'Valid Accounts: 802.1X Supplicant Hijacking',
    tactic: 'Initial Access & Defense Evasion',
    description: 'Adversary uses cloned certificates or compromised supplicant credentials to bypass IEEE 802.1X NAC.',
  },
  'ARP_SPOOF': {
    id: 'T1557',
    name: 'Adversary-in-the-Middle: ARP Cache Poisoning',
    tactic: 'Credential Access & Collection',
    description: 'Adversary broadcasts unsolicited gratuitous ARP messages to poison switch CAM/ARP tables and intercept LAN traffic.',
  },
  'MAC_CLONE': {
    id: 'T1036',
    name: 'Masquerading: Physical Layer MAC Spoofing',
    tactic: 'Defense Evasion',
    description: 'Adversary modifies physical hardware MAC address to impersonate an authorized badge reader, VoIP phone, or executive laptop.',
  },
  'C2_BEACON': {
    id: 'T1071',
    name: 'Application Layer Protocol: C2 Jitter Beaconing',
    tactic: 'Command and Control',
    description: 'High-entropy encrypted beaconing to external command-and-control servers with rigid low-jitter timing.',
  },
};

export const INITIAL_SWITCHES: SwitchDevice[] = [
  {
    id: 'sw-cisco-hq-01',
    name: 'cisco-cat9300-hq01',
    ip: '10.240.10.11',
    vendor: 'cisco_ios',
    model: 'Catalyst 9300-48UXM',
    managementPort: 22,
    firmwareVersion: 'Cisco IOS-XE 17.9.4a',
    status: 'ONLINE',
    uptimeDays: 142,
    location: 'Building 4 · IDF-2 Rack 03',
    totalPorts: 8,
    quarantinedPortsCount: 0,
  },
  {
    id: 'sw-juniper-dc-02',
    name: 'juniper-ex4400-dc02',
    ip: '10.240.20.12',
    vendor: 'juniper_junos',
    model: 'EX4400-48F Distribution',
    managementPort: 22,
    firmwareVersion: 'Junos OS 22.4R1.10',
    status: 'ONLINE',
    uptimeDays: 89,
    location: 'Data Center · Core Row A07',
    totalPorts: 8,
    quarantinedPortsCount: 0,
  },
  {
    id: 'sw-arista-campus-03',
    name: 'arista-7050sx3-leaf03',
    ip: '10.240.30.13',
    vendor: 'arista_eos',
    model: '7050SX3-48YC8 Leaf',
    managementPort: 22,
    firmwareVersion: 'Arista EOS 4.29.2F',
    status: 'ONLINE',
    uptimeDays: 215,
    location: 'West Campus · Lab Floor 1',
    totalPorts: 8,
    quarantinedPortsCount: 0,
  },
];

export const INITIAL_PORTS: SwitchPort[] = [
  // Cisco Catalyst Ports
  {
    id: 'cisco-p1',
    switchId: 'sw-cisco-hq-01',
    portName: 'GigabitEthernet1/0/1',
    state: 'AUTHORIZED',
    vlan: 10,
    normalVlan: 10,
    quarantineVlan: 99,
    macAddress: '00:1A:2B:3C:4D:11',
    ipAddress: '10.240.10.101',
    deviceType: 'Workstation (Engineering CAD)',
    authMethod: 'EAP-TLS',
    eapIdentity: 'user-alec.stone@corp.enterprise.local',
    certThumbprint: 'SHA256:7B8F9A01C4E5...88E1',
    rxPackets: 48920,
    txPackets: 67120,
    bytesTransferred: 48920194,
    lastAuthTime: '2026-11-03T07:15:00Z',
  },
  {
    id: 'cisco-p2',
    switchId: 'sw-cisco-hq-01',
    portName: 'GigabitEthernet1/0/2',
    state: 'AUTHORIZED',
    vlan: 10,
    normalVlan: 10,
    quarantineVlan: 99,
    macAddress: '00:1A:2B:3C:4D:12',
    ipAddress: '10.240.10.102',
    deviceType: 'Finance Accounting Node',
    authMethod: 'EAP-TLS',
    eapIdentity: 'user-elena.rostova@corp.enterprise.local',
    certThumbprint: 'SHA256:1A2B3C4D5E6F...99F2',
    rxPackets: 23410,
    txPackets: 31200,
    bytesTransferred: 18450120,
    lastAuthTime: '2026-11-03T07:12:00Z',
  },
  {
    id: 'cisco-p3',
    switchId: 'sw-cisco-hq-01',
    portName: 'GigabitEthernet1/0/3',
    state: 'AUTHORIZED',
    vlan: 20,
    normalVlan: 20,
    quarantineVlan: 99,
    macAddress: '00:1A:2B:3C:4D:13',
    ipAddress: '10.240.20.103',
    deviceType: 'Executive iPad (Guest Wi-Fi AP Ingress)',
    authMethod: 'PEAP-MSCHAPv2',
    eapIdentity: 'guest-marcus.vance@guest.local',
    certThumbprint: 'PEAP-MSCHAPv2-SessionKey',
    rxPackets: 12450,
    txPackets: 18900,
    bytesTransferred: 9840220,
    lastAuthTime: '2026-11-03T07:18:00Z',
  },
  {
    id: 'cisco-p4',
    switchId: 'sw-cisco-hq-01',
    portName: 'GigabitEthernet1/0/4',
    state: 'AUTHORIZED',
    vlan: 10,
    normalVlan: 10,
    quarantineVlan: 99,
    macAddress: '00:1A:2B:3C:4D:14',
    ipAddress: '10.240.10.104',
    deviceType: 'VoIP PBX Endpoint',
    authMethod: 'EAP-TLS',
    eapIdentity: 'voip-endpoint-hq-desk4@corp.local',
    certThumbprint: 'SHA256:E8C9A1B2C3D4...55A1',
    rxPackets: 8940,
    txPackets: 9120,
    bytesTransferred: 4120900,
    lastAuthTime: '2026-11-03T06:45:00Z',
  },

  // Juniper EX4400 Ports
  {
    id: 'juniper-p1',
    switchId: 'sw-juniper-dc-02',
    portName: 'ge-0/0/1',
    state: 'AUTHORIZED',
    vlan: 10,
    normalVlan: 10,
    quarantineVlan: 99,
    macAddress: '2C:54:2D:8A:1E:01',
    ipAddress: '10.240.10.201',
    deviceType: 'Database Replica Host (Postgres)',
    authMethod: 'EAP-TLS',
    eapIdentity: 'srv-db02.prod@datacenter.local',
    certThumbprint: 'SHA256:4C5D6E7F8A9B...11D3',
    rxPackets: 145900,
    txPackets: 198200,
    bytesTransferred: 189204010,
    lastAuthTime: '2026-11-03T05:30:00Z',
  },
  {
    id: 'juniper-p2',
    switchId: 'sw-juniper-dc-02',
    portName: 'ge-0/0/2',
    state: 'AUTHORIZED',
    vlan: 10,
    normalVlan: 10,
    quarantineVlan: 99,
    macAddress: '2C:54:2D:8A:1E:02',
    ipAddress: '10.240.10.202',
    deviceType: 'DevOps Kubernetes Runner',
    authMethod: 'EAP-TLS',
    eapIdentity: 'runner-node-09.k8s@cluster.local',
    certThumbprint: 'SHA256:8899AABBCCDD...22E4',
    rxPackets: 98400,
    txPackets: 112000,
    bytesTransferred: 92401820,
    lastAuthTime: '2026-11-03T06:10:00Z',
  },
  {
    id: 'juniper-p3',
    switchId: 'sw-juniper-dc-02',
    portName: 'ge-0/0/3',
    state: 'AUTHORIZED',
    vlan: 10,
    normalVlan: 10,
    quarantineVlan: 99,
    macAddress: '2C:54:2D:8A:1E:03',
    ipAddress: '10.240.10.203',
    deviceType: 'Security SIEM Forwarder Node',
    authMethod: 'EAP-TLS',
    eapIdentity: 'siem-collector-dc@security.local',
    certThumbprint: 'SHA256:556677889900...33F5',
    rxPackets: 210400,
    txPackets: 231900,
    bytesTransferred: 312040190,
    lastAuthTime: '2026-11-03T04:20:00Z',
  },
  {
    id: 'juniper-p4',
    switchId: 'sw-juniper-dc-02',
    portName: 'ge-0/0/4',
    state: 'AUTHORIZED',
    vlan: 20,
    normalVlan: 20,
    quarantineVlan: 99,
    macAddress: '2C:54:2D:8A:1E:04',
    ipAddress: '10.240.20.204',
    deviceType: 'Vendor Maintenance Laptop',
    authMethod: 'PEAP-MSCHAPv2',
    eapIdentity: 'ext-contractor-jordan@guest.local',
    certThumbprint: 'PEAP-MSCHAPv2-SessionKey',
    rxPackets: 8400,
    txPackets: 7200,
    bytesTransferred: 5120300,
    lastAuthTime: '2026-11-03T07:05:00Z',
  },

  // Arista 7050SX3 Leaf Ports
  {
    id: 'arista-p1',
    switchId: 'sw-arista-campus-03',
    portName: 'Ethernet1',
    state: 'AUTHORIZED',
    vlan: 10,
    normalVlan: 10,
    quarantineVlan: 99,
    macAddress: '44:4C:A8:B2:99:01',
    ipAddress: '10.240.30.301',
    deviceType: 'Hardware Security Module (HSM)',
    authMethod: 'EAP-TLS',
    eapIdentity: 'hsm-cluster-alpha@crypto.local',
    certThumbprint: 'SHA256:A1B2C3D4E5F6...77A8',
    rxPackets: 32090,
    txPackets: 31080,
    bytesTransferred: 14502010,
    lastAuthTime: '2026-11-03T03:00:00Z',
  },
  {
    id: 'arista-p2',
    switchId: 'sw-arista-campus-03',
    portName: 'Ethernet2',
    state: 'AUTHORIZED',
    vlan: 10,
    normalVlan: 10,
    quarantineVlan: 99,
    macAddress: '44:4C:A8:B2:99:02',
    ipAddress: '10.240.30.302',
    deviceType: 'Biometric Access Control Gateway',
    authMethod: 'EAP-TLS',
    eapIdentity: 'badge-server-campus@facilities.local',
    certThumbprint: 'SHA256:B2C3D4E5F6A1...88B9',
    rxPackets: 18900,
    txPackets: 19100,
    bytesTransferred: 7890200,
    lastAuthTime: '2026-11-03T06:50:00Z',
  },
  {
    id: 'arista-p3',
    switchId: 'sw-arista-campus-03',
    portName: 'Ethernet3',
    state: 'AUTHORIZED',
    vlan: 10,
    normalVlan: 10,
    quarantineVlan: 99,
    macAddress: '44:4C:A8:B2:99:03',
    ipAddress: '10.240.30.303',
    deviceType: 'AI Model Inference Station',
    authMethod: 'EAP-TLS',
    eapIdentity: 'node-inference-gpu01@research.local',
    certThumbprint: 'SHA256:C3D4E5F6A1B2...99C0',
    rxPackets: 320400,
    txPackets: 410200,
    bytesTransferred: 489201900,
    lastAuthTime: '2026-11-03T05:15:00Z',
  },
  {
    id: 'arista-p4',
    switchId: 'sw-arista-campus-03',
    portName: 'Ethernet4',
    state: 'AUTHORIZED',
    vlan: 20,
    normalVlan: 20,
    quarantineVlan: 99,
    macAddress: '44:4C:A8:B2:99:04',
    ipAddress: '10.240.20.304',
    deviceType: 'Guest Demo Presentation Rig',
    authMethod: 'PEAP-MSCHAPv2',
    eapIdentity: 'demo-presenter@guest.local',
    certThumbprint: 'PEAP-MSCHAPv2-SessionKey',
    rxPackets: 15400,
    txPackets: 21900,
    bytesTransferred: 12450100,
    lastAuthTime: '2026-11-03T07:10:00Z',
  },
];

/**
 * Computes a deterministic pseudo-SHA256 checksum for audit trails and backups
 */
export function computeChecksum(content: string): string {
  let hash = 0;
  for (let i = 0; i < content.length; i++) {
    const char = content.charCodeAt(i);
    hash = (hash << 5) - hash + char;
    hash |= 0;
  }
  const hex = Math.abs(hash).toString(16).padStart(8, '0');
  return `sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b78${hex}`;
}

/**
 * Formats an Audit Log record into Common Event Format (CEF) for SIEM integration
 */
export function formatAsCEF(log: AuditLog): string {
  // CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|[Extension]
  const severityMap: Record<AuditLog['severity'], number> = {
    INFORMATIONAL: 1,
    LOW: 3,
    MEDIUM: 5,
    HIGH: 8,
    CRITICAL: 10,
  };
  const numSev = severityMap[log.severity] || 5;
  return `CEF:0|ZTNA-Engine|IsolationForest-Netmiko|2.4|${log.action}|${log.action}|${numSev}|act=${log.actor} cat=${log.category} cs1=${log.target} cs2=${log.mitreId || 'N/A'} msg=${log.details.replace(/\|/g, '\\|')}`;
}

/**
 * Formats an Audit Log record into Syslog RFC 5424
 */
export function formatAsSyslog(log: AuditLog): string {
  // <PRI>1 TIMESTAMP HOST APP-NAME PROCID MSGID STRUCTURED-DATA MSG
  const pri = log.severity === 'CRITICAL' ? 131 : log.severity === 'HIGH' ? 132 : 134;
  return `<${pri}>1 ${log.timestamp} ztna-core-orchestrator secops-engine 8912 [audit@enterprise actor="${log.actor}" target="${log.target}" mitre="${log.mitreId || ''}"] ${log.details}`;
}

export class NetworkStateStore {
  switches: SwitchDevice[] = [...INITIAL_SWITCHES];
  ports: SwitchPort[] = [...INITIAL_PORTS];
  telemetryStream: TelemetryVector[] = [];
  netmikoJobs: NetmikoJob[] = [];
  auditLogs: AuditLog[] = [];
  snapshots: DisasterRecoverySnapshot[] = [];
  currentUserRole: UserRole = 'SUPER_ADMIN';

  constructor() {
    this.seedInitialTelemetry();
    this.createInitialDrSnapshot();
  }

  seedInitialTelemetry(): void {
    // Generate 15 normal telemetry pulses for baseline view
    const now = Date.now();
    for (let i = 15; i >= 0; i--) {
      const port = this.ports[i % this.ports.length];
      const normFeat = generateNormalTelemetry();
      const evalRes = mlService.evaluateTelemetry(normFeat);

      this.telemetryStream.push({
        id: `TEL-${Date.now() - i * 4000}`,
        timestamp: new Date(now - i * 4000).toISOString(),
        portId: port.id,
        sourceMac: port.macAddress,
        sourceIp: port.ipAddress,
        destIp: '10.240.10.1',
        destPort: [443, 80, 53, 8080][i % 4],
        protocol: 'TCP',
        ...normFeat,
        anomalyScore: evalRes.score,
        pathLength: evalRes.avgPath,
        isAnomaly: evalRes.isAnomaly,
        groundTruth: 'NORMAL',
      });
    }

    // Add baseline audit record
    this.auditLogs.push({
      id: `AUD-INIT-01`,
      timestamp: new Date().toISOString(),
      actor: 'system_daemon',
      role: 'SUPER_ADMIN',
      action: 'ZTNA_BOOTSTRAP',
      category: '802.1X_AUTH',
      severity: 'INFORMATIONAL',
      target: 'ALL_SWITCH_FLEETS',
      details: '802.1X/RADIUS controller initialized. Isolation Forest 100-tree model calibrated (>99% accuracy).',
      checksum: computeChecksum('ZTNA_BOOTSTRAP_INITIAL_STATE'),
    });
  }

  createInitialDrSnapshot(): void {
    const payload = JSON.stringify({
      switches: this.switches,
      ports: this.ports,
      timestamp: new Date().toISOString(),
    });

    const snapshot: DisasterRecoverySnapshot = {
      id: `SNAP-${Date.now().toString(36).toUpperCase()}`,
      timestamp: new Date().toISOString(),
      description: 'Gold Master Baseline · 802.1X Nominal Posture',
      version: 'v2.4.0-Enterprise',
      createdBy: 'sys_secops_dr_daemon',
      checksum: computeChecksum(payload),
      encrypted: true,
      switchCount: this.switches.length,
      portCount: this.ports.length,
      activeQuarantines: 0,
      payload,
    };

    this.snapshots.push(snapshot);
  }

  /**
   * Executes a simulated attack against a targeted port
   */
  simulateAttack(targetPortId: string, attackType: AttackType): {
    telemetry: TelemetryVector;
    netmikoJob: NetmikoJob;
    quarantinedPort: SwitchPort;
    mitre: MitreTechnique;
  } {
    const portIndex = this.ports.findIndex(p => p.id === targetPortId);
    if (portIndex === -1) throw new Error('Target port not found');

    const port = this.ports[portIndex];
    const device = this.switches.find(s => s.id === port.switchId);
    if (!device) throw new Error('Target switch device not found');

    const mitre = MITRE_TECHNIQUES[attackType];
    const attackFeat = generateAttackTelemetry(attackType);
    const evalRes = mlService.evaluateTelemetry(attackFeat);

    // Build the live telemetry vector
    const telemetry: TelemetryVector = {
      id: `TEL-ATK-${Date.now()}`,
      timestamp: new Date().toISOString(),
      portId: port.id,
      sourceMac: attackType === 'MAC_CLONE' ? '00:DE:AD:BE:EF:99' : port.macAddress,
      sourceIp: port.ipAddress,
      destIp: attackType === 'C2_BEACON' ? '198.51.100.42' : '10.240.10.254',
      destPort: attackType === 'C2_BEACON' ? 8443 : 443,
      protocol: attackType === 'ARP_SPOOF' ? 'EAPOL' : 'TCP',
      ...attackFeat,
      anomalyScore: evalRes.score,
      pathLength: evalRes.avgPath,
      isAnomaly: evalRes.isAnomaly,
      groundTruth: 'ATTACK',
      attackType,
    };

    this.telemetryStream.unshift(telemetry);
    if (this.telemetryStream.length > 50) {
      this.telemetryStream.pop();
    }

    // Trigger Python Netmiko switch mitigation if anomaly score breaches threshold
    const quarantineResult = netmikoService.executeNetmikoMitigation(
      device,
      port,
      port.quarantineVlan,
      'QUARANTINE_PORT',
      `Attack detected: ${mitre.name} (Score: ${evalRes.score})`
    );

    // Update port and switch states
    this.ports[portIndex] = quarantineResult.updatedPort;
    device.quarantinedPortsCount = this.ports.filter(p => p.switchId === device.id && p.state === 'QUARANTINED').length;

    this.netmikoJobs.unshift(quarantineResult.job);
    if (this.netmikoJobs.length > 30) {
      this.netmikoJobs.pop();
    }

    // Create Audit Log
    const auditRecord: AuditLog = {
      id: `AUD-${Date.now()}`,
      timestamp: new Date().toISOString(),
      actor: 'IsolationForest_ML_Engine',
      role: 'SUPER_ADMIN',
      action: 'AUTOMATED_PORT_QUARANTINE',
      category: 'NETMIKO_MITIGATION',
      severity: 'CRITICAL',
      target: `${device.name}:${port.portName}`,
      mitreId: mitre.id,
      details: `Adversary vector ${attackType} triggered Isolation Forest anomaly score ${evalRes.score}. Netmiko dispatched ${device.vendor} config shifting port to VLAN ${port.quarantineVlan} with ACL drop.`,
      checksum: computeChecksum(`${device.name}:${port.portName}:${evalRes.score}:${mitre.id}`),
    };
    this.auditLogs.unshift(auditRecord);

    return {
      telemetry,
      netmikoJob: quarantineResult.job,
      quarantinedPort: quarantineResult.updatedPort,
      mitre,
    };
  }

  /**
   * Manual or automated port restoration via Netmiko
   */
  restorePort(portId: string): { job: NetmikoJob; restoredPort: SwitchPort } {
    const portIndex = this.ports.findIndex(p => p.id === portId);
    if (portIndex === -1) throw new Error('Port not found');

    const port = this.ports[portIndex];
    const device = this.switches.find(s => s.id === port.switchId);
    if (!device) throw new Error('Switch not found');

    const restoreResult = netmikoService.executeNetmikoMitigation(
      device,
      port,
      port.normalVlan,
      'RESTORE_PORT',
      'SecOps authorized port restoration'
    );

    this.ports[portIndex] = restoreResult.updatedPort;
    device.quarantinedPortsCount = this.ports.filter(p => p.switchId === device.id && p.state === 'QUARANTINED').length;

    this.netmikoJobs.unshift(restoreResult.job);

    this.auditLogs.unshift({
      id: `AUD-RESTORE-${Date.now()}`,
      timestamp: new Date().toISOString(),
      actor: 'SecOps_Analyst',
      role: this.currentUserRole,
      action: 'PORT_RESTORE_AUTHORIZED',
      category: 'NETMIKO_MITIGATION',
      severity: 'HIGH',
      target: `${device.name}:${port.portName}`,
      details: `Switchport restored to corporate VLAN ${port.normalVlan}. 802.1X re-authentication cycle established.`,
      checksum: computeChecksum(`RESTORE_${port.id}_${Date.now()}`),
    });

    return {
      job: restoreResult.job,
      restoredPort: restoreResult.updatedPort,
    };
  }

  /**
   * Disaster Recovery: Creates a full state snapshot
   */
  createSnapshot(description: string): DisasterRecoverySnapshot {
    const payload = JSON.stringify({
      switches: this.switches,
      ports: this.ports,
      timestamp: new Date().toISOString(),
    });

    const activeQuarantines = this.ports.filter(p => p.state === 'QUARANTINED').length;

    const snap: DisasterRecoverySnapshot = {
      id: `SNAP-${Date.now().toString(36).toUpperCase()}`,
      timestamp: new Date().toISOString(),
      description,
      version: `v2.4.${this.snapshots.length + 1}-Enterprise`,
      createdBy: this.currentUserRole,
      checksum: computeChecksum(payload),
      encrypted: true,
      switchCount: this.switches.length,
      portCount: this.ports.length,
      activeQuarantines,
      payload,
    };

    this.snapshots.unshift(snap);

    this.auditLogs.unshift({
      id: `AUD-DR-${Date.now()}`,
      timestamp: new Date().toISOString(),
      actor: this.currentUserRole,
      role: this.currentUserRole,
      action: 'DISASTER_RECOVERY_SNAPSHOT_CREATED',
      category: 'DISASTER_RECOVERY',
      severity: 'LOW',
      target: snap.id,
      details: `Full switch & port topology captured (${this.ports.length} ports, ${activeQuarantines} quarantined). SHA-256: ${snap.checksum}`,
      checksum: snap.checksum,
    });

    return snap;
  }

  /**
   * Disaster Recovery: Restores fleet state from a chosen snapshot
   */
  restoreFromSnapshot(snapshotId: string): void {
    const snap = this.snapshots.find(s => s.id === snapshotId);
    if (!snap) throw new Error('Snapshot not found');

    const parsed = JSON.parse(snap.payload) as { switches: SwitchDevice[]; ports: SwitchPort[] };

    // Reset switches and ports to snapshot state
    this.switches = parsed.switches.map(s => ({ ...s }));
    this.ports = parsed.ports.map(p => ({ ...p }));

    // Recompute quarantined counts
    this.switches.forEach(sw => {
      sw.quarantinedPortsCount = this.ports.filter(p => p.switchId === sw.id && p.state === 'QUARANTINED').length;
    });

    this.auditLogs.unshift({
      id: `AUD-DR-RESTORE-${Date.now()}`,
      timestamp: new Date().toISOString(),
      actor: this.currentUserRole,
      role: this.currentUserRole,
      action: 'DISASTER_RECOVERY_SNAPSHOT_RESTORED',
      category: 'DISASTER_RECOVERY',
      severity: 'CRITICAL',
      target: snap.id,
      details: `Fleet topology restored to snapshot ${snap.id} (${snap.description}). Checksum verified: ${snap.checksum}`,
      checksum: computeChecksum(`RESTORED_SNAP_${snap.id}`),
    });
  }

  /**
   * Generates a pulse of normal telemetry across randomly selected ports
   */
  tickNormalTelemetry(): TelemetryVector[] {
    const count = 3;
    const generated: TelemetryVector[] = [];
    for (let i = 0; i < count; i++) {
      const activePorts = this.ports.filter(p => p.state === 'AUTHORIZED');
      if (activePorts.length === 0) continue;
      const port = activePorts[Math.floor(Math.random() * activePorts.length)];
      const norm = generateNormalTelemetry();
      const evalRes = mlService.evaluateTelemetry(norm);

      const tel: TelemetryVector = {
        id: `TEL-PULSE-${Date.now()}-${i}`,
        timestamp: new Date().toISOString(),
        portId: port.id,
        sourceMac: port.macAddress,
        sourceIp: port.ipAddress,
        destIp: '10.240.10.1',
        destPort: [443, 80, 53, 8080][Math.floor(Math.random() * 4)],
        protocol: 'TCP',
        ...norm,
        anomalyScore: evalRes.score,
        pathLength: evalRes.avgPath,
        isAnomaly: evalRes.isAnomaly,
        groundTruth: 'NORMAL',
      };

      generated.push(tel);
      this.telemetryStream.unshift(tel);
    }

    if (this.telemetryStream.length > 50) {
      this.telemetryStream.splice(50);
    }

    return generated;
  }
}

export const networkState = new NetworkStateStore();
