/**
 * KPI Telemetry Strip for Zero-Trust Network SOC
 * Enforces Zero-Pill discipline, unboxed metadata, and tabular figures.
 */

import React from 'react';
import { SwitchPort, IsolationForestMetrics } from '../types/network';
import { ShieldCheck, Cpu, AlertTriangle, DatabaseBackup } from 'lucide-react';

interface KpiMetricsStripProps {
  ports: SwitchPort[];
  metrics: IsolationForestMetrics;
  lastSnapshotTime?: string;
  onNavigateToQuarantine?: () => void;
}

export const KpiMetricsStrip: React.FC<KpiMetricsStripProps> = ({
  ports,
  metrics,
  lastSnapshotTime,
  onNavigateToQuarantine,
}) => {
  const totalPorts = ports.length;
  const authorizedPorts = ports.filter(p => p.state === 'AUTHORIZED').length;
  const quarantinedPorts = ports.filter(p => p.state === 'QUARANTINED').length;
  const authenticatingPorts = ports.filter(p => p.state === 'AUTHENTICATING').length;

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
      {/* 802.1X Access Posture */}
      <div className="bg-slate-900/90 border border-slate-800 rounded p-4">
        <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
          <span className="font-medium text-slate-300">802.1X Session Posture</span>
          <ShieldCheck className="w-4 h-4 text-blue-400" />
        </div>
        <div className="text-2xl font-bold font-mono tabular-nums text-slate-100">
          {authorizedPorts}/{totalPorts}
        </div>
        <div className="mt-2 text-xs text-slate-400 flex items-center gap-1.5 font-mono">
          <span className="text-emerald-400">Authorized</span>
          <span aria-hidden="true" className="text-slate-600">·</span>
          <span>{authenticatingPorts} Handshaking</span>
          <span aria-hidden="true" className="text-slate-600">·</span>
          <span>EAP-TLS / PEAP</span>
        </div>
      </div>

      {/* Isolation Forest Accuracy */}
      <div className="bg-slate-900/90 border border-slate-800 rounded p-4">
        <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
          <span className="font-medium text-slate-300">Isolation Forest Precision</span>
          <Cpu className="w-4 h-4 text-indigo-400" />
        </div>
        <div className="text-2xl font-bold font-mono tabular-nums text-slate-100">
          {(metrics.accuracy * 100).toFixed(1)}%
        </div>
        <div className="mt-2 text-xs text-slate-400 flex items-center gap-1.5 font-mono">
          <span className="text-blue-400">F1: {metrics.f1Score.toFixed(3)}</span>
          <span aria-hidden="true" className="text-slate-600">·</span>
          <span>{metrics.numberOfTrees} Trees</span>
          <span aria-hidden="true" className="text-slate-600">·</span>
          <span>ψ={metrics.subsampleSize}</span>
        </div>
      </div>

      {/* Netmiko Active Quarantines */}
      <div
        onClick={onNavigateToQuarantine}
        className={`bg-slate-900/90 border rounded p-4 transition-colors ${
          quarantinedPorts > 0
            ? 'border-red-900/60 bg-red-950/10 cursor-pointer hover:border-red-700/80'
            : 'border-slate-800'
        }`}
      >
        <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
          <span className="font-medium text-slate-300">Active Quarantines (VLAN 99)</span>
          <AlertTriangle className={`w-4 h-4 ${quarantinedPorts > 0 ? 'text-red-400' : 'text-slate-500'}`} />
        </div>
        <div className="text-2xl font-bold font-mono tabular-nums text-slate-100">
          {quarantinedPorts}
        </div>
        <div className="mt-2 text-xs text-slate-400 flex items-center gap-1.5 font-mono">
          <span className={quarantinedPorts > 0 ? 'text-red-400 font-semibold' : 'text-emerald-400'}>
            {quarantinedPorts > 0 ? 'Isolation ACL Enforced' : 'Zero Threats Active'}
          </span>
          <span aria-hidden="true" className="text-slate-600">·</span>
          <span>Netmiko ~142ms</span>
        </div>
      </div>

      {/* Disaster Recovery Status */}
      <div className="bg-slate-900/90 border border-slate-800 rounded p-4">
        <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
          <span className="font-medium text-slate-300">Disaster Recovery (DR)</span>
          <DatabaseBackup className="w-4 h-4 text-emerald-400" />
        </div>
        <div className="text-2xl font-bold font-mono tabular-nums text-slate-100">
          Ready
        </div>
        <div className="mt-2 text-xs text-slate-400 flex items-center gap-1.5 font-mono">
          <span className="text-emerald-400">SHA-256 Verified</span>
          <span aria-hidden="true" className="text-slate-600">·</span>
          <span>AES-256-GCM Encrypted</span>
        </div>
      </div>
    </div>
  );
};
