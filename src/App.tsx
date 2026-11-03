/**
 * Zero-Trust Network Access (ZTNA) Enterprise Orchestrator
 * Main Application Component
 */

import React, { useState, useEffect } from 'react';
import {
  AttackType,
  DisasterRecoverySnapshot,
  IsolationForestMetrics,
  NetmikoJob,
  SwitchDevice,
  SwitchPort,
  TelemetryVector,
  UserRole
} from './types/network';
import { networkState } from './services/networkState';
import { mlService } from './services/isolationForest';
import { TopBar } from './components/TopBar';
import { KpiMetricsStrip } from './components/KpiMetricsStrip';
import { AttackSimulatorPanel } from './components/AttackSimulatorPanel';
import { FleetTopologyView } from './components/FleetTopologyView';
import { MLThreatDetectorView } from './components/MLThreatDetectorView';
import { NetmikoTerminalView } from './components/NetmikoTerminalView';
import { AuditLogsView } from './components/AuditLogsView';
import { DisasterRecoveryView } from './components/DisasterRecoveryView';
import { ShieldAlert, CheckCircle2, ArrowRight, ExternalLink } from 'lucide-react';

export default function App() {
  const [activeTab, setActiveTab] = useState<string>('overview');
  const [currentRole, setCurrentRole] = useState<UserRole>('SUPER_ADMIN');
  const [switches, setSwitches] = useState<SwitchDevice[]>(networkState.switches);
  const [ports, setPorts] = useState<SwitchPort[]>(networkState.ports);
  const [telemetry, setTelemetry] = useState<TelemetryVector[]>(networkState.telemetryStream);
  const [jobs, setJobs] = useState<NetmikoJob[]>(networkState.netmikoJobs);
  const [logs, setLogs] = useState(networkState.auditLogs);
  const [snapshots, setSnapshots] = useState<DisasterRecoverySnapshot[]>(networkState.snapshots);
  const [metrics, setMetrics] = useState<IsolationForestMetrics>(mlService.metrics);
  const [isSimulating, setIsSimulating] = useState(false);
  const [selectedJobIdForTerminal, setSelectedJobIdForTerminal] = useState<string>('');

  // Active mitigation notification banner
  const [incidentAlert, setIncidentAlert] = useState<{
    attackName: string;
    portName: string;
    switchName: string;
    score: number;
    jobId: string;
  } | null>(null);

  // Sync state helper
  const syncState = () => {
    setSwitches([...networkState.switches]);
    setPorts([...networkState.ports]);
    setTelemetry([...networkState.telemetryStream]);
    setJobs([...networkState.netmikoJobs]);
    setLogs([...networkState.auditLogs]);
    setSnapshots([...networkState.snapshots]);
    setMetrics({ ...mlService.metrics });
  };

  // Periodic normal telemetry background pulse (every 8 seconds)
  useEffect(() => {
    const timer = setInterval(() => {
      networkState.tickNormalTelemetry();
      setTelemetry([...networkState.telemetryStream]);
    }, 8000);
    return () => clearInterval(timer);
  }, []);

  // Ingest manual telemetry pulse
  const handleTickPulse = () => {
    setIsSimulating(true);
    setTimeout(() => {
      networkState.tickNormalTelemetry();
      setTelemetry([...networkState.telemetryStream]);
      setIsSimulating(false);
    }, 300);
  };

  // Trigger simulated attack
  const handleTriggerAttack = (portId: string, attackType: AttackType) => {
    setIsSimulating(true);
    setTimeout(() => {
      try {
        const result = networkState.simulateAttack(portId, attackType);
        syncState();
        setIncidentAlert({
          attackName: result.mitre.name,
          portName: result.quarantinedPort.portName,
          switchName: result.netmikoJob.switchName,
          score: result.telemetry.anomalyScore,
          jobId: result.netmikoJob.id,
        });
      } catch (err) {
        console.error(err);
      } finally {
        setIsSimulating(false);
      }
    }, 400);
  };

  // Restore quarantined port
  const handleRestorePort = (portId: string) => {
    networkState.restorePort(portId);
    syncState();
  };

  // Recalibrate Isolation Forest model
  const handleRecalibrate = () => {
    mlService.calibrateAccuracy();
    setMetrics({ ...mlService.metrics });
  };

  // DR snapshot creation
  const handleCreateSnapshot = (desc: string) => {
    networkState.createSnapshot(desc);
    syncState();
  };

  // DR snapshot rollback drill
  const handleRestoreSnapshot = (snapshotId: string) => {
    networkState.restoreFromSnapshot(snapshotId);
    syncState();
  };

  // Jump to Netmiko view for a specific job
  const handleViewNetmikoJob = (jobId: string) => {
    setSelectedJobIdForTerminal(jobId);
    setActiveTab('netmiko');
  };

  // Change user role
  const handleRoleChange = (role: UserRole) => {
    setCurrentRole(role);
    networkState.currentUserRole = role;
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col antialiased">
      {/* Strict 3-Zone Top Bar */}
      <TopBar
        activeTab={activeTab}
        onTabChange={setActiveTab}
        currentRole={currentRole}
        onRoleChange={handleRoleChange}
        onTickPulse={handleTickPulse}
        isSimulating={isSimulating}
      />

      {/* Real-time Threat Mitigation Banner if triggered */}
      {incidentAlert && (
        <div className="bg-red-950/80 border-b border-red-800/80 px-6 py-2.5 flex items-center justify-between text-xs font-mono">
          <div className="flex items-center gap-3">
            <ShieldAlert className="w-4 h-4 text-red-400 shrink-0" />
            <span className="text-red-200">
              <strong className="text-white uppercase">[THREAT QUARANTINED]</strong> {incidentAlert.attackName} detected on{' '}
              <span className="text-white font-bold">{incidentAlert.switchName} · {incidentAlert.portName}</span> (Score:{' '}
              <span className="text-red-400 font-bold">{incidentAlert.score}</span>). Shifted to Isolation VLAN 99 via Netmiko.
            </span>
          </div>

          <div className="flex items-center gap-3 shrink-0">
            <button
              onClick={() => handleViewNetmikoJob(incidentAlert.jobId)}
              className="text-blue-400 hover:text-blue-300 font-sans flex items-center gap-1"
            >
              <span>Inspect Netmiko Execution</span>
              <ExternalLink className="w-3.5 h-3.5" />
            </button>
            <button
              onClick={() => setIncidentAlert(null)}
              className="text-slate-400 hover:text-slate-200 ml-2"
              aria-label="Dismiss banner"
            >
              ×
            </button>
          </div>
        </div>
      )}

      {/* Main Container - 1440px desktop baseline */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-6 md:p-8">
        {/* Top KPI Metrics Strip (Rendered on every page or overview) */}
        <KpiMetricsStrip
          ports={ports}
          metrics={metrics}
          onNavigateToQuarantine={() => setActiveTab('topology')}
        />

        {/* Tab 1: SOC Overview (Primary Operational Dashboard) */}
        {activeTab === 'overview' && (
          <div className="space-y-6">
            {/* Interactive Attack Simulator Control */}
            <AttackSimulatorPanel
              switches={switches}
              ports={ports}
              onTriggerAttack={handleTriggerAttack}
              userRole={currentRole}
              isSimulating={isSimulating}
            />

            {/* Split Grid: Port Matrix Summary & Recent Netmiko Mitigations */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* Left 2 Cols: Switch Fleet Summary */}
              <div className="lg:col-span-2 space-y-4">
                <div className="flex items-center justify-between">
                  <h3 className="text-sm font-semibold text-slate-100">
                    Switch Fleet Status & 802.1X Port Allocations
                  </h3>
                  <button
                    onClick={() => setActiveTab('topology')}
                    className="text-xs text-blue-400 hover:text-blue-300 flex items-center gap-1 font-sans"
                  >
                    <span>View Full Topology</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </button>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                  {switches.map(sw => {
                    const swPorts = ports.filter(p => p.switchId === sw.id);
                    const quarantined = swPorts.filter(p => p.state === 'QUARANTINED').length;
                    return (
                      <div key={sw.id} className="bg-slate-900/90 border border-slate-800 rounded p-3 font-mono text-xs space-y-2">
                        <div className="flex justify-between items-start">
                          <div>
                            <div className="font-semibold text-slate-100 truncate max-w-[130px]">{sw.name}</div>
                            <div className="text-[10px] text-blue-400 uppercase">{sw.vendor}</div>
                          </div>
                          <span className="text-[10px] text-slate-400">{sw.uptimeDays}d up</span>
                        </div>

                        <div className="flex gap-1 py-1">
                          {swPorts.map(p => (
                            <div
                              key={p.id}
                              title={`${p.portName}: ${p.state} (VLAN ${p.vlan})`}
                              className={`h-4 flex-1 rounded-xs transition-colors ${
                                p.state === 'QUARANTINED'
                                  ? 'bg-red-500'
                                  : 'bg-emerald-600'
                              }`}
                            />
                          ))}
                        </div>

                        <div className="flex justify-between text-[11px] text-slate-400 border-t border-slate-800/80 pt-1.5">
                          <span>Quarantined:</span>
                          <span className={quarantined > 0 ? 'text-red-400 font-bold' : 'text-slate-200'}>
                            {quarantined} / {swPorts.length}
                          </span>
                        </div>
                      </div>
                    );
                  })}
                </div>

                {/* Live Telemetry Log Snippet */}
                <div className="bg-slate-900/90 border border-slate-800 rounded p-4">
                  <div className="flex items-center justify-between mb-3">
                    <h4 className="text-xs font-semibold text-slate-200">
                      Live Statistical Ingress Telemetry (Isolation Forest Evaluator)
                    </h4>
                    <span className="text-[11px] text-slate-400 font-mono">
                      Subsample ψ=256 · Threshold 0.62
                    </span>
                  </div>

                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-xs font-mono">
                      <thead>
                        <tr className="border-b border-slate-800 text-slate-400 text-[10px]">
                          <th className="py-1.5 px-2">Time</th>
                          <th className="py-1.5 px-2">Endpoint</th>
                          <th className="py-1.5 px-2">Entropy</th>
                          <th className="py-1.5 px-2">Jitter</th>
                          <th className="py-1.5 px-2">Score</th>
                          <th className="py-1.5 px-2">Status</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/60 text-slate-300">
                        {telemetry.slice(0, 6).map(t => (
                          <tr key={t.id} className={t.isAnomaly ? 'bg-red-950/20' : ''}>
                            <td className="py-1.5 px-2 text-slate-400">{new Date(t.timestamp).toLocaleTimeString()}</td>
                            <td className="py-1.5 px-2">{t.sourceIp}</td>
                            <td className="py-1.5 px-2 tabular-nums">{t.entropy.toFixed(2)}</td>
                            <td className="py-1.5 px-2 tabular-nums">{t.jitterMs.toFixed(1)}ms</td>
                            <td className="py-1.5 px-2 tabular-nums font-bold">
                              <span className={t.isAnomaly ? 'text-red-400' : 'text-emerald-400'}>
                                {t.anomalyScore.toFixed(3)}
                              </span>
                            </td>
                            <td className="py-1.5 px-2">
                              <span className={t.isAnomaly ? 'text-red-400 font-semibold' : 'text-slate-400'}>
                                {t.isAnomaly ? 'ISOLATED' : 'NOMINAL'}
                              </span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              </div>

              {/* Right 1 Col: Recent Netmiko Mitigations Feed */}
              <div className="bg-slate-900/90 border border-slate-800 rounded p-4 flex flex-col justify-between">
                <div>
                  <div className="flex items-center justify-between border-b border-slate-800 pb-2 mb-3">
                    <h3 className="text-xs font-semibold text-slate-100">
                      Recent Netmiko Automations
                    </h3>
                    <button
                      onClick={() => setActiveTab('netmiko')}
                      className="text-[11px] text-blue-400 hover:underline"
                    >
                      Terminal
                    </button>
                  </div>

                  {jobs.length === 0 ? (
                    <div className="text-xs text-slate-500 py-10 text-center font-mono">
                      No mitigation jobs triggered yet. All 802.1X interfaces nominal.
                    </div>
                  ) : (
                    <div className="space-y-2.5">
                      {jobs.slice(0, 4).map(job => (
                        <div
                          key={job.id}
                          onClick={() => handleViewNetmikoJob(job.id)}
                          className="p-2.5 bg-slate-950 rounded border border-slate-800/80 hover:border-slate-700 cursor-pointer transition-colors text-xs font-mono"
                        >
                          <div className="flex items-center justify-between mb-1">
                            <span className="font-semibold text-slate-200">{job.portName}</span>
                            <span className="text-[10px] text-emerald-400">{job.durationMs}ms</span>
                          </div>
                          <div className="text-[11px] text-slate-400">
                            {job.switchName} ({job.vendor}) → VLAN {job.targetVlan}
                          </div>
                          <div className="text-[10px] text-slate-500 mt-1 truncate">
                            {job.triggeredBy}
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                <div className="mt-4 pt-3 border-t border-slate-800 text-[11px] font-mono text-slate-500 flex justify-between">
                  <span>Disaster Recovery:</span>
                  <span className="text-emerald-400">Golden Baseline Synced</span>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Tab 2: Fleet Topology */}
        {activeTab === 'topology' && (
          <FleetTopologyView
            switches={switches}
            ports={ports}
            onRestorePort={handleRestorePort}
            onSimulateAttack={handleTriggerAttack}
            userRole={currentRole}
            onViewNetmikoJob={handleViewNetmikoJob}
          />
        )}

        {/* Tab 3: ML Threat Detector */}
        {activeTab === 'ml_detector' && (
          <MLThreatDetectorView
            metrics={metrics}
            telemetryStream={telemetry}
            onRecalibrate={handleRecalibrate}
          />
        )}

        {/* Tab 4: Netmiko Terminal */}
        {activeTab === 'netmiko' && (
          <NetmikoTerminalView
            jobs={jobs}
            switches={switches}
            ports={ports}
            activeJobId={selectedJobIdForTerminal}
          />
        )}

        {/* Tab 5: Audit Logs */}
        {activeTab === 'audit' && (
          <AuditLogsView logs={logs} />
        )}

        {/* Tab 6: Disaster Recovery */}
        {activeTab === 'recovery' && (
          <DisasterRecoveryView
            snapshots={snapshots}
            onCreateSnapshot={handleCreateSnapshot}
            onRestoreSnapshot={handleRestoreSnapshot}
            userRole={currentRole}
          />
        )}
      </main>
    </div>
  );
}
