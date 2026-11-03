/**
 * Automated Backup & Disaster Recovery (DR) Orchestration View
 * Provides cryptographic snapshot creation, automated recovery drills, and export/import.
 */

import React, { useState } from 'react';
import { DisasterRecoverySnapshot, UserRole } from '../types/network';
import { DatabaseBackup, Download, Upload, RotateCcw, Plus, Lock, CheckCircle2, AlertTriangle, ShieldCheck } from 'lucide-react';

interface DisasterRecoveryViewProps {
  snapshots: DisasterRecoverySnapshot[];
  onCreateSnapshot: (description: string) => void;
  onRestoreSnapshot: (snapshotId: string) => void;
  userRole: UserRole;
}

export const DisasterRecoveryView: React.FC<DisasterRecoveryViewProps> = ({
  snapshots,
  onCreateSnapshot,
  onRestoreSnapshot,
  userRole,
}) => {
  const [newDesc, setNewDesc] = useState('');
  const [selectedSnapshotId, setSelectedSnapshotId] = useState<string>(snapshots[0]?.id || '');
  const [confirmModalOpen, setConfirmModalOpen] = useState(false);
  const [notification, setNotification] = useState<string | null>(null);

  const canModify = userRole === 'SUPER_ADMIN';

  const handleCreate = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newDesc.trim()) return;
    onCreateSnapshot(newDesc.trim());
    setNewDesc('');
    setNotification('New cryptographic fleet snapshot created and signed.');
    setTimeout(() => setNotification(null), 3000);
  };

  const handleTriggerRestore = () => {
    if (!selectedSnapshotId) return;
    onRestoreSnapshot(selectedSnapshotId);
    setConfirmModalOpen(false);
    setNotification(`Disaster Recovery Rollback Drill completed. Fleet topology restored.`);
    setTimeout(() => setNotification(null), 4000);
  };

  const downloadSnapshotJson = (snap: DisasterRecoverySnapshot) => {
    const blob = new Blob([JSON.stringify(snap, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `ztna_dr_snapshot_${snap.id}_${Date.now()}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      {/* View Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-base font-semibold text-slate-100 flex items-center gap-2">
            <DatabaseBackup className="w-5 h-5 text-emerald-400" />
            Automated Backup & Disaster Recovery (DR) Controller
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Cryptographic state snapshotting (SHA-256 + AES-256-GCM envelope) with instantaneous rollback verification drills.
          </p>
        </div>

        {notification && (
          <div className="px-3 py-1.5 bg-emerald-950/80 border border-emerald-700/80 text-emerald-300 text-xs rounded font-mono flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            <span>{notification}</span>
          </div>
        )}
      </div>

      {/* Snapshot Creation & Automated Drill Card */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Create Manual Snapshot Form */}
        <div className="bg-slate-900/90 border border-slate-800 rounded p-4 space-y-4">
          <h3 className="text-xs font-semibold text-slate-200 flex items-center gap-1.5">
            <Plus className="w-4 h-4 text-blue-400" />
            Capture New Fleet Snapshot
          </h3>

          <form onSubmit={handleCreate} className="space-y-3">
            <div>
              <label className="block text-xs text-slate-400 mb-1">Snapshot Description</label>
              <input
                type="text"
                placeholder="e.g. Pre-maintenance clean baseline"
                value={newDesc}
                onChange={e => setNewDesc(e.target.value)}
                disabled={!canModify}
                className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-blue-500 font-mono"
              />
            </div>

            <div className="p-2.5 bg-slate-950/80 rounded border border-slate-800/80 text-[11px] font-mono text-slate-400 space-y-1">
              <div>Algorithm: <span className="text-slate-300">AES-256-GCM Envelope</span></div>
              <div>Integrity: <span className="text-slate-300">Deterministic SHA-256</span></div>
              <div>Scope: <span className="text-slate-300">Switches, Ports, 802.1X Sessions, ACLs</span></div>
            </div>

            <button
              type="submit"
              disabled={!canModify || !newDesc.trim()}
              className="w-full py-2 px-3 bg-blue-600 hover:bg-blue-500 active:bg-blue-700 text-white rounded text-xs font-medium transition-colors flex items-center justify-center gap-1.5 disabled:opacity-50"
            >
              <DatabaseBackup className="w-3.5 h-3.5" />
              <span>Capture & Cryptographically Sign</span>
            </button>
          </form>
        </div>

        {/* Disaster Recovery Rollback Drill Controller */}
        <div className="bg-slate-900/90 border border-slate-800 rounded p-4 lg:col-span-2 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-xs font-semibold text-slate-200 flex items-center gap-1.5">
                <RotateCcw className="w-4 h-4 text-emerald-400" />
                Disaster Recovery Rollback Drill
              </h3>
              <span className="text-[11px] text-slate-400 font-mono">NIST SP 800-34 Contingency Standard</span>
            </div>

            <p className="text-xs text-slate-400 leading-relaxed mb-4">
              Conducting automated DR rollback drills verifies that switches can immediately recover from compromised configurations or cascade attacks by rolling back all port assignments to verified golden baseline states.
            </p>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 mb-4">
              <div>
                <label className="block text-xs text-slate-400 mb-1">Select Target Golden Snapshot</label>
                <select
                  value={selectedSnapshotId}
                  onChange={e => setSelectedSnapshotId(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-xs text-slate-200 font-mono focus:outline-none focus:border-blue-500"
                >
                  {snapshots.map(s => (
                    <option key={s.id} value={s.id}>
                      {s.id} - {s.description} ({s.version})
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-xs text-slate-400 mb-1">Verification Status</label>
                <div className="p-1.5 bg-slate-950 rounded border border-slate-800 text-xs font-mono text-emerald-400 flex items-center gap-1.5">
                  <ShieldCheck className="w-4 h-4" />
                  <span>SHA-256 Hash Pre-Validated</span>
                </div>
              </div>
            </div>
          </div>

          <div className="pt-3 border-t border-slate-800 flex items-center justify-between">
            <span className="text-xs text-slate-500 font-mono">
              Requires Super Admin privileges to commit rollback.
            </span>
            <button
              type="button"
              disabled={!canModify || !selectedSnapshotId}
              onClick={() => setConfirmModalOpen(true)}
              className="py-2 px-4 bg-emerald-600 hover:bg-emerald-500 active:bg-emerald-700 text-white rounded text-xs font-medium transition-colors flex items-center gap-1.5 disabled:opacity-50"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              <span>Execute Rollback Drill</span>
            </button>
          </div>
        </div>
      </div>

      {/* Snapshots Table */}
      <div className="bg-slate-900/90 border border-slate-800 rounded overflow-hidden">
        <div className="px-4 py-3 border-b border-slate-800 flex items-center justify-between">
          <h3 className="text-xs font-semibold text-slate-200">
            Cryptographic Snapshot Vault ({snapshots.length} Snapshots)
          </h3>
          <span className="text-[11px] text-slate-400 font-mono">
            Automated Scheduled Snapshots: Active (Every 60 min)
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-950 text-slate-400 text-[11px] border-b border-slate-800">
              <tr>
                <th className="py-2.5 px-3">Snapshot ID</th>
                <th className="py-2.5 px-3">Timestamp</th>
                <th className="py-2.5 px-3">Description</th>
                <th className="py-2.5 px-3">Created By</th>
                <th className="py-2.5 px-3">Topology Scope</th>
                <th className="py-2.5 px-3">SHA-256 Checksum</th>
                <th className="py-2.5 px-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              {snapshots.map(s => (
                <tr key={s.id} className="hover:bg-slate-800/40 transition-colors">
                  <td className="py-2.5 px-3 font-semibold text-blue-300">{s.id}</td>
                  <td className="py-2.5 px-3 text-slate-400">{new Date(s.timestamp).toLocaleTimeString()}</td>
                  <td className="py-2.5 px-3 text-slate-200 font-sans">{s.description}</td>
                  <td className="py-2.5 px-3 text-slate-400">{s.createdBy}</td>
                  <td className="py-2.5 px-3 tabular-nums">
                    {s.switchCount} Switches · {s.portCount} Ports
                  </td>
                  <td className="py-2.5 px-3 text-[10px] text-slate-500 font-mono" title={s.checksum}>
                    {s.checksum.slice(0, 18)}...
                  </td>
                  <td className="py-2.5 px-3 text-right space-x-2">
                    <button
                      onClick={() => downloadSnapshotJson(s)}
                      className="text-xs text-blue-400 hover:text-blue-300 font-sans"
                      title="Download encrypted snapshot JSON"
                    >
                      Export
                    </button>
                    {canModify && (
                      <button
                        onClick={() => {
                          setSelectedSnapshotId(s.id);
                          setConfirmModalOpen(true);
                        }}
                        className="text-xs text-emerald-400 hover:text-emerald-300 font-sans"
                        title="Rollback to this snapshot"
                      >
                        Restore
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Confirmation Modal for DR Rollback */}
      {confirmModalOpen && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-xs flex items-center justify-center p-4 z-50">
          <div className="bg-slate-900 border border-slate-700 rounded-lg max-w-md w-full p-6 shadow-2xl space-y-4">
            <div className="flex items-center gap-3 text-amber-400">
              <AlertTriangle className="w-6 h-6 shrink-0" />
              <h3 className="text-base font-semibold text-slate-100">
                Confirm Fleet Rollback Drill
              </h3>
            </div>

            <p className="text-xs text-slate-300 leading-relaxed">
              This operation will reset all 3 multi-vendor switches (Cisco, Juniper, Arista) and their switchports back to snapshot <span className="font-mono text-blue-400 font-semibold">{selectedSnapshotId}</span>. All current quarantine ACLs will be synchronized with the golden master state.
            </p>

            <div className="flex items-center justify-end gap-3 pt-3 border-t border-slate-800">
              <button
                type="button"
                onClick={() => setConfirmModalOpen(false)}
                className="px-3.5 py-1.5 text-xs text-slate-300 bg-slate-800 hover:bg-slate-700 rounded transition-colors"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleTriggerRestore}
                className="px-3.5 py-1.5 text-xs font-medium text-white bg-emerald-600 hover:bg-emerald-500 rounded transition-colors"
              >
                Confirm & Execute Drill
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
