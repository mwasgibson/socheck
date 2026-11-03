/**
 * Threat Simulation & Real-time Mitigation Panel
 * Injects MITRE ATT&CK vectors, evaluates with Isolation Forest,
 * and triggers automated multi-vendor Netmiko quarantine.
 */

import React, { useState } from 'react';
import { AttackType, MitreTechnique, SwitchDevice, SwitchPort, UserRole } from '../types/network';
import { MITRE_TECHNIQUES } from '../services/networkState';
import { Zap, AlertOctagon, Terminal, ShieldAlert, Cpu, ArrowRight } from 'lucide-react';

interface AttackSimulatorPanelProps {
  switches: SwitchDevice[];
  ports: SwitchPort[];
  onTriggerAttack: (portId: string, attackType: AttackType) => void;
  userRole: UserRole;
  isSimulating: boolean;
}

export const AttackSimulatorPanel: React.FC<AttackSimulatorPanelProps> = ({
  switches,
  ports,
  onTriggerAttack,
  userRole,
  isSimulating,
}) => {
  const [selectedPortId, setSelectedPortId] = useState<string>(ports[0]?.id || '');
  const [selectedAttackType, setSelectedAttackType] = useState<AttackType>('8021X_BYPASS');

  const selectedPort = ports.find(p => p.id === selectedPortId);
  const selectedSwitch = switches.find(s => s.id === selectedPort?.switchId);
  const currentMitre = MITRE_TECHNIQUES[selectedAttackType];

  const handleExecute = () => {
    if (!selectedPortId) return;
    onTriggerAttack(selectedPortId, selectedAttackType);
  };

  const attackOptions: { type: AttackType; label: string; vectorId: string }[] = [
    { type: '8021X_BYPASS', label: '802.1X EAP Bypass / Supplicant Hijack', vectorId: 'MITRE T1078' },
    { type: 'ARP_SPOOF', label: 'ARP Subnet Cache Poisoning Storm', vectorId: 'MITRE T1557' },
    { type: 'MAC_CLONE', label: 'Physical Layer MAC Address Cloning', vectorId: 'MITRE T1036' },
    { type: 'C2_BEACON', label: 'Command & Control Low-Jitter Beaconing', vectorId: 'MITRE T1071' },
  ];

  const isRestrictedRole = userRole === 'NETWORK_AUDITOR';

  return (
    <div className="bg-slate-900/90 border border-slate-800 rounded p-5 mb-6">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-5 border-b border-slate-800/80 pb-4">
        <div>
          <h2 className="text-base font-semibold text-slate-100 flex items-center gap-2">
            <Zap className="w-4 h-4 text-amber-400" />
            Attack Simulation & Automated Netmiko Mitigation
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Simulate zero-trust attack vectors against ingress switchports to verify 99%+ accuracy Isolation Forest threat detection and sub-150ms switchport quarantine.
          </p>
        </div>

        {isRestrictedRole && (
          <div className="text-xs text-amber-400 font-mono">
            Auditor Mode: Read-Only (Simulation Disabled)
          </div>
        )}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        {/* Step 1: Select Target Switch & Port */}
        <div>
          <label className="block text-xs font-medium text-slate-300 mb-1.5">
            1. Target Switchport (Multi-Vendor Fleet)
          </label>
          <select
            value={selectedPortId}
            onChange={e => setSelectedPortId(e.target.value)}
            disabled={isRestrictedRole || isSimulating}
            className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-blue-500 font-mono"
          >
            {switches.map(sw => (
              <optgroup key={sw.id} label={`${sw.name} (${sw.vendor.toUpperCase()} · ${sw.model})`}>
                {ports
                  .filter(p => p.switchId === sw.id)
                  .map(p => (
                    <option key={p.id} value={p.id}>
                      {sw.name} / {p.portName} - {p.deviceType} [VLAN {p.vlan} · {p.state}]
                    </option>
                  ))}
              </optgroup>
            ))}
          </select>

          {selectedPort && selectedSwitch && (
            <div className="mt-2.5 p-2.5 bg-slate-950/70 border border-slate-800/60 rounded text-xs space-y-1 font-mono text-slate-400">
              <div className="flex justify-between">
                <span>Vendor Driver:</span>
                <span className="text-slate-200">{selectedSwitch.vendor}</span>
              </div>
              <div className="flex justify-between">
                <span>IP / Port:</span>
                <span className="text-slate-200">{selectedPort.ipAddress} · {selectedPort.portName}</span>
              </div>
              <div className="flex justify-between">
                <span>802.1X Identity:</span>
                <span className="text-slate-200 truncate max-w-[180px]">{selectedPort.eapIdentity}</span>
              </div>
              <div className="flex justify-between">
                <span>Current State:</span>
                <span className={selectedPort.state === 'QUARANTINED' ? 'text-red-400 font-semibold' : 'text-emerald-400'}>
                  {selectedPort.state} (VLAN {selectedPort.vlan})
                </span>
              </div>
            </div>
          )}
        </div>

        {/* Step 2: Choose Attack Scenario */}
        <div>
          <label className="block text-xs font-medium text-slate-300 mb-1.5">
            2. MITRE Threat Vector
          </label>
          <div className="space-y-1.5">
            {attackOptions.map(opt => (
              <button
                key={opt.type}
                type="button"
                onClick={() => setSelectedAttackType(opt.type)}
                disabled={isRestrictedRole || isSimulating}
                className={`w-full text-left px-3 py-2 rounded text-xs border transition-colors flex items-center justify-between ${
                  selectedAttackType === opt.type
                    ? 'bg-slate-800 border-blue-500/80 text-blue-200'
                    : 'bg-slate-950/60 border-slate-800/80 text-slate-400 hover:text-slate-200 hover:bg-slate-900'
                }`}
              >
                <span className="font-medium truncate">{opt.label}</span>
                <span className="text-[10px] font-mono text-slate-500 ml-2 whitespace-nowrap">
                  {opt.vectorId}
                </span>
              </button>
            ))}
          </div>
        </div>

        {/* Step 3: Threat Details & Launch Mitigation */}
        <div className="flex flex-col justify-between">
          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1.5">
              3. Execution Context & Automated Pipeline
            </label>
            <div className="p-3 bg-slate-950/80 border border-slate-800 rounded text-xs text-slate-300 space-y-2">
              <div className="flex items-center gap-2 text-red-400 font-semibold">
                <ShieldAlert className="w-4 h-4 shrink-0" />
                <span>{currentMitre.name}</span>
              </div>
              <p className="text-[11px] text-slate-400 leading-relaxed">
                {currentMitre.description}
              </p>
              <div className="text-[10px] text-slate-500 font-mono border-t border-slate-800/60 pt-2">
                Flow: Ingest Telemetry → iForest (score &gt; 0.62) → Netmiko SSH → Port shifted to VLAN 99 → Isolation ACL drop
              </div>
            </div>
          </div>

          <div className="mt-4">
            <button
              onClick={handleExecute}
              disabled={isRestrictedRole || isSimulating || selectedPort?.state === 'QUARANTINED'}
              className="w-full py-2.5 px-4 bg-red-600 hover:bg-red-500 active:bg-red-700 text-white rounded font-medium text-xs transition-colors flex items-center justify-center gap-2 shadow-sm disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {selectedPort?.state === 'QUARANTINED' ? (
                <>
                  <AlertOctagon className="w-4 h-4" />
                  <span>Port Already Quarantined in VLAN 99</span>
                </>
              ) : isSimulating ? (
                <>
                  <Cpu className="w-4 h-4 animate-spin text-white" />
                  <span>Evaluating Isolation Forest & Dispatched Netmiko...</span>
                </>
              ) : (
                <>
                  <Zap className="w-4 h-4" />
                  <span>Execute Attack & Trigger Netmiko Quarantine</span>
                </>
              )}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
