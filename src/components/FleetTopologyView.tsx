/**
 * Multi-Vendor Switch Fleet & Port Matrix Visualizer
 * Shows active 802.1X/RADIUS session states across Cisco, Juniper, and Arista switches.
 */

import React, { useState } from 'react';
import { AttackType, SwitchDevice, SwitchPort, UserRole } from '../types/network';
import { ShieldCheck, ShieldAlert, RotateCcw, Zap, Server, Lock, ExternalLink, X } from 'lucide-react';

interface FleetTopologyViewProps {
  switches: SwitchDevice[];
  ports: SwitchPort[];
  onRestorePort: (portId: string) => void;
  onSimulateAttack: (portId: string, attackType: AttackType) => void;
  userRole: UserRole;
  onViewNetmikoJob: (jobId: string) => void;
}

export const FleetTopologyView: React.FC<FleetTopologyViewProps> = ({
  switches,
  ports,
  onRestorePort,
  onSimulateAttack,
  userRole,
  onViewNetmikoJob,
}) => {
  const [selectedPort, setSelectedPort] = useState<SwitchPort | null>(null);
  const [vendorFilter, setVendorFilter] = useState<'ALL' | 'cisco_ios' | 'juniper_junos' | 'arista_eos'>('ALL');

  const filteredSwitches = vendorFilter === 'ALL'
    ? switches
    : switches.filter(s => s.vendor === vendorFilter);

  const canModify = userRole !== 'NETWORK_AUDITOR';

  return (
    <div className="space-y-6">
      {/* View Header with Vendor Segmented Filters */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-base font-semibold text-slate-100">
            Multi-Vendor Switch Fleet & Port Authentication Matrix
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Real-time port-level 802.1X/RADIUS NAC states, dynamic VLAN allocation, and automated isolation ACL enforcement.
          </p>
        </div>

        {/* Interactive Segmented Filter Controls */}
        <div className="flex items-center gap-1 p-1 bg-slate-900 border border-slate-800 rounded">
          <button
            onClick={() => setVendorFilter('ALL')}
            className={`px-3 py-1 text-xs font-medium rounded transition-colors whitespace-nowrap ${
              vendorFilter === 'ALL' ? 'bg-slate-800 text-blue-400' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            All Vendors ({switches.length})
          </button>
          <button
            onClick={() => setVendorFilter('cisco_ios')}
            className={`px-3 py-1 text-xs font-medium rounded transition-colors whitespace-nowrap ${
              vendorFilter === 'cisco_ios' ? 'bg-slate-800 text-blue-400' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Cisco IOS-XE
          </button>
          <button
            onClick={() => setVendorFilter('juniper_junos')}
            className={`px-3 py-1 text-xs font-medium rounded transition-colors whitespace-nowrap ${
              vendorFilter === 'juniper_junos' ? 'bg-slate-800 text-blue-400' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Juniper Junos
          </button>
          <button
            onClick={() => setVendorFilter('arista_eos')}
            className={`px-3 py-1 text-xs font-medium rounded transition-colors whitespace-nowrap ${
              vendorFilter === 'arista_eos' ? 'bg-slate-800 text-blue-400' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Arista EOS
          </button>
        </div>
      </div>

      {/* Switch Cards Grid */}
      <div className="grid grid-cols-1 gap-6">
        {filteredSwitches.map(sw => {
          const switchPorts = ports.filter(p => p.switchId === sw.id);
          const quarantined = switchPorts.filter(p => p.state === 'QUARANTINED').length;

          return (
            <div
              key={sw.id}
              className="bg-slate-900/90 border border-slate-800 rounded p-5 space-y-4"
            >
              {/* Switch Metadata Header */}
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 border-b border-slate-800/80 pb-3">
                <div className="flex items-center gap-3">
                  <div className="w-9 h-9 rounded bg-slate-800 flex items-center justify-center text-slate-300">
                    <Server className="w-5 h-5 text-blue-400" />
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <h3 className="text-sm font-semibold text-slate-100 font-mono">
                        {sw.name}
                      </h3>
                      <span className="text-xs text-slate-400 font-mono">· {sw.model}</span>
                    </div>
                    <div className="text-xs text-slate-400 flex items-center gap-2 font-mono mt-0.5">
                      <span>{sw.ip}</span>
                      <span aria-hidden="true">·</span>
                      <span className="uppercase text-blue-400">{sw.vendor}</span>
                      <span aria-hidden="true">·</span>
                      <span>{sw.firmwareVersion}</span>
                      <span aria-hidden="true">·</span>
                      <span>{sw.location}</span>
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-4 text-xs font-mono">
                  <div className="text-slate-400">
                    Uptime: <span className="text-slate-200 tabular-nums">{sw.uptimeDays}d</span>
                  </div>
                  <div className="text-slate-400">
                    Quarantined: <span className={quarantined > 0 ? 'text-red-400 font-semibold tabular-nums' : 'text-slate-200 tabular-nums'}>{quarantined}</span>
                  </div>
                </div>
              </div>

              {/* Visual Port Matrix Grid */}
              <div>
                <div className="text-xs font-medium text-slate-400 mb-2">
                  Front Panel Switchport Matrix (Click a port to inspect 802.1X session / isolate):
                </div>
                <div className="grid grid-cols-2 sm:grid-cols-4 md:grid-cols-8 gap-2.5">
                  {switchPorts.map(port => {
                    const isQuarantined = port.state === 'QUARANTINED';
                    return (
                      <button
                        key={port.id}
                        type="button"
                        onClick={() => setSelectedPort(port)}
                        className={`text-left p-2.5 rounded border transition-all ${
                          isQuarantined
                            ? 'bg-red-950/20 border-red-700/80 hover:border-red-500'
                            : 'bg-slate-950/80 border-slate-800 hover:border-blue-500/80'
                        }`}
                      >
                        <div className="flex items-center justify-between mb-1.5">
                          <span className="text-[11px] font-mono font-semibold text-slate-200">
                            {port.portName.replace('GigabitEthernet', 'Gi').replace('Ethernet', 'Eth')}
                          </span>
                          {isQuarantined ? (
                            <ShieldAlert className="w-3.5 h-3.5 text-red-400" />
                          ) : (
                            <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
                          )}
                        </div>
                        <div className="text-[10px] text-slate-400 font-mono truncate">
                          VLAN {port.vlan}
                        </div>
                        <div className="text-[10px] text-slate-500 font-mono truncate mt-0.5">
                          {port.ipAddress.split('.').slice(-2).join('.')}
                        </div>
                      </button>
                    );
                  })}
                </div>
              </div>

              {/* Port Table Summary for Dense Scannability */}
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs font-mono">
                  <thead>
                    <tr className="border-b border-slate-800 text-slate-400 text-[11px]">
                      <th className="py-2 px-3">Port</th>
                      <th className="py-2 px-3">State</th>
                      <th className="py-2 px-3">VLAN</th>
                      <th className="py-2 px-3">IP / MAC</th>
                      <th className="py-2 px-3">802.1X Identity</th>
                      <th className="py-2 px-3">Auth Method</th>
                      <th className="py-2 px-3 text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60 text-slate-300">
                    {switchPorts.map(p => {
                      const isQuar = p.state === 'QUARANTINED';
                      return (
                        <tr key={p.id} className="hover:bg-slate-800/40 transition-colors">
                          <td className="py-2.5 px-3 font-semibold text-slate-200">{p.portName}</td>
                          <td className="py-2.5 px-3">
                            <span className={isQuar ? 'text-red-400 font-semibold' : 'text-emerald-400'}>
                              {p.state}
                            </span>
                          </td>
                          <td className="py-2.5 px-3 tabular-nums">
                            VLAN {p.vlan}
                            {isQuar && <span className="text-red-400 text-[10px] ml-1">(Isolation)</span>}
                          </td>
                          <td className="py-2.5 px-3">
                            <div>{p.ipAddress}</div>
                            <div className="text-[10px] text-slate-500">{p.macAddress}</div>
                          </td>
                          <td className="py-2.5 px-3 truncate max-w-[200px]" title={p.eapIdentity}>
                            {p.eapIdentity}
                          </td>
                          <td className="py-2.5 px-3">{p.authMethod}</td>
                          <td className="py-2.5 px-3 text-right">
                            <button
                              onClick={() => setSelectedPort(p)}
                              className="text-xs text-blue-400 hover:text-blue-300 font-sans"
                            >
                              Details
                            </button>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          );
        })}
      </div>

      {/* Port Inspection Drawer / Modal */}
      {selectedPort && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-xs flex items-center justify-center p-4 z-50">
          <div className="bg-slate-900 border border-slate-700 rounded-lg max-w-xl w-full p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <Lock className="w-5 h-5 text-blue-400" />
                <h3 className="text-base font-semibold text-slate-100 font-mono">
                  {selectedPort.portName} Telemetry & 802.1X Posture
                </h3>
              </div>
              <button
                onClick={() => setSelectedPort(null)}
                className="text-slate-400 hover:text-slate-200 p-1"
                aria-label="Close modal"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="grid grid-cols-2 gap-4 text-xs font-mono">
              <div className="p-3 bg-slate-950 rounded border border-slate-800 space-y-1.5">
                <div className="text-slate-500 text-[11px]">Interface State</div>
                <div className={`font-semibold text-sm ${selectedPort.state === 'QUARANTINED' ? 'text-red-400' : 'text-emerald-400'}`}>
                  {selectedPort.state}
                </div>
                <div className="text-slate-400">Current VLAN: <span className="text-slate-200">{selectedPort.vlan}</span></div>
                <div className="text-slate-400">Standard VLAN: <span className="text-slate-200">{selectedPort.normalVlan}</span></div>
                <div className="text-slate-400">Quarantine VLAN: <span className="text-slate-200">{selectedPort.quarantineVlan}</span></div>
              </div>

              <div className="p-3 bg-slate-950 rounded border border-slate-800 space-y-1.5">
                <div className="text-slate-500 text-[11px]">Endpoint Identity</div>
                <div className="text-slate-200 font-semibold truncate">{selectedPort.deviceType}</div>
                <div className="text-slate-400">IPv4: <span className="text-slate-200">{selectedPort.ipAddress}</span></div>
                <div className="text-slate-400">MAC: <span className="text-slate-200">{selectedPort.macAddress}</span></div>
                <div className="text-slate-400">Auth Method: <span className="text-blue-400">{selectedPort.authMethod}</span></div>
              </div>
            </div>

            {/* Supplicant & Certificate Details */}
            <div className="p-3 bg-slate-950 rounded border border-slate-800 text-xs font-mono space-y-1.5">
              <div className="text-slate-500 text-[11px]">802.1X EAP Session Credentials</div>
              <div className="flex justify-between">
                <span className="text-slate-400">EAP-Identity:</span>
                <span className="text-slate-200">{selectedPort.eapIdentity}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Certificate Hash:</span>
                <span className="text-slate-300 truncate max-w-[280px]">{selectedPort.certThumbprint}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Last Auth Timestamp:</span>
                <span className="text-slate-300">{new Date(selectedPort.lastAuthTime).toLocaleTimeString()}</span>
              </div>
            </div>

            {/* Quarantine Info if Active */}
            {selectedPort.state === 'QUARANTINED' && (
              <div className="p-3 bg-red-950/20 border border-red-800/60 rounded text-xs font-mono space-y-1.5">
                <div className="flex items-center gap-1.5 text-red-400 font-semibold">
                  <ShieldAlert className="w-4 h-4" />
                  <span>Isolation Forest Incident Quarantine</span>
                </div>
                <div className="text-slate-300 text-[11px]">
                  Reason: {selectedPort.quarantineReason || 'Threat vector detected'}
                </div>
                <div className="flex justify-between text-slate-400 text-[11px]">
                  <span>Applied Ingress ACL:</span>
                  <span className="text-red-300 font-semibold">{selectedPort.aclApplied || 'ZTNA_QUARANTINE_ACL'}</span>
                </div>
                {selectedPort.quarantineJobId && (
                  <div className="flex justify-between text-slate-400 text-[11px] pt-1">
                    <span>Netmiko Job:</span>
                    <button
                      onClick={() => {
                        onViewNetmikoJob(selectedPort.quarantineJobId!);
                        setSelectedPort(null);
                      }}
                      className="text-blue-400 hover:underline flex items-center gap-1"
                    >
                      {selectedPort.quarantineJobId} <ExternalLink className="w-3 h-3" />
                    </button>
                  </div>
                )}
              </div>
            )}

            {/* Modal Actions */}
            <div className="flex items-center justify-end gap-3 pt-2 border-t border-slate-800">
              <button
                type="button"
                onClick={() => setSelectedPort(null)}
                className="px-3.5 py-1.5 text-xs text-slate-300 bg-slate-800 hover:bg-slate-700 rounded transition-colors"
              >
                Close
              </button>

              {selectedPort.state === 'QUARANTINED' ? (
                <button
                  type="button"
                  disabled={!canModify}
                  onClick={() => {
                    onRestorePort(selectedPort.id);
                    setSelectedPort(null);
                  }}
                  className="px-3.5 py-1.5 text-xs font-medium text-white bg-emerald-600 hover:bg-emerald-500 rounded transition-colors flex items-center gap-1.5 disabled:opacity-50"
                >
                  <RotateCcw className="w-3.5 h-3.5" />
                  <span>Restore Port via Netmiko</span>
                </button>
              ) : (
                <button
                  type="button"
                  disabled={!canModify}
                  onClick={() => {
                    onSimulateAttack(selectedPort.id, '8021X_BYPASS');
                    setSelectedPort(null);
                  }}
                  className="px-3.5 py-1.5 text-xs font-medium text-white bg-red-600 hover:bg-red-500 rounded transition-colors flex items-center gap-1.5 disabled:opacity-50"
                >
                  <Zap className="w-3.5 h-3.5" />
                  <span>Simulate Attack on Port</span>
                </button>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
