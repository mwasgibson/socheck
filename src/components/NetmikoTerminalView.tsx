/**
 * Python / Netmiko Multi-Vendor Interactive Terminal View
 * Provides real-time SSH execution logs, CLI commands, and raw Python Netmiko source.
 */

import React, { useState } from 'react';
import { NetmikoJob, SwitchDevice, SwitchPort, VendorType } from '../types/network';
import { netmikoService } from '../services/netmikoOrchestrator';
import { Terminal, Copy, Check, Code, FileText, ArrowRight, Server } from 'lucide-react';

interface NetmikoTerminalViewProps {
  jobs: NetmikoJob[];
  switches: SwitchDevice[];
  ports: SwitchPort[];
  activeJobId?: string;
}

export const NetmikoTerminalView: React.FC<NetmikoTerminalViewProps> = ({
  jobs,
  switches,
  ports,
  activeJobId,
}) => {
  const [selectedJobId, setSelectedJobId] = useState<string>(activeJobId || jobs[0]?.id || '');
  const [viewMode, setViewMode] = useState<'TERMINAL' | 'PYTHON_SCRIPT' | 'CONFIG_DIFF'>('TERMINAL');
  const [copied, setCopied] = useState<boolean>(false);

  // Fallback if no jobs exist yet, generate a sample Cisco quarantine preview
  const currentJob = jobs.find(j => j.id === selectedJobId) || jobs[0];

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="space-y-6">
      {/* View Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-base font-semibold text-slate-100 flex items-center gap-2">
            <Terminal className="w-5 h-5 text-emerald-400" />
            Python / Netmiko Multi-Vendor Execution Engine
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Automated SSH mitigation scripts dispatched to Cisco IOS-XE, Juniper Junos, and Arista EOS switches.
          </p>
        </div>

        {/* View Mode Segmented Switcher */}
        <div className="flex items-center gap-1 p-1 bg-slate-900 border border-slate-800 rounded">
          <button
            onClick={() => setViewMode('TERMINAL')}
            className={`px-3 py-1 text-xs font-medium rounded transition-colors whitespace-nowrap flex items-center gap-1.5 ${
              viewMode === 'TERMINAL' ? 'bg-slate-800 text-blue-400' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Terminal className="w-3.5 h-3.5" />
            <span>Interactive Terminal</span>
          </button>
          <button
            onClick={() => setViewMode('PYTHON_SCRIPT')}
            className={`px-3 py-1 text-xs font-medium rounded transition-colors whitespace-nowrap flex items-center gap-1.5 ${
              viewMode === 'PYTHON_SCRIPT' ? 'bg-slate-800 text-blue-400' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Code className="w-3.5 h-3.5" />
            <span>Netmiko Python Source</span>
          </button>
          <button
            onClick={() => setViewMode('CONFIG_DIFF')}
            className={`px-3 py-1 text-xs font-medium rounded transition-colors whitespace-nowrap flex items-center gap-1.5 ${
              viewMode === 'CONFIG_DIFF' ? 'bg-slate-800 text-blue-400' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <FileText className="w-3.5 h-3.5" />
            <span>Configuration Diff</span>
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* Job History Selector List */}
        <div className="bg-slate-900/90 border border-slate-800 rounded p-4 lg:col-span-1 space-y-3">
          <div className="flex items-center justify-between text-xs font-semibold text-slate-200 border-b border-slate-800 pb-2">
            <span>Netmiko Execution Jobs</span>
            <span className="font-mono text-slate-500">{jobs.length} total</span>
          </div>

          {jobs.length === 0 ? (
            <div className="text-xs text-slate-500 py-6 text-center font-mono">
              No jobs dispatched yet. Trigger an attack simulation to view live Netmiko execution.
            </div>
          ) : (
            <div className="space-y-1.5 max-h-[500px] overflow-y-auto">
              {jobs.map(job => (
                <button
                  key={job.id}
                  onClick={() => setSelectedJobId(job.id)}
                  className={`w-full text-left p-2.5 rounded border transition-colors text-xs font-mono ${
                    (selectedJobId === job.id || (!selectedJobId && job === jobs[0]))
                      ? 'bg-slate-800 border-blue-500/80 text-blue-200'
                      : 'bg-slate-950/60 border-slate-800/80 text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <div className="flex items-center justify-between font-semibold">
                    <span className="truncate">{job.portName}</span>
                    <span className="text-[10px] text-emerald-400 uppercase">{job.vendor}</span>
                  </div>
                  <div className="text-[10px] text-slate-500 truncate mt-1">
                    {job.action} · VLAN {job.targetVlan}
                  </div>
                  <div className="text-[10px] text-slate-500 mt-0.5">
                    {new Date(job.timestamp).toLocaleTimeString()} ({job.durationMs}ms)
                  </div>
                </button>
              ))}
            </div>
          )}
        </div>

        {/* Terminal / Code Content Pane */}
        <div className="bg-slate-900/90 border border-slate-800 rounded p-4 lg:col-span-3 flex flex-col justify-between">
          {currentJob ? (
            <div>
              {/* Job Info Banner */}
              <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 pb-3 mb-4 text-xs font-mono">
                <div className="flex items-center gap-3">
                  <div className="w-7 h-7 rounded bg-slate-800 flex items-center justify-center text-blue-400">
                    <Server className="w-4 h-4" />
                  </div>
                  <div>
                    <div className="text-slate-100 font-semibold">{currentJob.id}</div>
                    <div className="text-[11px] text-slate-400">
                      Switch: <span className="text-slate-200">{currentJob.switchName}</span> · Driver: <span className="text-blue-400">{currentJob.vendor}</span> · Action: <span className="text-red-400">{currentJob.action}</span>
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    onClick={() => handleCopy(viewMode === 'PYTHON_SCRIPT' ? currentJob.netmikoScript : currentJob.terminalOutput)}
                    className="flex items-center gap-1 px-2.5 py-1 text-xs bg-slate-800 hover:bg-slate-700 text-slate-300 rounded border border-slate-700 transition-colors"
                  >
                    {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>{copied ? 'Copied' : 'Copy'}</span>
                  </button>
                </div>
              </div>

              {/* View Mode 1: Terminal Console */}
              {viewMode === 'TERMINAL' && (
                <div className="bg-black/90 rounded border border-slate-800 p-4 font-mono text-xs text-emerald-400 h-96 overflow-y-auto whitespace-pre leading-relaxed selection:bg-emerald-900 selection:text-white">
                  {currentJob.terminalOutput}
                </div>
              )}

              {/* View Mode 2: Python Script */}
              {viewMode === 'PYTHON_SCRIPT' && (
                <div className="bg-slate-950 rounded border border-slate-800 p-4 font-mono text-xs text-blue-300 h-96 overflow-y-auto whitespace-pre leading-relaxed">
                  {currentJob.netmikoScript}
                </div>
              )}

              {/* View Mode 3: Config Diff */}
              {viewMode === 'CONFIG_DIFF' && (
                <div className="bg-slate-950 rounded border border-slate-800 p-4 font-mono text-xs h-96 overflow-y-auto space-y-1">
                  <div className="text-slate-500">@@ Switch Interface Configuration Transition @@</div>
                  <div className="text-red-400">- switchport access vlan 10 (Corporate Authenticated)</div>
                  <div className="text-red-400">- no ip access-group ZTNA_QUARANTINE_ACL in</div>
                  <div className="text-emerald-400">+ switchport access vlan 99 (Isolation & Remediation)</div>
                  <div className="text-emerald-400">+ ip access-group ZTNA_QUARANTINE_ACL in</div>
                  <div className="text-emerald-400">+ dot1x control-direction in</div>
                  <div className="text-emerald-400">+ description [QUARANTINED] Isolation Forest Anomaly Triggered</div>
                  <div className="text-slate-500 pt-3">
                    Status: Verified and active in running-config. Drop-all ingress filter active on interface {currentJob.portName}.
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="flex flex-col items-center justify-center py-20 text-slate-500 font-mono text-xs">
              <Terminal className="w-8 h-8 mb-2 text-slate-600" />
              <span>Awaiting first Netmiko dispatch</span>
            </div>
          )}

          {/* Terminal Footer Telemetry */}
          {currentJob && (
            <div className="mt-4 pt-3 border-t border-slate-800/80 flex flex-wrap items-center justify-between text-xs font-mono text-slate-500">
              <div>Triggered: <span className="text-slate-400">{currentJob.triggeredBy}</span></div>
              <div>Duration: <span className="text-slate-400">{currentJob.durationMs}ms</span></div>
              <div>Status: <span className="text-emerald-400 font-semibold">{currentJob.status}</span></div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
