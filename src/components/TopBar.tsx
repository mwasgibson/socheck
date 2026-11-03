/**
 * Top Bar conforming to the Strict One-Row Three-Zone Top Bar Contract
 * Zone 1: Single text element wordmark
 * Zone 2: Navigation tabs with single-line labels
 * Zone 3: User Role Switcher & Live Pulse Trigger
 */

import React from 'react';
import { UserRole } from '../types/network';
import { ShieldCheck, RefreshCw, KeyRound } from 'lucide-react';

interface TopBarProps {
  activeTab: string;
  onTabChange: (tab: string) => void;
  currentRole: UserRole;
  onRoleChange: (role: UserRole) => void;
  onTickPulse: () => void;
  isSimulating: boolean;
}

export const TopBar: React.FC<TopBarProps> = ({
  activeTab,
  onTabChange,
  currentRole,
  onRoleChange,
  onTickPulse,
  isSimulating,
}) => {
  const navTabs = [
    { id: 'overview', label: 'SOC Overview' },
    { id: 'topology', label: 'Fleet Topology' },
    { id: 'ml_detector', label: 'ML Detector' },
    { id: 'netmiko', label: 'Netmiko Terminal' },
    { id: 'audit', label: 'Audit Logs' },
    { id: 'recovery', label: 'Disaster Recovery' },
  ];

  return (
    <header className="flex items-center justify-between gap-8 px-6 py-3.5 bg-slate-950 border-b border-slate-800/80 sticky top-0 z-50">
      {/* Zone 1: Single text element Brand wordmark */}
      <div className="flex items-center gap-3 shrink-0">
        <div className="w-8 h-8 rounded bg-blue-600/20 border border-blue-500/30 flex items-center justify-center text-blue-400">
          <ShieldCheck className="w-5 h-5" />
        </div>
        <span className="text-base font-semibold tracking-tight text-slate-100 whitespace-nowrap">
          ZTNA Orchestrator
        </span>
      </div>

      {/* Zone 2: Navigation tabs with clean hover and active states (No pill badges) */}
      <nav className="hidden lg:flex items-center gap-1 text-sm font-medium">
        {navTabs.map(tab => (
          <button
            key={tab.id}
            onClick={() => onTabChange(tab.id)}
            className={`px-3.5 py-1.5 text-xs rounded transition-colors whitespace-nowrap shrink-0 ${
              activeTab === tab.id
                ? 'bg-slate-800 text-blue-400 font-semibold'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
            }`}
          >
            {tab.label}
          </button>
        ))}
      </nav>

      {/* Zone 3: RBAC selector & 1 primary action */}
      <div className="flex items-center gap-3 shrink-0">
        <div className="flex items-center gap-2 border border-slate-800 bg-slate-900/80 rounded px-2.5 py-1 text-xs">
          <KeyRound className="w-3.5 h-3.5 text-slate-400" />
          <select
            value={currentRole}
            onChange={e => onRoleChange(e.target.value as UserRole)}
            className="bg-transparent text-slate-200 font-medium text-xs focus:outline-none cursor-pointer"
            aria-label="Select User Role"
          >
            <option value="SUPER_ADMIN" className="bg-slate-900 text-slate-200">
              Super Admin
            </option>
            <option value="SECOPS_ANALYST" className="bg-slate-900 text-slate-200">
              SecOps Analyst
            </option>
            <option value="NETWORK_AUDITOR" className="bg-slate-900 text-slate-200">
              Network Auditor
            </option>
          </select>
        </div>

        <button
          onClick={onTickPulse}
          disabled={isSimulating}
          className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-200 bg-slate-800 hover:bg-slate-700 active:bg-slate-600 border border-slate-700/60 rounded transition-colors whitespace-nowrap shrink-0 disabled:opacity-50"
          title="Simulate background network traffic pulse"
        >
          <RefreshCw className={`w-3.5 h-3.5 text-blue-400 ${isSimulating ? 'animate-spin' : ''}`} />
          <span>Ingest Telemetry</span>
        </button>
      </div>
    </header>
  );
};
