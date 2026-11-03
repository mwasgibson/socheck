/**
 * Exportable Audit Trails & Incident Response Analysis View
 * Compliant with enterprise SIEM standards (CEF, Syslog RFC 5424, CSV, JSON).
 */

import React, { useState } from 'react';
import { AuditLog } from '../types/network';
import { formatAsCEF, formatAsSyslog } from '../services/networkState';
import { FileText, Download, ShieldCheck, Search, Filter } from 'lucide-react';

interface AuditLogsViewProps {
  logs: AuditLog[];
}

export const AuditLogsView: React.FC<AuditLogsViewProps> = ({ logs }) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [copiedFormat, setCopiedFormat] = useState<string | null>(null);

  const filteredLogs = logs.filter(log => {
    const matchesSearch =
      searchTerm === '' ||
      log.action.toLowerCase().includes(searchTerm.toLowerCase()) ||
      log.target.toLowerCase().includes(searchTerm.toLowerCase()) ||
      log.details.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (log.mitreId && log.mitreId.toLowerCase().includes(searchTerm.toLowerCase()));

    const matchesSeverity = severityFilter === 'ALL' || log.severity === severityFilter;

    return matchesSearch && matchesSeverity;
  });

  // Export handlers
  const downloadFile = (content: string, filename: string, mimeType: string) => {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const handleExportCEF = () => {
    const lines = filteredLogs.map(formatAsCEF).join('\n');
    downloadFile(lines, `ztna_audit_cef_${Date.now()}.log`, 'text/plain');
  };

  const handleExportSyslog = () => {
    const lines = filteredLogs.map(formatAsSyslog).join('\n');
    downloadFile(lines, `ztna_audit_syslog_rfc5424_${Date.now()}.log`, 'text/plain');
  };

  const handleExportCSV = () => {
    const headers = ['ID', 'Timestamp', 'Actor', 'Role', 'Severity', 'Category', 'Target', 'MITRE_ID', 'Details', 'Checksum'];
    const rows = filteredLogs.map(l => [
      l.id,
      l.timestamp,
      l.actor,
      l.role,
      l.severity,
      l.category,
      l.target,
      l.mitreId || '',
      `"${l.details.replace(/"/g, '""')}"`,
      l.checksum,
    ]);
    const csvContent = [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
    downloadFile(csvContent, `ztna_audit_report_${Date.now()}.csv`, 'text/csv');
  };

  const handleExportJSON = () => {
    const jsonContent = JSON.stringify(filteredLogs, null, 2);
    downloadFile(jsonContent, `ztna_audit_export_${Date.now()}.json`, 'application/json');
  };

  const getSeverityStyle = (sev: AuditLog['severity']) => {
    switch (sev) {
      case 'CRITICAL':
        return 'text-red-400 font-bold';
      case 'HIGH':
        return 'text-amber-400 font-semibold';
      case 'MEDIUM':
        return 'text-yellow-400';
      case 'LOW':
        return 'text-blue-400';
      default:
        return 'text-slate-400';
    }
  };

  return (
    <div className="space-y-6">
      {/* View Header with Export Action Buttons */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
        <div>
          <h2 className="text-base font-semibold text-slate-100 flex items-center gap-2">
            <FileText className="w-5 h-5 text-blue-400" />
            Incident Response Logs & Exportable Audit Trails
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Tamper-evident, cryptographically hashed event stream for compliance auditing (NIST 800-207, SOC 2, ISO 27001).
          </p>
        </div>

        {/* SIEM / Compliance Export Buttons */}
        <div className="flex flex-wrap items-center gap-2">
          <button
            onClick={handleExportCEF}
            className="px-3 py-1.5 text-xs font-medium text-slate-200 bg-slate-800 hover:bg-slate-700 active:bg-slate-600 border border-slate-700 rounded transition-colors flex items-center gap-1.5"
            title="Common Event Format (Splunk / ArcSight)"
          >
            <Download className="w-3.5 h-3.5 text-blue-400" />
            <span>Export CEF</span>
          </button>
          <button
            onClick={handleExportSyslog}
            className="px-3 py-1.5 text-xs font-medium text-slate-200 bg-slate-800 hover:bg-slate-700 active:bg-slate-600 border border-slate-700 rounded transition-colors flex items-center gap-1.5"
            title="Syslog RFC 5424"
          >
            <Download className="w-3.5 h-3.5 text-indigo-400" />
            <span>Export Syslog</span>
          </button>
          <button
            onClick={handleExportCSV}
            className="px-3 py-1.5 text-xs font-medium text-slate-200 bg-slate-800 hover:bg-slate-700 active:bg-slate-600 border border-slate-700 rounded transition-colors flex items-center gap-1.5"
            title="Download CSV spreadsheet"
          >
            <Download className="w-3.5 h-3.5 text-emerald-400" />
            <span>Export CSV</span>
          </button>
          <button
            onClick={handleExportJSON}
            className="px-3 py-1.5 text-xs font-medium text-slate-200 bg-slate-800 hover:bg-slate-700 active:bg-slate-600 border border-slate-700 rounded transition-colors flex items-center gap-1.5"
            title="Export Signed JSON"
          >
            <Download className="w-3.5 h-3.5 text-purple-400" />
            <span>Export JSON</span>
          </button>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col sm:flex-row gap-3 bg-slate-900/90 border border-slate-800 rounded p-3">
        <div className="relative flex-1">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
          <input
            type="text"
            placeholder="Search by action, switch, port, IP, or MITRE ID..."
            value={searchTerm}
            onChange={e => setSearchTerm(e.target.value)}
            className="w-full bg-slate-950 border border-slate-800 rounded pl-9 pr-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-blue-500 font-mono"
          />
        </div>

        <div className="flex items-center gap-2">
          <Filter className="w-4 h-4 text-slate-500" />
          <select
            value={severityFilter}
            onChange={e => setSeverityFilter(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-blue-500 font-mono"
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
            <option value="INFORMATIONAL">Informational</option>
          </select>
        </div>
      </div>

      {/* High-Density Audit Table */}
      <div className="bg-slate-900/90 border border-slate-800 rounded overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-950 text-slate-400 text-[11px] border-b border-slate-800">
              <tr>
                <th className="py-2.5 px-3">Timestamp</th>
                <th className="py-2.5 px-3">Severity</th>
                <th className="py-2.5 px-3">Actor</th>
                <th className="py-2.5 px-3">Action</th>
                <th className="py-2.5 px-3">Target</th>
                <th className="py-2.5 px-3">MITRE ID</th>
                <th className="py-2.5 px-3">Details</th>
                <th className="py-2.5 px-3">SHA-256 Checksum</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              {filteredLogs.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-8 text-center text-slate-500 font-mono text-xs">
                    No audit records matching current filter criteria.
                  </td>
                </tr>
              ) : (
                filteredLogs.map(log => (
                  <tr key={log.id} className="hover:bg-slate-800/40 transition-colors">
                    <td className="py-2.5 px-3 text-slate-400 whitespace-nowrap">
                      {new Date(log.timestamp).toLocaleTimeString()}
                    </td>
                    <td className="py-2.5 px-3 whitespace-nowrap">
                      <span className={getSeverityStyle(log.severity)}>{log.severity}</span>
                    </td>
                    <td className="py-2.5 px-3 text-slate-300 whitespace-nowrap">{log.actor}</td>
                    <td className="py-2.5 px-3 font-semibold text-slate-200 whitespace-nowrap">{log.action}</td>
                    <td className="py-2.5 px-3 text-blue-300 whitespace-nowrap">{log.target}</td>
                    <td className="py-2.5 px-3 whitespace-nowrap">
                      {log.mitreId ? (
                        <span className="text-red-400 font-semibold">{log.mitreId}</span>
                      ) : (
                        <span className="text-slate-600">-</span>
                      )}
                    </td>
                    <td className="py-2.5 px-3 text-slate-300 min-w-[280px]">
                      {log.details}
                    </td>
                    <td className="py-2.5 px-3 text-[10px] text-slate-500 whitespace-nowrap font-mono" title={log.checksum}>
                      {log.checksum.slice(0, 16)}...
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
