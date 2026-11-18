import React, { useState } from 'react';
import { Shield, Radio, Play, ChevronDown, Flame, Bug, Terminal, CheckCircle2, AlertTriangle } from 'lucide-react';

interface NavbarProps {
  wsConnected: boolean;
  onSimulate: (eventType?: string, scenario?: string) => Promise<void>;
  isSimulating: boolean;
}

export const Navbar: React.FC<NavbarProps> = ({ wsConnected, onSimulate, isSimulating }) => {
  const [dropdownOpen, setDropdownOpen] = useState(false);

  const scenarios = [
    { type: 'phishing_email', scenario: 'credential_phishing', label: '🎣 Phishing: Credential Harvesting', desc: 'Urgent password reset link' },
    { type: 'phishing_email', scenario: 'ceo_fraud', label: '💼 Phishing: CEO Wire Fraud', desc: 'Urgent $25k transfer request' },
    { type: 'phishing_email', scenario: 'malware_attachment', label: '📎 Phishing: Malware Attachment', desc: 'Invoice with executable payload' },
    { type: 'phishing_email', scenario: 'benign_email', label: '✉️ Email: Benign Newsletter (FP Test)', desc: 'Valid GitHub weekly digest' },
    { type: 'auth_log', scenario: 'brute_force', label: '🔨 Auth: Brute Force Attack', desc: '60+ rapid failed password attempts' },
    { type: 'auth_log', scenario: 'impossible_travel', label: '✈️ Auth: Impossible Travel', desc: 'US and RU logins within 10 min' },
    { type: 'auth_log', scenario: 'credential_stuffing', label: '🤖 Auth: Credential Stuffing', desc: 'Automated multi-user login attempts' },
    { type: 'auth_log', scenario: 'normal_login', label: '👤 Auth: Normal SSO Login (FP Test)', desc: 'Valid MFA authenticated session' },
    { type: 'malware_alert', scenario: 'known_malware', label: '🦠 Endpoint: Known Trojan Executable', desc: 'CrowdStrike Trojan.GenericKD match' },
    { type: 'malware_alert', scenario: 'clean_file', label: '📄 Endpoint: Clean PDF Alert (FP Test)', desc: 'Legitimate document falsely flagged' },
  ];

  return (
    <header className="border-b border-slate-800 bg-[#0d1322]/90 backdrop-blur sticky top-0 z-50 px-6 py-3.5 flex items-center justify-between">
      {/* Brand & SOC Status */}
      <div className="flex items-center space-x-4">
        <div className="flex items-center space-x-3">
          <div className="p-2 bg-blue-500/10 border border-blue-500/20 rounded-lg text-blue-400">
            <Shield className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <span className="font-bold text-lg text-slate-100 tracking-tight font-mono">AUTOSOC</span>
              <span className="text-xs font-semibold px-2 py-0.5 rounded bg-blue-950 text-blue-400 border border-blue-800 uppercase tracking-wider">
                SENTINEL
              </span>
              <span className="text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">
                DRY-RUN / SIMULATED
              </span>
            </div>
            <p className="text-xs text-slate-400">Autonomous Incident Response • Human-in-the-Loop</p>
          </div>
        </div>

        {/* Live Stream Status Indicator */}
        <div className="hidden md:flex items-center space-x-2 border-l border-slate-800 pl-4 py-1">
          <span className="relative flex h-2.5 w-2.5">
            {wsConnected ? (
              <>
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-emerald-500"></span>
              </>
            ) : (
              <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-rose-500"></span>
            )}
          </span>
          <span className="text-xs font-mono text-slate-300">
            {wsConnected ? 'LIVE FEED ACTIVE' : 'CONNECTING WS...'}
          </span>
        </div>
      </div>

      {/* Simulator Controls */}
      <div className="flex items-center space-x-3 relative">
        <button
          onClick={() => onSimulate()}
          disabled={isSimulating}
          className="flex items-center space-x-2 bg-gradient-to-r from-red-600 to-rose-600 hover:from-red-500 hover:to-rose-500 disabled:opacity-50 text-white font-medium text-xs px-4 py-2 rounded-lg shadow-lg shadow-red-950/50 transition border border-red-500/30"
        >
          <Flame className={`w-4 h-4 ${isSimulating ? 'animate-spin' : ''}`} />
          <span>{isSimulating ? 'Analyzing...' : 'Simulate Random Attack'}</span>
        </button>

        {/* Dropdown for specific scenarios */}
        <div className="relative">
          <button
            onClick={() => setDropdownOpen(!dropdownOpen)}
            className="flex items-center space-x-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs px-3 py-2 rounded-lg border border-slate-700 transition"
          >
            <span>Scenario</span>
            <ChevronDown className="w-3.5 h-3.5" />
          </button>

          {dropdownOpen && (
            <div className="absolute right-0 mt-2 w-80 bg-slate-900 border border-slate-700 rounded-xl shadow-2xl overflow-hidden z-50 max-h-96 overflow-y-auto">
              <div className="px-3 py-2 bg-slate-950 border-b border-slate-800 text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
                Select Telemetry Scenario
              </div>
              <div className="py-1">
                {scenarios.map((s, idx) => (
                  <button
                    key={idx}
                    onClick={() => {
                      setDropdownOpen(false);
                      onSimulate(s.type, s.scenario);
                    }}
                    className="w-full text-left px-3 py-2 hover:bg-slate-800/80 transition flex flex-col border-b border-slate-800/50 last:border-0"
                  >
                    <span className="text-xs font-medium text-slate-200">{s.label}</span>
                    <span className="text-[11px] text-slate-400">{s.desc}</span>
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </header>
  );
};
