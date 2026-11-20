import React, { useEffect, useState, useRef, useCallback } from 'react';
import { Navbar } from './components/Navbar';
import { StatsBanner } from './components/StatsBanner';
import { IncidentQueue } from './components/IncidentQueue';
import { IncidentDetail } from './components/IncidentDetail';
import { DashboardStats, IncidentDetail as IncidentDetailType, IncidentSummary } from './types';

// Read API URL from environment variable, defaulting to http://localhost:8000
const API_BASE = (import.meta.env.VITE_API_URL || 'http://localhost:8000').replace(/\/$/, '');

function getWebSocketUrl(): string {
  if (API_BASE.startsWith('http://') || API_BASE.startsWith('https://')) {
    const wsProto = API_BASE.startsWith('https://') ? 'wss:' : 'ws:';
    const host = API_BASE.replace(/^https?:\/\//i, '');
    return `${wsProto}//${host}/ws/events`;
  }
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  return `${protocol}//${window.location.host}/ws/events`;
}

export const App: React.FC = () => {
  const [incidents, setIncidents] = useState<IncidentSummary[]>([]);
  const [selectedIncident, setSelectedIncident] = useState<IncidentDetailType | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [wsConnected, setWsConnected] = useState<boolean>(false);
  const [isSimulating, setIsSimulating] = useState<boolean>(false);
  const [isLoadingAction, setIsLoadingAction] = useState<boolean>(false);

  const selectedIdRef = useRef<string | null>(null);
  selectedIdRef.current = selectedId;

  // ── Fetch Functions ──────────────────────────────────────────

  const fetchStats = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/stats`);
      if (res.ok) {
        const data = await res.json();
        setStats(data);
      }
    } catch (e) {
      console.error('Failed to fetch stats:', e);
    }
  };

  const fetchIncidents = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/incidents`);
      if (res.ok) {
        const data: IncidentSummary[] = await res.json();
        setIncidents(data);
        if (!selectedIdRef.current && data.length > 0) {
          handleSelectIncident(data[0].id);
        }
      }
    } catch (e) {
      console.error('Failed to fetch incidents:', e);
    }
  };

  const fetchIncidentDetail = async (id: string) => {
    try {
      const res = await fetch(`${API_BASE}/api/incidents/${id}`);
      if (res.ok) {
        const data: IncidentDetailType = await res.json();
        setSelectedIncident(data);
      }
    } catch (e) {
      console.error('Failed to fetch incident detail:', e);
    }
  };

  const handleSelectIncident = (id: string) => {
    setSelectedId(id);
    fetchIncidentDetail(id);
  };

  // ── WebSocket Handler ────────────────────────────────────────

  useEffect(() => {
    let ws: WebSocket | null = null;
    let reconnectTimeout: ReturnType<typeof setTimeout> | null = null;

    const connectWS = () => {
      const wsUrl = getWebSocketUrl();
      try {
        ws = new WebSocket(wsUrl);

        ws.onopen = () => {
          setWsConnected(true);
        };

        ws.onmessage = (event) => {
          try {
            const msg = JSON.parse(event.data);
            fetchIncidents();
            fetchStats();

            if (selectedIdRef.current === msg.incident_id) {
              fetchIncidentDetail(msg.incident_id);
            }
          } catch (e) {
            // Heartbeat
          }
        };

        ws.onclose = () => {
          setWsConnected(false);
          reconnectTimeout = setTimeout(connectWS, 3000);
        };

        ws.onerror = () => {
          ws?.close();
        };
      } catch (e) {
        setWsConnected(false);
        reconnectTimeout = setTimeout(connectWS, 4000);
      }
    };

    connectWS();
    fetchStats();
    fetchIncidents();

    const interval = setInterval(() => {
      fetchStats();
      fetchIncidents();
    }, 10000);

    return () => {
      ws?.close();
      if (reconnectTimeout !== null) clearTimeout(reconnectTimeout);
      clearInterval(interval);
    };
  }, []);

  // ── Action Handlers ──────────────────────────────────────────

  const handleSimulate = async (eventType?: string, scenario?: string) => {
    setIsSimulating(true);
    try {
      const res = await fetch(`${API_BASE}/api/simulate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ event_type: eventType, scenario: scenario }),
      });
      if (res.ok) {
        const result = await res.json();
        if (result.incident_id) {
          handleSelectIncident(result.incident_id);
        }
        await fetchIncidents();
        await fetchStats();
      }
    } catch (e) {
      console.error('Simulation failed:', e);
    } finally {
      setIsSimulating(false);
    }
  };

  const handleApproveAction = async (actionId: string, comment?: string) => {
    if (!selectedId) return;
    setIsLoadingAction(true);
    try {
      const res = await fetch(`${API_BASE}/api/incidents/${selectedId}/actions/${actionId}/approve`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ analyst_comment: comment, approved_by: 'analyst' }),
      });
      if (res.ok) {
        await fetchIncidentDetail(selectedId);
        await fetchIncidents();
        await fetchStats();
      }
    } catch (e) {
      console.error('Approval failed:', e);
    } finally {
      setIsLoadingAction(false);
    }
  };

  const handleRejectAction = async (actionId: string, comment?: string) => {
    if (!selectedId) return;
    setIsLoadingAction(true);
    try {
      const res = await fetch(`${API_BASE}/api/incidents/${selectedId}/actions/${actionId}/reject`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ analyst_comment: comment, approved_by: 'analyst' }),
      });
      if (res.ok) {
        await fetchIncidentDetail(selectedId);
        await fetchIncidents();
        await fetchStats();
      }
    } catch (e) {
      console.error('Rejection failed:', e);
    } finally {
      setIsLoadingAction(false);
    }
  };

  const handleRollbackAction = async (actionId: string) => {
    if (!selectedId) return;
    setIsLoadingAction(true);
    try {
      const res = await fetch(`${API_BASE}/api/incidents/${selectedId}/actions/${actionId}/rollback`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ approved_by: 'analyst' }),
      });
      if (res.ok) {
        await fetchIncidentDetail(selectedId);
        await fetchIncidents();
        await fetchStats();
      }
    } catch (e) {
      console.error('Rollback failed:', e);
    } finally {
      setIsLoadingAction(false);
    }
  };

  const handleApproveAllRecommended = async () => {
    if (!selectedId) return;
    setIsLoadingAction(true);
    try {
      const res = await fetch(`${API_BASE}/api/incidents/${selectedId}/actions/approve-recommended`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ approved_by: 'analyst' }),
      });
      if (res.ok) {
        await fetchIncidentDetail(selectedId);
        await fetchIncidents();
        await fetchStats();
      }
    } catch (e) {
      console.error('Batch approval failed:', e);
    } finally {
      setIsLoadingAction(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#0a0d14] text-slate-100 flex flex-col font-sans">
      <Navbar
        wsConnected={wsConnected}
        onSimulate={handleSimulate}
        isSimulating={isSimulating}
      />

      <StatsBanner stats={stats} />

      {/* Main SOC Workspace */}
      <main className="flex-1 px-6 py-4 grid grid-cols-1 lg:grid-cols-12 gap-5 overflow-hidden">
        {/* Left Column: Live Incident Queue (4 cols on lg) */}
        <div className="lg:col-span-4 h-[calc(100vh-210px)]">
          <IncidentQueue
            incidents={incidents}
            selectedId={selectedId}
            onSelect={handleSelectIncident}
          />
        </div>

        {/* Right Column: Detailed Incident & HITL Containment (8 cols on lg) */}
        <div className="lg:col-span-8 h-[calc(100vh-210px)]">
          <IncidentDetail
            incident={selectedIncident}
            onApproveAction={handleApproveAction}
            onRejectAction={handleRejectAction}
            onRollbackAction={handleRollbackAction}
            onApproveAllRecommended={handleApproveAllRecommended}
            isLoading={isLoadingAction}
          />
        </div>
      </main>
    </div>
  );
};

export default App;
