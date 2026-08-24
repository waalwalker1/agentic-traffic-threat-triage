import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Shield,
  Activity,
  AlertTriangle,
  Search,
  CheckCircle2,
  Layers,
  BarChart3,
  Sparkles,
  Database,
} from 'lucide-react';

const API_BASE = (import.meta as any).env?.VITE_API_BASE || '';

export function App() {
  const [activeTab, setActiveTab] = useState<'overview' | 'sessions' | 'incidents' | 'evals'>('overview');
  const [selectedSessionId, setSelectedSessionId] = useState<string | null>(null);
  const [selectedIncidentId, setSelectedIncidentId] = useState<string | null>(null);
  const [dispositionNotes, setDispositionNotes] = useState('');

  const queryClient = useQueryClient();

  // Queries
  const readyQuery = useQuery({
    queryKey: ['ready'],
    queryFn: () => fetch(`${API_BASE}/ready`).then((r) => r.json()),
    refetchInterval: 10000,
  });

  const sessionsQuery = useQuery({
    queryKey: ['sessions'],
    queryFn: () => fetch(`${API_BASE}/api/v1/sessions?limit=50`).then((r) => r.json()),
  });

  const sessionDetailQuery = useQuery({
    queryKey: ['session', selectedSessionId],
    queryFn: () => fetch(`${API_BASE}/api/v1/sessions/${selectedSessionId}`).then((r) => r.json()),
    enabled: !!selectedSessionId,
  });

  const incidentsQuery = useQuery({
    queryKey: ['incidents'],
    queryFn: () => fetch(`${API_BASE}/api/v1/incidents?limit=50`).then((r) => r.json()),
  });

  const incidentDetailQuery = useQuery({
    queryKey: ['incident', selectedIncidentId],
    queryFn: () => fetch(`${API_BASE}/api/v1/incidents/${selectedIncidentId}`).then((r) => r.json()),
    enabled: !!selectedIncidentId,
  });

  const evalsQuery = useQuery({
    queryKey: ['evals'],
    queryFn: () => fetch(`${API_BASE}/api/v1/evals/latest`).then((r) => r.json()),
  });

  // Mutations
  const triageMutation = useMutation({
    mutationFn: (sessionId: string) =>
      fetch(`${API_BASE}/api/v1/sessions/${sessionId}/triage`, { method: 'POST' }).then((r) => r.json()),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['incidents'] });
      setSelectedIncidentId(data.incident_id);
      setActiveTab('incidents');
    },
  });

  const dispositionMutation = useMutation({
    mutationFn: ({ incidentId, disposition, notes }: { incidentId: string; disposition: string; notes: string }) =>
      fetch(`${API_BASE}/api/v1/incidents/${incidentId}/disposition`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ disposition, notes }),
      }).then((r) => r.json()),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['incidents'] });
      queryClient.invalidateQueries({ queryKey: ['incident', selectedIncidentId] });
      setDispositionNotes('');
    },
  });

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-sky-500 selection:text-white">
      {/* Top Navigation */}
      <header className="border-b border-slate-800/80 bg-slate-900/60 backdrop-blur px-6 py-3.5 flex items-center justify-between sticky top-0 z-50">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-sky-500/10 border border-sky-500/30 rounded-lg text-sky-400">
            <Shield className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-base font-bold text-white tracking-wide flex items-center gap-2">
              Agentic Traffic Threat Triage
              <span className="text-xs px-2 py-0.5 rounded-full bg-slate-800 text-slate-400 font-mono font-normal">
                v0.1.0-remediated
              </span>
            </h1>
            <p className="text-xs text-slate-400">
              Defensive Traffic-Intelligence & Grounded Multi-Agent SOC Investigation
            </p>
          </div>
        </div>

        {/* System Status Indicators */}
        <div className="flex items-center gap-4 text-xs">
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-md bg-slate-900 border border-slate-800">
            <span
              className={`w-2 h-2 rounded-full ${
                readyQuery.data?.models_loaded ? 'bg-emerald-400' : 'bg-amber-400'
              }`}
            />
            <span className="text-slate-300">
              Models:{' '}
              <strong className="text-white">
                {readyQuery.data?.models_loaded ? 'Loaded (Trained Bundle)' : 'Loading / Demo'}
              </strong>
            </span>
          </div>

          <div className="flex items-center gap-2 px-3 py-1.5 rounded-md bg-slate-900 border border-slate-800">
            <Database className="w-3.5 h-3.5 text-sky-400" />
            <span className="text-slate-300">
              Storage: <strong className="text-white">DuckDB (Analytical)</strong>
            </span>
          </div>
        </div>
      </header>

      {/* Main Layout Grid */}
      <div className="flex-1 flex overflow-hidden">
        {/* Sidebar Navigation */}
        <aside className="w-64 border-r border-slate-800/80 bg-slate-900/30 p-4 space-y-2 flex flex-col justify-between shrink-0">
          <div className="space-y-1">
            <button
              onClick={() => setActiveTab('overview')}
              className={`w-full flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium transition ${
                activeTab === 'overview'
                  ? 'bg-sky-600 text-white'
                  : 'text-slate-400 hover:bg-slate-800/60 hover:text-slate-200'
              }`}
            >
              <Activity className="w-4 h-4" />
              <span>SOC Overview</span>
            </button>
            <button
              onClick={() => setActiveTab('sessions')}
              className={`w-full flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium transition ${
                activeTab === 'sessions'
                  ? 'bg-sky-600 text-white'
                  : 'text-slate-400 hover:bg-slate-800/60 hover:text-slate-200'
              }`}
            >
              <Layers className="w-4 h-4" />
              <span>Session Explorer</span>
              {sessionsQuery.data && (
                <span className="ml-auto text-xs px-1.5 py-0.5 rounded bg-slate-800 text-slate-300">
                  {sessionsQuery.data.length}
                </span>
              )}
            </button>
            <button
              onClick={() => setActiveTab('incidents')}
              className={`w-full flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium transition ${
                activeTab === 'incidents'
                  ? 'bg-sky-600 text-white'
                  : 'text-slate-400 hover:bg-slate-800/60 hover:text-slate-200'
              }`}
            >
              <AlertTriangle className="w-4 h-4" />
              <span>Incident Triage</span>
              {incidentsQuery.data && (
                <span className="ml-auto text-xs px-1.5 py-0.5 rounded bg-slate-800 text-slate-300">
                  {incidentsQuery.data.length}
                </span>
              )}
            </button>
            <button
              onClick={() => setActiveTab('evals')}
              className={`w-full flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium transition ${
                activeTab === 'evals'
                  ? 'bg-sky-600 text-white'
                  : 'text-slate-400 hover:bg-slate-800/60 hover:text-slate-200'
              }`}
            >
              <BarChart3 className="w-4 h-4" />
              <span>Benchmark Evals</span>
            </button>
          </div>

          <div className="pt-4 border-t border-slate-800/80">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 px-3 mb-2">
              Architecture Invariants
            </h3>
            <div className="space-y-1 text-xs text-slate-400 px-3">
              <div className="flex items-center gap-1.5 py-1">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                <span>Defensive-Only Boundary</span>
              </div>
              <div className="flex items-center gap-1.5 py-1">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                <span>Deterministic Score Protection</span>
              </div>
              <div className="flex items-center gap-1.5 py-1">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                <span>Evidence Grounding Verification</span>
              </div>
              <div className="flex items-center gap-1.5 py-1">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                <span>Zero Cloud Credentials Required</span>
              </div>
            </div>
          </div>
        </aside>

        {/* Content Body */}
        <main className="flex-1 p-6 overflow-y-auto">
          {/* TAB 1: OVERVIEW */}
          {activeTab === 'overview' && (
            <div className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                <div className="p-5 bg-slate-900/60 border border-slate-800 rounded-xl">
                  <div className="text-xs font-medium text-slate-400 uppercase">Total Sessions Ingested</div>
                  <div className="mt-2 text-3xl font-bold text-white">
                    {sessionsQuery.data ? sessionsQuery.data.length : '...'}
                  </div>
                  <div className="mt-1 text-xs text-slate-500">From 30 synthetic scenario families</div>
                </div>

                <div className="p-5 bg-slate-900/60 border border-slate-800 rounded-xl">
                  <div className="text-xs font-medium text-slate-400 uppercase">Triaged Incidents</div>
                  <div className="mt-2 text-3xl font-bold text-sky-400">
                    {incidentsQuery.data ? incidentsQuery.data.length : '0'}
                  </div>
                  <div className="mt-1 text-xs text-slate-500">Synthesized by 6-role SOC crew</div>
                </div>

                <div className="p-5 bg-slate-900/60 border border-slate-800 rounded-xl">
                  <div className="text-xs font-medium text-slate-400 uppercase">Model Runtime Mode</div>
                  <div className="mt-2 text-2xl font-bold text-emerald-400">
                    {readyQuery.data?.model_mode || 'trained'}
                  </div>
                  <div className="mt-1 text-xs text-slate-500">
                    Bundle: {readyQuery.data?.bundle_version || '1.0.0'}
                  </div>
                </div>

                <div className="p-5 bg-slate-900/60 border border-slate-800 rounded-xl">
                  <div className="text-xs font-medium text-slate-400 uppercase">Risk Policy Fusion</div>
                  <div className="mt-2 text-2xl font-bold text-purple-400">
                    {readyQuery.data?.risk_policy_version || '2026.1.0'}
                  </div>
                  <div className="mt-1 text-xs text-slate-500">Deterministic Hard Overrides</div>
                </div>
              </div>

              {/* Quick Action Banner */}
              <div className="p-6 bg-gradient-to-r from-sky-900/40 via-slate-900 to-indigo-900/30 border border-sky-500/20 rounded-2xl flex items-center justify-between">
                <div>
                  <h2 className="text-lg font-bold text-white">Explore Synthetic Traffic & Triage Incidents</h2>
                  <p className="text-sm text-slate-300 mt-1 max-w-2xl">
                    Inspect deterministic 32-feature sessions, Ed25519 cryptographic identity verifications, and MCP protocol sequence traces. Trigger evidence-grounded agent triage with one click.
                  </p>
                </div>
                <button
                  onClick={() => setActiveTab('sessions')}
                  className="px-4 py-2 bg-sky-600 hover:bg-sky-500 text-white text-sm font-semibold rounded-lg shadow-lg shadow-sky-600/30 transition flex items-center gap-2"
                >
                  <Search className="w-4 h-4" />
                  <span>Launch Session Explorer</span>
                </button>
              </div>
            </div>
          )}

          {/* TAB 2: SESSIONS */}
          {activeTab === 'sessions' && (
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* Session List */}
              <div className="lg:col-span-1 border border-slate-800 bg-slate-900/40 rounded-xl p-4 space-y-3">
                <div className="flex items-center justify-between pb-2 border-b border-slate-800">
                  <h2 className="text-sm font-bold text-white uppercase tracking-wider">Sessions</h2>
                  <span className="text-xs text-slate-400 font-mono">
                    {sessionsQuery.data?.length || 0} items
                  </span>
                </div>

                <div className="space-y-2 max-h-[700px] overflow-y-auto pr-1">
                  {sessionsQuery.data?.map((s: any) => (
                    <div
                      key={s.session_id}
                      onClick={() => setSelectedSessionId(s.session_id)}
                      className={`p-3 rounded-lg border cursor-pointer transition text-xs ${
                        selectedSessionId === s.session_id
                          ? 'border-sky-500 bg-sky-950/40 text-white'
                          : 'border-slate-800/80 bg-slate-900/60 text-slate-300 hover:border-slate-700'
                      }`}
                    >
                      <div className="font-mono font-semibold text-sky-400 truncate">{s.session_id}</div>
                      <div className="flex items-center justify-between mt-1 text-slate-400">
                        <span>{s.event_count} events</span>
                        <span>{new Date(s.start_time).toLocaleTimeString()}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Session Detail & Forensic Inspection */}
              <div className="lg:col-span-2 border border-slate-800 bg-slate-900/40 rounded-xl p-6 space-y-6">
                {selectedSessionId && sessionDetailQuery.data ? (
                  <>
                    <div className="flex items-center justify-between border-b border-slate-800 pb-4">
                      <div>
                        <div className="text-xs text-slate-400 uppercase font-mono">Selected Session</div>
                        <h3 className="text-base font-bold text-white font-mono">{selectedSessionId}</h3>
                      </div>
                      <button
                        onClick={() => triageMutation.mutate(selectedSessionId)}
                        disabled={triageMutation.isPending}
                        className="px-4 py-2 bg-sky-600 hover:bg-sky-500 disabled:bg-slate-800 text-white text-xs font-semibold rounded-lg flex items-center gap-2 shadow-lg shadow-sky-600/20"
                      >
                        <Sparkles className="w-3.5 h-3.5" />
                        <span>{triageMutation.isPending ? 'Triaging...' : 'Run 6-Agent Triage'}</span>
                      </button>
                    </div>

                    {/* Forensic Evidence Items */}
                    <div>
                      <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider mb-2">
                        Deterministic Evidence Items ({sessionDetailQuery.data.evidence_items?.length || 0})
                      </h4>
                      <div className="space-y-2">
                        {sessionDetailQuery.data.evidence_items?.map((ev: any) => (
                          <div key={ev.evidence_id} className="p-3 bg-slate-950/80 border border-slate-800 rounded-lg text-xs">
                            <div className="flex items-center justify-between">
                              <span className="font-mono text-sky-400 font-semibold">{ev.evidence_id}</span>
                              <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 uppercase text-[10px]">
                                {ev.kind}
                              </span>
                            </div>
                            <p className="mt-1 text-slate-300">{ev.human_readable_explanation}</p>
                            <div className="mt-1 text-[11px] text-slate-400 font-mono">
                              Observed: <strong className="text-white">{String(ev.observed_value)}</strong> | Expected: {ev.expected_range_or_context}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  </>
                ) : (
                  <div className="py-24 text-center text-slate-500 text-sm">
                    Select a session from the list to inspect forensic telemetry and trigger triage.
                  </div>
                )}
              </div>
            </div>
          )}

          {/* TAB 3: INCIDENTS */}
          {activeTab === 'incidents' && (
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* Incident List */}
              <div className="lg:col-span-1 border border-slate-800 bg-slate-900/40 rounded-xl p-4 space-y-3">
                <div className="flex items-center justify-between pb-2 border-b border-slate-800">
                  <h2 className="text-sm font-bold text-white uppercase tracking-wider">Incidents</h2>
                  <span className="text-xs text-slate-400 font-mono">{incidentsQuery.data?.length || 0}</span>
                </div>
                <div className="space-y-2 max-h-[700px] overflow-y-auto pr-1">
                  {incidentsQuery.data?.map((inc: any) => (
                    <div
                      key={inc.incident_id}
                      onClick={() => setSelectedIncidentId(inc.incident_id)}
                      className={`p-3 rounded-lg border cursor-pointer transition text-xs ${
                        selectedIncidentId === inc.incident_id
                          ? 'border-sky-500 bg-sky-950/40 text-white'
                          : 'border-slate-800/80 bg-slate-900/60 text-slate-300 hover:border-slate-700'
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-mono font-semibold text-sky-400 truncate">{inc.incident_id}</span>
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            inc.risk_band === 'CRITICAL'
                              ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                              : inc.risk_band === 'HIGH'
                              ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                              : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                          }`}
                        >
                          {inc.risk_band} ({inc.risk_score})
                        </span>
                      </div>
                      <div className="mt-1 text-slate-400 truncate">{inc.identity_assessment}</div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Incident Brief & Human Disposition */}
              <div className="lg:col-span-2 border border-slate-800 bg-slate-900/40 rounded-xl p-6 space-y-6">
                {selectedIncidentId && incidentDetailQuery.data ? (
                  <>
                    <div className="flex items-center justify-between border-b border-slate-800 pb-4">
                      <div>
                        <div className="text-xs text-slate-400 font-mono">Incident Brief</div>
                        <h3 className="text-lg font-bold text-white font-mono">{selectedIncidentId}</h3>
                      </div>
                      <div className="text-right">
                        <div className="text-xs text-slate-400">Deterministic Policy Score</div>
                        <div className="text-2xl font-bold text-rose-400">
                          {incidentDetailQuery.data.risk_score} ({incidentDetailQuery.data.risk_band})
                        </div>
                      </div>
                    </div>

                    {/* Key Grounded Findings */}
                    <div>
                      <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider mb-2">
                        Grounded Findings & Citations
                      </h4>
                      <ul className="space-y-2 text-xs">
                        {incidentDetailQuery.data.grounded_findings?.map((gf: any, i: number) => (
                          <li key={i} className="p-3 bg-slate-950/80 border border-slate-800 rounded-lg">
                            <p className="text-slate-200">{gf.finding}</p>
                            <div className="mt-1 flex items-center gap-1.5 text-[11px] text-sky-400 font-mono">
                              <span>Citations:</span>
                              {gf.evidence_ids?.map((cid: string) => (
                                <span key={cid} className="px-1.5 py-0.5 rounded bg-sky-950 border border-sky-800 text-[10px]">
                                  {cid}
                                </span>
                              ))}
                            </div>
                          </li>
                        ))}
                      </ul>
                    </div>

                    {/* Critic Review */}
                    {incidentDetailQuery.data.critic_review && (
                      <div className="p-4 bg-slate-950/80 border border-slate-800 rounded-xl">
                        <div className="flex items-center justify-between">
                          <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider">
                            Evidence Critic Verdict
                          </h4>
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                              incidentDetailQuery.data.critic_review.approved
                                ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                                : 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                            }`}
                          >
                            {incidentDetailQuery.data.critic_review.approved ? 'APPROVED' : 'REJECTED'}
                          </span>
                        </div>
                      </div>
                    )}

                    {/* Human Disposition Form */}
                    <div className="p-4 bg-slate-950/80 border border-slate-800 rounded-xl space-y-3">
                      <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider">
                        Record Human Analyst Disposition
                      </h4>
                      {incidentDetailQuery.data.analyst_disposition && (
                        <div className="text-xs text-slate-400">
                          Current: <strong className="text-sky-400">{incidentDetailQuery.data.analyst_disposition.disposition}</strong> (by {incidentDetailQuery.data.analyst_disposition.analyst_id})
                        </div>
                      )}
                      <textarea
                        value={dispositionNotes}
                        onChange={(e) => setDispositionNotes(e.target.value)}
                        placeholder="Enter SOC analyst forensic notes..."
                        className="w-full p-2.5 bg-slate-900 border border-slate-800 rounded-lg text-xs text-white placeholder-slate-500 focus:outline-none focus:border-sky-500"
                        rows={2}
                      />
                      <div className="flex items-center gap-2">
                        <button
                          onClick={() =>
                            dispositionMutation.mutate({
                              incidentId: selectedIncidentId,
                              disposition: 'CONFIRMED_ABUSE',
                              notes: dispositionNotes,
                            })
                          }
                          className="px-3 py-1.5 bg-rose-600 hover:bg-rose-500 text-white text-xs font-semibold rounded"
                        >
                          Confirmed Abuse
                        </button>
                        <button
                          onClick={() =>
                            dispositionMutation.mutate({
                              incidentId: selectedIncidentId,
                              disposition: 'SUSPICIOUS_MONITOR',
                              notes: dispositionNotes,
                            })
                          }
                          className="px-3 py-1.5 bg-amber-600 hover:bg-amber-500 text-white text-xs font-semibold rounded"
                        >
                          Monitor
                        </button>
                        <button
                          onClick={() =>
                            dispositionMutation.mutate({
                              incidentId: selectedIncidentId,
                              disposition: 'FALSE_POSITIVE',
                              notes: dispositionNotes,
                            })
                          }
                          className="px-3 py-1.5 bg-slate-700 hover:bg-slate-600 text-white text-xs font-semibold rounded"
                        >
                          False Positive
                        </button>
                      </div>
                    </div>
                  </>
                ) : (
                  <div className="py-24 text-center text-slate-500 text-sm">
                    Select an incident brief to view findings, critic verdict, and record disposition.
                  </div>
                )}
              </div>
            </div>
          )}

          {/* TAB 4: EVALS */}
          {activeTab === 'evals' && (
            <div className="space-y-6">
              <div className="flex items-center justify-between border-b border-slate-800 pb-4">
                <div>
                  <h2 className="text-lg font-bold text-white">Reproducible Benchmark Evaluations</h2>
                  <p className="text-xs text-slate-400">
                    Synthetic benchmarks covering Track A (IID), Track B (OOD 5-fold), Hard Negatives (N=500), and Agent Grounding.
                  </p>
                </div>
              </div>

              {evalsQuery.data && evalsQuery.data.iid ? (
                <>
                  {/* Track A: IID Metrics */}
                  <div>
                    <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider mb-3">
                      Track A: In-Distribution (IID) Held-out Benchmark (N={evalsQuery.data.iid?.n_samples})
                    </h3>
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                      <div className="p-4 bg-slate-900/60 border border-slate-800 rounded-xl">
                        <div className="text-xs text-slate-400 uppercase font-medium">Precision</div>
                        <div className="mt-1 text-2xl font-bold text-emerald-400">
                          {(evalsQuery.data.iid.precision * 100).toFixed(1)}%
                        </div>
                      </div>
                      <div className="p-4 bg-slate-900/60 border border-slate-800 rounded-xl">
                        <div className="text-xs text-slate-400 uppercase font-medium">Recall</div>
                        <div className="mt-1 text-2xl font-bold text-sky-400">
                          {(evalsQuery.data.iid.recall * 100).toFixed(1)}%
                        </div>
                      </div>
                      <div className="p-4 bg-slate-900/60 border border-slate-800 rounded-xl">
                        <div className="text-xs text-slate-400 uppercase font-medium">F1 Score</div>
                        <div className="mt-1 text-2xl font-bold text-purple-400">
                          {evalsQuery.data.iid.f1}
                        </div>
                      </div>
                      <div className="p-4 bg-slate-900/60 border border-slate-800 rounded-xl">
                        <div className="text-xs text-slate-400 uppercase font-medium">Brier Score</div>
                        <div className="mt-1 text-2xl font-bold text-amber-400">
                          {evalsQuery.data.iid.brier_score}
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Track B: OOD Metrics & Hard Negatives */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div className="p-5 bg-slate-900/60 border border-slate-800 rounded-xl">
                      <h3 className="text-sm font-semibold text-slate-200 mb-2">
                        Track B: Out-of-Distribution (5-Fold Family Holdout)
                      </h3>
                      <p className="text-xs text-slate-400 mb-3">Entire scenario families withheld from training</p>
                      <div className="space-y-2 text-xs">
                        <div className="flex justify-between py-1 border-b border-slate-800">
                          <span className="text-slate-400">Mean F1 Score:</span>
                          <span className="font-bold text-purple-400">
                            {evalsQuery.data.family_holdout?.mean_f1} ± {evalsQuery.data.family_holdout?.std_f1}
                          </span>
                        </div>
                        <div className="flex justify-between py-1 border-b border-slate-800">
                          <span className="text-slate-400">Mean Recall:</span>
                          <span className="font-bold text-sky-400">
                            {evalsQuery.data.family_holdout?.mean_recall} ± {evalsQuery.data.family_holdout?.std_recall}
                          </span>
                        </div>
                        <div className="flex justify-between py-1 border-b border-slate-800">
                          <span className="text-slate-400">Mean FPR:</span>
                          <span className="font-bold text-emerald-400">
                            {evalsQuery.data.family_holdout?.mean_fpr} ± {evalsQuery.data.family_holdout?.std_fpr}
                          </span>
                        </div>
                      </div>
                    </div>

                    <div className="p-5 bg-slate-900/60 border border-slate-800 rounded-xl">
                      <h3 className="text-sm font-semibold text-slate-200 mb-2">
                        Hard-Negative Cohort (N={evalsQuery.data.hard_negatives?.n_benign_sessions})
                      </h3>
                      <p className="text-xs text-slate-400 mb-3">Legitimate automation and human browsing baselines</p>
                      <div className="space-y-2 text-xs">
                        <div className="flex justify-between py-1 border-b border-slate-800">
                          <span className="text-slate-400">False Positives Observed:</span>
                          <span className="font-bold text-emerald-400">
                            {evalsQuery.data.hard_negatives?.false_positive_count} / {evalsQuery.data.hard_negatives?.n_benign_sessions}
                          </span>
                        </div>
                        <div className="flex justify-between py-1 border-b border-slate-800">
                          <span className="text-slate-400">Estimated FPR:</span>
                          <span className="font-bold text-emerald-400">
                            {(evalsQuery.data.hard_negatives?.false_positive_rate * 100).toFixed(2)}%
                          </span>
                        </div>
                        <div className="flex justify-between py-1 border-b border-slate-800">
                          <span className="text-slate-400">95% Wilson Confidence Interval:</span>
                          <span className="font-mono text-slate-300">
                            [{evalsQuery.data.hard_negatives?.wilson_95_ci?.lower}, {evalsQuery.data.hard_negatives?.wilson_95_ci?.upper}]
                          </span>
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Agent Grounding & Security Verification */}
                  <div className="p-5 bg-slate-900/60 border border-slate-800 rounded-xl">
                    <h3 className="text-sm font-semibold text-slate-200 mb-3">
                      Observed Agent Grounding & Security Verification
                    </h3>
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-xs">
                      <div className="p-3 bg-slate-950 border border-slate-800 rounded-lg">
                        <div className="text-slate-400">Citation Validity Rate:</div>
                        <div className="mt-1 text-lg font-bold text-emerald-400">
                          {(evalsQuery.data.groundedness?.citation_validity_rate * 100).toFixed(1)}%
                        </div>
                      </div>
                      <div className="p-3 bg-slate-950 border border-slate-800 rounded-lg">
                        <div className="text-slate-400">Unsupported Claim Rate:</div>
                        <div className="mt-1 text-lg font-bold text-emerald-400">
                          {(evalsQuery.data.groundedness?.unsupported_claim_rate * 100).toFixed(1)}%
                        </div>
                      </div>
                      <div className="p-3 bg-slate-950 border border-slate-800 rounded-lg">
                        <div className="text-slate-400">Critic Challenge Catch Rate:</div>
                        <div className="mt-1 text-lg font-bold text-emerald-400">
                          {(evalsQuery.data.critic?.catch_rate * 100).toFixed(1)}%
                        </div>
                      </div>
                      <div className="p-3 bg-slate-950 border border-slate-800 rounded-lg">
                        <div className="text-slate-400">Injection Defense Pass Rate:</div>
                        <div className="mt-1 text-lg font-bold text-emerald-400">
                          {(evalsQuery.data.injection?.pass_rate * 100).toFixed(1)}%
                        </div>
                      </div>
                    </div>
                  </div>
                </>
              ) : (
                <div className="py-24 text-center text-slate-500 text-sm">
                  {evalsQuery.isLoading
                    ? 'Loading benchmark evaluations...'
                    : 'No evaluation reports available. Run "make eval" to generate benchmark results.'}
                </div>
              )}
            </div>
          )}
        </main>
      </div>
    </div>
  );
}

export default App;
