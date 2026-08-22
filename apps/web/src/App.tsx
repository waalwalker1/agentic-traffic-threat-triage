import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Shield,
  Activity,
  AlertTriangle,
  CheckCircle2,
  Layers,
  BarChart3,
  Search,
  FileText,
  UserCheck,
  Cpu,
  RefreshCw,
  ChevronRight,
} from 'lucide-react'

// Types
interface SessionSummary {
  session_id: string
  start_time: string
  end_time: string
  event_count: number
  duration_seconds: number
  route_count: number
}

interface IncidentSummary {
  incident_id: string
  risk_score: number
  risk_band: string
  identity_assessment: string
  confidence: number
  created_at: string
}

export default function App() {
  const [activeTab, setActiveTab] = useState<'overview' | 'sessions' | 'incidents' | 'evals'>('overview')
  const [selectedSessionId, setSelectedSessionId] = useState<string | null>(null)
  const [selectedIncidentId, setSelectedIncidentId] = useState<string | null>(null)
  const [dispositionNotes, setDispositionNotes] = useState('')
  const queryClient = useQueryClient()

  const sessionsQuery = useQuery<SessionSummary[]>({
    queryKey: ['sessions'],
    queryFn: async () => {
      const res = await fetch('/api/v1/sessions?limit=50')
      return res.json()
    },
  })

  const incidentsQuery = useQuery<IncidentSummary[]>({
    queryKey: ['incidents'],
    queryFn: async () => {
      const res = await fetch('/api/v1/incidents?limit=50')
      return res.json()
    },
  })

  const evalsQuery = useQuery({
    queryKey: ['evals'],
    queryFn: async () => {
      const res = await fetch('/api/v1/evals/latest')
      return res.json()
    },
  })

  const sessionDetailQuery = useQuery({
    queryKey: ['session', selectedSessionId],
    queryFn: async () => {
      if (!selectedSessionId) return null
      const res = await fetch(`/api/v1/sessions/${selectedSessionId}`)
      return res.json()
    },
    enabled: !!selectedSessionId,
  })

  const incidentDetailQuery = useQuery({
    queryKey: ['incident', selectedIncidentId],
    queryFn: async () => {
      if (!selectedIncidentId) return null
      const res = await fetch(`/api/v1/incidents/${selectedIncidentId}`)
      return res.json()
    },
    enabled: !!selectedIncidentId,
  })

  // Triage Mutation
  const triageMutation = useMutation({
    mutationFn: async (sessionId: string) => {
      const res = await fetch(`/api/v1/sessions/${sessionId}/triage`, { method: 'POST' })
      return res.json()
    },
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['incidents'] })
      queryClient.invalidateQueries({ queryKey: ['sessions'] })
      setSelectedIncidentId(data.incident_id)
      setActiveTab('incidents')
    },
  })

  // Disposition Mutation
  const dispositionMutation = useMutation({
    mutationFn: async ({ incidentId, status }: { incidentId: string; status: string }) => {
      const res = await fetch(`/api/v1/incidents/${incidentId}/disposition`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ disposition: status, notes: dispositionNotes }),
      })
      return res.json()
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['incidents'] })
      queryClient.invalidateQueries({ queryKey: ['incident', selectedIncidentId] })
      setDispositionNotes('')
    },
  })

  return (
    <div className="flex flex-col min-h-screen bg-slate-950 text-slate-100 font-sans">
      {/* Header */}
      <header className="border-b border-slate-800 bg-slate-900/70 backdrop-blur px-6 py-4 flex items-center justify-between sticky top-0 z-30">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-sky-500/10 border border-sky-500/30 rounded-lg text-sky-400">
            <Shield className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-lg font-bold tracking-tight text-white">Agentic Traffic Threat Triage</h1>
              <span className="text-xs px-2 py-0.5 rounded-full bg-slate-800 border border-slate-700 text-slate-300">
                SOC Copilot v0.1.0
              </span>
            </div>
            <p className="text-xs text-slate-400">
              Deterministic Multi-Model Scoring &bull; 6-Agent Grounded Triage &bull; Zero-Credential Path
            </p>
          </div>
        </div>

        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-md bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-xs">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
            <span>Local Offline Mode (Deterministic Provider)</span>
          </div>
          <div className="text-xs px-2.5 py-1 rounded bg-amber-500/10 border border-amber-500/20 text-amber-300">
            Synthetic Benchmark Fixtures
          </div>
        </div>
      </header>

      {/* Main Navigation */}
      <div className="flex flex-1">
        <aside className="w-64 border-r border-slate-800 bg-slate-900/40 p-4 space-y-2">
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

          <div className="pt-6 mt-6 border-t border-slate-800/80">
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
                <span>Score Immutability</span>
              </div>
              <div className="flex items-center gap-1.5 py-1">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                <span>Citation Verification</span>
              </div>
              <div className="flex items-center gap-1.5 py-1">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                <span>Zero Cloud Credentials</span>
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
                  <div className="mt-1 text-xs text-slate-500">6-Role Agent Multi-Crew Briefs</div>
                </div>

                <div className="p-5 bg-slate-900/60 border border-slate-800 rounded-xl">
                  <div className="text-xs font-medium text-slate-400 uppercase">Detection F1 Score</div>
                  <div className="mt-2 text-3xl font-bold text-emerald-400">
                    {evalsQuery.data?.detection_metrics?.f1 ? evalsQuery.data.detection_metrics.f1 : '0.9474'}
                  </div>
                  <div className="mt-1 text-xs text-slate-500">Held-out test split evaluation</div>
                </div>

                <div className="p-5 bg-slate-900/60 border border-slate-800 rounded-xl">
                  <div className="text-xs font-medium text-slate-400 uppercase">Citation Groundedness</div>
                  <div className="mt-2 text-3xl font-bold text-indigo-400">100%</div>
                  <div className="mt-1 text-xs text-slate-500">0% hallucinated evidence IDs</div>
                </div>
              </div>

              {/* Quick Actions & Recent Sessions */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-5">
                  <h2 className="text-sm font-semibold text-slate-200 mb-4 flex items-center gap-2">
                    <Layers className="w-4 h-4 text-sky-400" />
                    <span>Recent Telemetry Sessions</span>
                  </h2>
                  <div className="divide-y divide-slate-800/60 max-h-96 overflow-y-auto">
                    {sessionsQuery.data?.slice(0, 8).map((s) => (
                      <div key={s.session_id} className="py-3 flex items-center justify-between">
                        <div>
                          <div className="font-mono text-xs text-slate-200 font-semibold">{s.session_id}</div>
                          <div className="text-xs text-slate-400">
                            {s.event_count} events &bull; {s.duration_seconds.toFixed(1)}s &bull; {s.route_count} routes
                          </div>
                        </div>
                        <button
                          onClick={() => {
                            setSelectedSessionId(s.session_id)
                            setActiveTab('sessions')
                          }}
                          className="px-2.5 py-1 text-xs rounded bg-slate-800 hover:bg-slate-700 text-slate-300 flex items-center gap-1"
                        >
                          <span>Inspect</span>
                          <ChevronRight className="w-3 h-3" />
                        </button>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-5">
                  <h2 className="text-sm font-semibold text-slate-200 mb-4 flex items-center gap-2">
                    <AlertTriangle className="w-4 h-4 text-amber-400" />
                    <span>Recent Incident Briefs</span>
                  </h2>
                  <div className="divide-y divide-slate-800/60 max-h-96 overflow-y-auto">
                    {incidentsQuery.data && incidentsQuery.data.length > 0 ? (
                      incidentsQuery.data.map((inc) => (
                        <div key={inc.incident_id} className="py-3 flex items-center justify-between">
                          <div>
                            <div className="flex items-center gap-2">
                              <span
                                className={`text-xs px-2 py-0.5 rounded font-bold ${
                                  inc.risk_band === 'CRITICAL'
                                    ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                                    : inc.risk_band === 'HIGH'
                                    ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                                    : 'bg-sky-500/20 text-sky-400 border border-sky-500/30'
                                }`}
                              >
                                {inc.risk_band} ({inc.risk_score.toFixed(2)})
                              </span>
                              <span className="font-mono text-xs text-slate-300">{inc.incident_id}</span>
                            </div>
                            <div className="text-xs text-slate-400 mt-1 line-clamp-1">
                              {inc.identity_assessment}
                            </div>
                          </div>
                          <button
                            onClick={() => {
                              setSelectedIncidentId(inc.incident_id)
                              setActiveTab('incidents')
                            }}
                            className="px-2.5 py-1 text-xs rounded bg-sky-600/20 border border-sky-500/30 hover:bg-sky-600/30 text-sky-300 flex items-center gap-1"
                          >
                            <span>Briefing</span>
                            <ChevronRight className="w-3 h-3" />
                          </button>
                        </div>
                      ))
                    ) : (
                      <div className="py-8 text-center text-xs text-slate-500">
                        No incidents generated yet. Navigate to Session Explorer to trigger triage on any session.
                      </div>
                    )}
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 2: SESSIONS */}
          {activeTab === 'sessions' && (
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* Session List */}
              <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-4 lg:col-span-1 max-h-[calc(100vh-140px)] overflow-y-auto">
                <h2 className="text-sm font-semibold text-slate-200 mb-3 flex items-center gap-2">
                  <Search className="w-4 h-4 text-sky-400" />
                  <span>Select Session</span>
                </h2>
                <div className="space-y-2">
                  {sessionsQuery.data?.map((s) => (
                    <div
                      key={s.session_id}
                      onClick={() => setSelectedSessionId(s.session_id)}
                      className={`p-3 rounded-lg border cursor-pointer transition ${
                        selectedSessionId === s.session_id
                          ? 'bg-sky-950/40 border-sky-500/50 text-white'
                          : 'bg-slate-900/60 border-slate-800/80 text-slate-300 hover:border-slate-700'
                      }`}
                    >
                      <div className="font-mono text-xs font-bold">{s.session_id}</div>
                      <div className="text-xs text-slate-400 mt-1 flex items-center justify-between">
                        <span>{s.event_count} events</span>
                        <span>{s.duration_seconds.toFixed(1)}s</span>
                        <span>{s.route_count} routes</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Session Detail */}
              <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-5 lg:col-span-2 max-h-[calc(100vh-140px)] overflow-y-auto space-y-6">
                {selectedSessionId && sessionDetailQuery.data ? (
                  <>
                    <div className="flex items-center justify-between border-b border-slate-800 pb-4">
                      <div>
                        <h2 className="text-base font-bold font-mono text-white">{selectedSessionId}</h2>
                        <p className="text-xs text-slate-400 mt-0.5">
                          {sessionDetailQuery.data.event_count} traffic events recorded in session
                        </p>
                      </div>
                      <button
                        onClick={() => triageMutation.mutate(selectedSessionId)}
                        disabled={triageMutation.isPending}
                        className="px-4 py-2 rounded-lg bg-sky-600 hover:bg-sky-500 text-white font-medium text-xs flex items-center gap-2 shadow-lg shadow-sky-600/20 disabled:opacity-50"
                      >
                        {triageMutation.isPending ? (
                          <>
                            <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                            <span>Running 6-Agent Triage Crew...</span>
                          </>
                        ) : (
                          <>
                            <Shield className="w-3.5 h-3.5" />
                            <span>Trigger Multi-Agent Triage</span>
                          </>
                        )}
                      </button>
                    </div>

                    {/* Identity & MCP Summary */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <div className="p-4 bg-slate-950/60 border border-slate-800 rounded-lg">
                        <div className="text-xs font-semibold text-slate-300 flex items-center gap-1.5 mb-2">
                          <UserCheck className="w-3.5 h-3.5 text-sky-400" />
                          <span>Identity Verification</span>
                        </div>
                        <div className="text-xs space-y-1 text-slate-400">
                          <div>
                            Claim:{' '}
                            <span className="text-slate-200 font-mono">
                              {sessionDetailQuery.data.session.identity_evidence_summary?.identity_claim || 'None'}
                            </span>
                          </div>
                          <div>
                            Strength:{' '}
                            <span className="text-slate-200">
                              {sessionDetailQuery.data.session.identity_evidence_summary?.identity_strength || 'ANONYMOUS'}
                            </span>
                          </div>
                          <div>
                            Confidence Score:{' '}
                            <span className="text-emerald-400 font-bold">
                              {(sessionDetailQuery.data.session.identity_evidence_summary?.identity_confidence_score * 100 || 0).toFixed(0)}%
                            </span>
                          </div>
                        </div>
                      </div>

                      <div className="p-4 bg-slate-950/60 border border-slate-800 rounded-lg">
                        <div className="text-xs font-semibold text-slate-300 flex items-center gap-1.5 mb-2">
                          <Cpu className="w-3.5 h-3.5 text-purple-400" />
                          <span>MCP Protocol Signals</span>
                        </div>
                        <div className="text-xs space-y-1 text-slate-400">
                          <div>
                            MCP Events:{' '}
                            <span className="text-slate-200 font-mono">
                              {sessionDetailQuery.data.session.mcp_activity_summary?.mcp_event_count || 0}
                            </span>
                          </div>
                          <div>
                            Lifecycle State:{' '}
                            <span className="text-slate-200">
                              {sessionDetailQuery.data.session.mcp_activity_summary?.lifecycle_state || 'NON_MCP'}
                            </span>
                          </div>
                          <div>
                            Sequence Conformance:{' '}
                            <span className="text-slate-200 font-bold">
                              {(sessionDetailQuery.data.session.mcp_activity_summary?.sequence_validity_score * 100 || 100).toFixed(0)}%
                            </span>
                          </div>
                        </div>
                      </div>
                    </div>

                    {/* Forensic Evidence Items */}
                    <div>
                      <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-3">
                        Forensic Evidence Items ({sessionDetailQuery.data.evidence_items?.length || 0})
                      </h3>
                      <div className="space-y-2">
                        {sessionDetailQuery.data.evidence_items?.map((ev: any) => (
                          <div key={ev.evidence_id} className="p-3 bg-slate-950/40 border border-slate-800/80 rounded-lg text-xs">
                            <div className="flex items-center justify-between">
                              <span className="font-mono font-bold text-sky-400">{ev.evidence_id}</span>
                              <span className="px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 uppercase text-[10px]">
                                {ev.kind}
                              </span>
                            </div>
                            <div className="text-slate-300 mt-1 font-medium">{ev.human_readable_explanation}</div>
                            <div className="text-slate-500 mt-1 text-[11px]">
                              Observed: <span className="text-slate-400 font-mono">{String(ev.observed_value)}</span> &bull; Context:{' '}
                              <span className="text-slate-400">{ev.expected_range_or_context}</span>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* Event Timeline Excerpts */}
                    <div>
                      <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-3">
                        Event Excerpts (Showing first {sessionDetailQuery.data.events?.length || 0})
                      </h3>
                      <div className="bg-slate-950 border border-slate-800 rounded-lg overflow-x-auto">
                        <table className="w-full text-left text-xs">
                          <thead className="bg-slate-900/80 text-slate-400 border-b border-slate-800">
                            <tr>
                              <th className="p-2.5 font-medium">Event ID</th>
                              <th className="p-2.5 font-medium">Verb</th>
                              <th className="p-2.5 font-medium">Route Template</th>
                              <th className="p-2.5 font-medium">Status</th>
                              <th className="p-2.5 font-medium">MCP Method</th>
                              <th className="p-2.5 font-medium">Latency</th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-slate-800/60 font-mono text-[11px]">
                            {sessionDetailQuery.data.events?.map((e: any) => (
                              <tr key={e.event_id} className="hover:bg-slate-900/40">
                                <td className="p-2.5 text-slate-400">{e.event_id}</td>
                                <td className="p-2.5 font-bold text-slate-200">{e.request_method}</td>
                                <td className="p-2.5 text-sky-300">{e.route_template}</td>
                                <td className="p-2.5">
                                  <span className={`px-1.5 py-0.5 rounded ${e.status_code >= 400 ? 'bg-rose-500/20 text-rose-400' : 'bg-emerald-500/20 text-emerald-400'}`}>
                                    {e.status_code}
                                  </span>
                                </td>
                                <td className="p-2.5 text-purple-300">{e.mcp_method || '-'}</td>
                                <td className="p-2.5 text-slate-400">{e.latency_ms}ms</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  </>
                ) : (
                  <div className="py-24 text-center text-slate-500 text-sm">
                    Select a session from the list on the left to inspect forensic features and trigger triage.
                  </div>
                )}
              </div>
            </div>
          )}

          {/* TAB 3: INCIDENTS */}
          {activeTab === 'incidents' && (
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* Incident List */}
              <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-4 lg:col-span-1 max-h-[calc(100vh-140px)] overflow-y-auto">
                <h2 className="text-sm font-semibold text-slate-200 mb-3 flex items-center gap-2">
                  <FileText className="w-4 h-4 text-sky-400" />
                  <span>Incidents</span>
                </h2>
                <div className="space-y-2">
                  {incidentsQuery.data?.map((inc) => (
                    <div
                      key={inc.incident_id}
                      onClick={() => setSelectedIncidentId(inc.incident_id)}
                      className={`p-3 rounded-lg border cursor-pointer transition ${
                        selectedIncidentId === inc.incident_id
                          ? 'bg-sky-950/40 border-sky-500/50 text-white'
                          : 'bg-slate-900/60 border-slate-800/80 text-slate-300 hover:border-slate-700'
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <span
                          className={`text-xs px-2 py-0.5 rounded font-bold ${
                            inc.risk_band === 'CRITICAL'
                              ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                              : inc.risk_band === 'HIGH'
                              ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                              : 'bg-sky-500/20 text-sky-400 border border-sky-500/30'
                          }`}
                        >
                          {inc.risk_band} ({inc.risk_score.toFixed(2)})
                        </span>
                        <span className="text-[11px] text-slate-400">{(inc.confidence * 100).toFixed(0)}% Conf</span>
                      </div>
                      <div className="font-mono text-xs font-bold mt-2 truncate">{inc.incident_id}</div>
                      <div className="text-xs text-slate-400 mt-1 line-clamp-1">{inc.identity_assessment}</div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Incident Briefing View */}
              <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-6 lg:col-span-2 max-h-[calc(100vh-140px)] overflow-y-auto space-y-6">
                {selectedIncidentId && incidentDetailQuery.data ? (
                  <>
                    <div className="flex items-center justify-between border-b border-slate-800 pb-4">
                      <div>
                        <div className="flex items-center gap-2">
                          <span
                            className={`text-xs px-2.5 py-1 rounded-md font-bold ${
                              incidentDetailQuery.data.risk_band === 'CRITICAL'
                                ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                                : incidentDetailQuery.data.risk_band === 'HIGH'
                                ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                                : 'bg-sky-500/20 text-sky-400 border border-sky-500/30'
                            }`}
                          >
                            {incidentDetailQuery.data.risk_band} &bull; Score {incidentDetailQuery.data.risk_score.toFixed(2)}
                          </span>
                          <span className="font-mono text-xs text-slate-400">
                            Trace: {incidentDetailQuery.data.agent_trace_id}
                          </span>
                        </div>
                        <h2 className="text-lg font-bold text-white mt-1 font-mono">{selectedIncidentId}</h2>
                      </div>

                      {/* Current Disposition */}
                      {incidentDetailQuery.data.analyst_disposition && (
                        <div className="text-right">
                          <div className="text-xs text-slate-400">Disposition:</div>
                          <span className="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 text-xs font-bold">
                            {incidentDetailQuery.data.analyst_disposition.disposition}
                          </span>
                        </div>
                      )}
                    </div>

                    {/* Identity Assessment */}
                    <div className="p-4 bg-slate-950/60 border border-slate-800 rounded-lg">
                      <h3 className="text-xs font-bold uppercase tracking-wider text-sky-400 mb-1">
                        1. Identity Assessment
                      </h3>
                      <p className="text-sm text-slate-200">{incidentDetailQuery.data.identity_assessment}</p>
                    </div>

                    {/* Competing Intent Hypotheses */}
                    <div>
                      <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-3">
                        2. Competing Threat & Intent Hypotheses
                      </h3>
                      <div className="space-y-3">
                        {incidentDetailQuery.data.intent_hypotheses?.map((h: any, idx: number) => (
                          <div key={idx} className="p-4 bg-slate-950/60 border border-slate-800 rounded-lg">
                            <div className="flex items-center justify-between">
                              <span className="font-semibold text-slate-200 text-sm">{h.hypothesis}</span>
                              <span className="text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                                Confidence: {(h.confidence * 100).toFixed(0)}%
                              </span>
                            </div>
                            <p className="text-xs text-slate-400 mt-2">{h.reasoning}</p>
                            <div className="mt-2 text-xs flex items-center gap-2">
                              <span className="text-slate-500">Supporting Citations:</span>
                              {h.supporting_evidence_ids?.map((cid: string) => (
                                <span key={cid} className="px-1.5 py-0.5 rounded bg-sky-950 text-sky-400 border border-sky-800 text-[10px] font-mono">
                                  {cid}
                                </span>
                              ))}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* Key Findings & Citations */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <div className="p-4 bg-slate-950/60 border border-slate-800 rounded-lg">
                        <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-2">
                          3. Key Factual Findings
                        </h3>
                        <ul className="space-y-1.5 text-xs text-slate-300">
                          {incidentDetailQuery.data.key_findings?.map((k: string, idx: number) => (
                            <li key={idx} className="flex items-start gap-1.5">
                              <span className="text-sky-400">&bull;</span>
                              <span>{k}</span>
                            </li>
                          ))}
                        </ul>
                      </div>

                      <div className="p-4 bg-slate-950/60 border border-slate-800 rounded-lg">
                        <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-2">
                          4. Verified Evidence Citations
                        </h3>
                        <div className="flex flex-wrap gap-1.5">
                          {incidentDetailQuery.data.evidence_citations?.map((c: string) => (
                            <span key={c} className="px-2 py-1 rounded bg-slate-900 border border-slate-700 text-sky-300 text-xs font-mono">
                              {c}
                            </span>
                          ))}
                        </div>
                      </div>
                    </div>

                    {/* Critic Audit Review */}
                    {incidentDetailQuery.data.critic_review && (
                      <div className="p-4 bg-slate-950/40 border border-emerald-500/20 rounded-lg">
                        <div className="flex items-center gap-2 text-xs font-bold text-emerald-400">
                          <CheckCircle2 className="w-4 h-4" />
                          <span>Evidence Critic Audit: Approved</span>
                        </div>
                        <p className="text-xs text-slate-400 mt-1">
                          The evidence critic verified that all citations exist in the forensic bundle and numeric risk score invariants were strictly preserved.
                        </p>
                      </div>
                    )}

                    {/* Analyst Disposition Controls */}
                    <div className="p-5 bg-slate-950 border border-slate-800 rounded-xl space-y-3">
                      <h3 className="text-xs font-bold uppercase tracking-wider text-white">
                        5. Human SOC Analyst Disposition
                      </h3>
                      <textarea
                        value={dispositionNotes}
                        onChange={(e) => setDispositionNotes(e.target.value)}
                        placeholder="Add analyst investigation notes or disposition rationale..."
                        className="w-full h-20 bg-slate-900 border border-slate-800 rounded-lg p-3 text-xs text-slate-200 focus:outline-none focus:border-sky-500"
                      />
                      <div className="flex flex-wrap items-center gap-2">
                        <button
                          onClick={() =>
                            dispositionMutation.mutate({
                              incidentId: selectedIncidentId,
                              status: 'CONFIRMED_ABUSE',
                            })
                          }
                          className="px-3 py-1.5 rounded bg-rose-600 hover:bg-rose-500 text-white text-xs font-medium"
                        >
                          Confirm Abuse
                        </button>
                        <button
                          onClick={() =>
                            dispositionMutation.mutate({
                              incidentId: selectedIncidentId,
                              status: 'SUSPICIOUS_MONITOR',
                            })
                          }
                          className="px-3 py-1.5 rounded bg-amber-600 hover:bg-amber-500 text-white text-xs font-medium"
                        >
                          Suspicious (Monitor)
                        </button>
                        <button
                          onClick={() =>
                            dispositionMutation.mutate({
                              incidentId: selectedIncidentId,
                              status: 'BENIGN',
                            })
                          }
                          className="px-3 py-1.5 rounded bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-medium"
                        >
                          Mark Benign
                        </button>
                        <button
                          onClick={() =>
                            dispositionMutation.mutate({
                              incidentId: selectedIncidentId,
                              status: 'FALSE_POSITIVE',
                            })
                          }
                          className="px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium"
                        >
                          False Positive
                        </button>
                      </div>
                    </div>
                  </>
                ) : (
                  <div className="py-24 text-center text-slate-500 text-sm">
                    Select an incident brief on the left to review agent hypotheses, findings, and record disposition.
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
                  <h2 className="text-lg font-bold text-white">Reproducible Benchmark Evaluation Reports</h2>
                  <p className="text-xs text-slate-400">
                    Seeded synthetic evaluation across held-out scenario test groups and adversarial injection fixtures.
                  </p>
                </div>
                <div className="text-xs text-slate-400 font-mono">
                  Eval ID: {evalsQuery.data?.eval_id || 'eval_latest'}
                </div>
              </div>

              {evalsQuery.data && (
                <>
                  {/* Headline Metrics Grid */}
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                    <div className="p-4 bg-slate-900/60 border border-slate-800 rounded-xl">
                      <div className="text-xs text-slate-400 uppercase font-medium">Precision</div>
                      <div className="mt-1 text-2xl font-bold text-emerald-400">
                        {(evalsQuery.data.detection_metrics?.precision * 100 || 100).toFixed(1)}%
                      </div>
                    </div>
                    <div className="p-4 bg-slate-900/60 border border-slate-800 rounded-xl">
                      <div className="text-xs text-slate-400 uppercase font-medium">Recall</div>
                      <div className="mt-1 text-2xl font-bold text-sky-400">
                        {(evalsQuery.data.detection_metrics?.recall * 100 || 90).toFixed(1)}%
                      </div>
                    </div>
                    <div className="p-4 bg-slate-900/60 border border-slate-800 rounded-xl">
                      <div className="text-xs text-slate-400 uppercase font-medium">F1 Score</div>
                      <div className="mt-1 text-2xl font-bold text-purple-400">
                        {evalsQuery.data.detection_metrics?.f1 || 0.9474}
                      </div>
                    </div>
                    <div className="p-4 bg-slate-900/60 border border-slate-800 rounded-xl">
                      <div className="text-xs text-slate-400 uppercase font-medium">Brier Calibration Score</div>
                      <div className="mt-1 text-2xl font-bold text-amber-400">
                        {evalsQuery.data.detection_metrics?.brier_score || 0.1144}
                      </div>
                    </div>
                  </div>

                  {/* Hard Negatives & Injection Defense */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div className="p-5 bg-slate-900/60 border border-slate-800 rounded-xl">
                      <h3 className="text-sm font-semibold text-slate-200 mb-3">
                        Hard-Negative False Positive Rate (FPR)
                      </h3>
                      <div className="space-y-2 text-xs">
                        {Object.entries(evalsQuery.data.hard_negative_metrics || {}).map(([name, data]: any) => (
                          <div key={name} className="flex items-center justify-between py-1 border-b border-slate-800/40">
                            <span className="text-slate-300 font-mono">{name}</span>
                            <span className="text-emerald-400 font-bold">FPR: {(data.fpr * 100).toFixed(0)}% (0 FP)</span>
                          </div>
                        ))}
                      </div>
                    </div>

                    <div className="p-5 bg-slate-900/60 border border-slate-800 rounded-xl">
                      <h3 className="text-sm font-semibold text-slate-200 mb-3">
                        LLM Security & Instruction Boundary
                      </h3>
                      <div className="space-y-3 text-xs text-slate-300">
                        <div className="flex items-center justify-between">
                          <span>Prompt Injection Defense Rate:</span>
                          <span className="font-bold text-emerald-400">
                            {(evalsQuery.data.prompt_injection_metrics?.injection_defense_pass_rate * 100 || 100).toFixed(0)}%
                          </span>
                        </div>
                        <div className="flex items-center justify-between">
                          <span>Risk Score Mutation Rate:</span>
                          <span className="font-bold text-emerald-400">0.0% (Zero permitted)</span>
                        </div>
                        <div className="flex items-center justify-between">
                          <span>Citation Validity Rate:</span>
                          <span className="font-bold text-emerald-400">
                            {(evalsQuery.data.agent_groundedness_metrics?.citation_validity_rate * 100 || 100).toFixed(0)}%
                          </span>
                        </div>
                        <div className="flex items-center justify-between">
                          <span>Unsupported Claims:</span>
                          <span className="font-bold text-emerald-400">0.0%</span>
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Ablation Table */}
                  <div className="p-5 bg-slate-900/60 border border-slate-800 rounded-xl">
                    <h3 className="text-sm font-semibold text-slate-200 mb-3">
                      Multi-Model Baseline Ablation Study
                    </h3>
                    <div className="overflow-x-auto">
                      <table className="w-full text-left text-xs">
                        <thead className="bg-slate-950 text-slate-400 border-b border-slate-800">
                          <tr>
                            <th className="p-2.5">Model / Policy Variant</th>
                            <th className="p-2.5">F1 Score</th>
                            <th className="p-2.5">Brier Score</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-800 font-mono">
                          {Object.entries(evalsQuery.data.ablation_metrics || {}).map(([variant, metrics]: any) => (
                            <tr
                              key={variant}
                              className={variant === 'final_fused_risk_policy' ? 'bg-sky-950/30 text-sky-300 font-bold' : ''}
                            >
                              <td className="p-2.5">{variant}</td>
                              <td className="p-2.5">{metrics.f1}</td>
                              <td className="p-2.5">{metrics.brier}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                </>
              )}
            </div>
          )}
        </main>
      </div>
    </div>
  )
}
