import api from './api'

/** Wire shape of GET /api/entity-graph, from core/entity_graph/build.py and store.py. */

export interface LoglmStats {
  scored: number
  anomalous: number
  max_score: number | null
}

export type RoleBand = 'likely' | 'possible' | 'unknown'

export interface RoleCandidate {
  role: string
  label: string
  score: number
  evidence: string[]
}

export interface GraphNode {
  id: string
  label: string
  hostname: string | null
  internal: boolean
  subnet: string
  block: string
  role: {
    primary: string
    label: string
    group: string
    confidence: number
    band: RoleBand
    candidates: RoleCandidate[]
    limits: string[]
  }
  stats: {
    flows_in: number
    flows_out: number
    bytes_in: number | null
    bytes_out: number | null
    served_ports: { port: number; proto: string; clients: number }[]
  }
  loglm: LoglmStats
  findings: string[]
  on_path: boolean
  logs_query: string
}

export interface GraphEdge {
  id: string
  source: string
  target: string
  flows: number
  bytes: number | null
  answered: boolean | null
  services: { port: number; proto: string; flows: number }[]
  first_ts: number | null
  last_ts: number | null
  cross_block: boolean
  cross_subnet: boolean
  loglm: LoglmStats
  findings: string[]
  on_path: boolean
}

export interface GraphBlock {
  id: string
  subnet: string
  zone: string
  group: string
  label: string
  hosts: string[]
  roles: Record<string, number>
  anomalous_hosts: number
  findings: string[]
}

export interface ZeroTrustFinding {
  id: string
  check: string
  title: string
  severity: string
  detail: string
  why: string
  false_positive_note: string
  /** False when the check needs a service to have answered and no byte count shows it did. */
  confirmed: boolean
  hosts: string[]
  flows: { source: string; target: string; flows: number; ports: number[]; first_ts: number | null; last_ts: number | null }[]
  flows_total: number
  logs_query: string
}

export interface CasePath {
  case_id: string
  title: string
  entities: string[]
  not_seen: string[]
  hops: { source: string; target: string; flows: number; first_ts: number | null; last_ts: number | null }[]
}

export interface EntityGraph {
  nodes: GraphNode[]
  edges: GraphEdge[]
  blocks: GraphBlock[]
  findings: ZeroTrustFinding[]
  coverage: { flows: number; with_port: number; with_source_port: number; with_bytes: number; scored: number }
  checks_not_run: { check: string; title: string; needs: string }[]
  truncated: { nodes: number; edges: number }
  /** Whether any flow in the window carries a LogLM score. */
  loglm: boolean
  path: CasePath | null
  window: { hours: number; start: string; end: string }
  rows: { in_window: number; read: number; flows: number; skipped: number; cap: number; capped: number }
  internal_ranges: string[]
}

/** A build over the row cap takes seconds, past the client's default timeout on a busy install. */
const GRAPH_TIMEOUT = 60_000

export async function fetchEntityGraph(hours: number, caseId: string | null, signal?: AbortSignal): Promise<EntityGraph> {
  const { data } = await api.get<EntityGraph>('/entity-graph', {
    params: { hours, case_id: caseId ?? undefined },
    signal,
    timeout: GRAPH_TIMEOUT,
  })
  return data
}
