import api, { LLM_TIMEOUT } from './api'

/** Detection engineering. The server moves every state and names who did it; nothing here reaches a SIEM. */

export type ProposalState = 'draft' | 'linted' | 'replayed' | 'converted' | 'shadow' | 'live' | 'rejected'
export type TargetStatus = 'converted' | 'pasted' | 'needs_field_mapping' | 'not_installed' | 'failed'
export type TechniqueState = 'validated' | 'unproven' | 'no_rule'
export type RuleHealth = 'fails_to_run' | 'data_silent' | 'missing_field' | 'disabled' | 'never_fired' | 'fires'
export type RedTeamVerdict = 'rule' | 'loglm' | 'both' | 'missed'

export interface LintCheck {
  name: string
  /** null: the check could not run here */
  passed: boolean | null
  blocking: boolean
  detail: string
}

export interface EventSample {
  event_id: string
  time: string
  source: string
  src_host: string | null
  user_name: string | null
  summary: string
}

export interface TargetRow {
  target: string
  platform: string
  status: TargetStatus
  measured_valid_pct: number | null
  pipeline: string[]
  tried: string[]
  output: string
  file: string | null
  query: string | null
  error: string
  pasted_by?: string
}

/** Each step writes its own evidence; `step` says which. */
export interface StepEvidence {
  step: string
  tool?: string
  source?: string
  asked_by?: string
  filled_in?: string[]
  passed?: boolean
  checks?: LintCheck[]
  evaluated?: boolean
  reason?: string
  engine?: string
  attack_basis?: string
  attack_rows?: number
  hits?: number
  hit_samples?: EventSample[]
  benign_rows?: number
  benign_rows_holding_fields?: number
  benign_truncated?: boolean
  false_positives?: number
  false_positive_samples?: EventSample[]
  window_days?: number
  proven?: boolean
  unproven_because?: string | null
  exclusion?: { field: string; match: string; values: string[] }
  before?: { hits?: number; attack_rows?: number; false_positives?: number; benign_rows?: number } | null
  pysigma_installed?: boolean
  targets?: TargetRow[]
  accepted_unproven?: { by: string; reason: string }
  siem_written?: boolean
  channel?: string
  saved?: { rule_id: number; source: string; version: number; stage: string | null; file_path: string }[]
  shadow?: ShadowReport
}

export interface ProposalEvent {
  id: number
  from_state: ProposalState | null
  to_state: ProposalState
  actor: string
  reason: string
  at: string
  evidence: StepEvidence
  sigma: string
  judges_current_text: boolean
}

export interface StageRow {
  rule_id: number
  version: number
  stage: string
  actor: string
  reason: string
  at: string
}

export type StepName = 'draft' | 'lint' | 'replay' | 'tune' | 'convert' | 'shadow' | 'live' | 'reject'

export interface Proposal {
  proposal_id: string
  title: string
  technique: string | null
  case_id: string | null
  origin: { source?: string; finding_id?: string | null; rule_id?: number }
  sigma: string
  state: ProposalState
  rule_id: number | null
  created_by: string
  created_at: string
  updated_at: string
  allowed: ProposalState[]
  latest: Record<StepName, ProposalEvent | null>
  events: ProposalEvent[]
  stages: StageRow[]
}

export interface ProposalRow {
  proposal_id: string
  title: string
  technique: string | null
  case_id: string | null
  state: ProposalState
  created_by: string
  created_at: string
  updated_at: string
  replay: { evaluated?: boolean; hits?: number; attack_rows?: number; false_positives?: number; benign_rows?: number; proven?: boolean } | null
}

export interface ShadowReport {
  evaluated: boolean
  reason?: string
  since?: string
  rows?: number
  matches?: number
  matches_in_case?: number
  matches_unclaimed?: number
  samples?: EventSample[]
}

export interface TechniqueCell {
  technique: string
  name: string
  tactic: string
  state: TechniqueState
  rules: number
  rules_failing_checks: number
  seen: number
  priority: boolean
  proof: { proposal_id: string; hits: number; attack_rows: number; benign_rows: number; at: string } | null
  proposal: { proposal_id: string; state: ProposalState } | null
}

export interface Coverage {
  techniques: TechniqueCell[]
  tactics: string[]
  rule_total: number
  summary: {
    validated: number
    unproven: number
    no_rule: number
    basis: 'priority' | 'all'
    counted: number
    counted_validated: number
    percent_validated: number | null
  }
}

export interface RuleRow {
  rule_id: number
  name: string
  language: string
  source: string
  tool: string
  status: string
  techniques: string[]
  health: RuleHealth
  why: string
  fires: number
  missing_fields: string[] | null
  validated: boolean
}

export interface RulesReport {
  /** Rows, one per stored copy. */
  total: number
  /** Rules, each counted once however many SIEM copies it has. */
  rule_total: number
  mapped: number
  validated: number
  counts: Record<RuleHealth, number>
  rules: RuleRow[]
  fires_window_days: number
  fields_known: boolean
  limits: string
}

export interface LogSourcesReport {
  configured: { source_id: string; enabled: boolean; last_success_at: string | null; last_error: string | null }[]
  stored: { source: string; event_class: string; rows: number; first: string; last: string }[]
  total_rows: number
  kinds: { kind: string; rows: number; configured: boolean }[]
  kinds_basis: string
}

export interface ThreatModel {
  sector: string
  crown_jewels: string
  exposure: string
  advisories: string
  notes: string
  priority_techniques: string[]
  updated_by?: string | null
  updated_at?: string | null
}

export interface RedTeamStep {
  index: number
  id: string | null
  name: string | null
  technique_id: string | null
  hostname: string | null
  user: string | null
  started_at: string | null
  verdict: RedTeamVerdict
  could_not_correlate: boolean
  citations: { finding_id: string; data_source?: string; rule_name?: string; description?: string }[]
}

export interface RedTeamRun {
  name: string
  uploaded_by: string
  uploaded_at: string
  window_minutes: number
  steps: RedTeamStep[]
  counts: Record<RedTeamVerdict, number>
}

export interface TargetsReport {
  targets: { target: string; platform: string; installed: boolean; measured_valid_pct: number }[]
  pysigma_installed: boolean
  not_installed: string | null
  measured: string
}

const BASE = '/detection-engineering'
const step = (id: string, name: string, body: object = {}) =>
  api.post<Proposal>(`${BASE}/proposals/${encodeURIComponent(id)}/${name}`, body).then((r) => r.data)

export const detectionsApi = {
  listProposals: () => api.get<{ proposals: ProposalRow[] }>(`${BASE}/proposals`).then((r) => r.data.proposals),
  getProposal: (id: string) => api.get<Proposal>(`${BASE}/proposals/${encodeURIComponent(id)}`).then((r) => r.data),
  paste: (body: { sigma: string; technique?: string; case_id?: string; finding_id?: string }) =>
    api.post<Proposal>(`${BASE}/proposals`, body).then((r) => r.data),
  draft: (body: { case_id?: string; finding_id?: string; technique?: string; notes?: string }) =>
    api.post<Proposal>(`${BASE}/proposals/draft`, body, { timeout: LLM_TIMEOUT }).then((r) => r.data),
  fromRule: (ruleId: number) => api.post<Proposal>(`${BASE}/proposals/from-rule`, { rule_id: ruleId }).then((r) => r.data),
  edit: (id: string, sigma: string, reason: string) => step(id, 'edit', { sigma, reason }),
  lint: (id: string) => step(id, 'lint'),
  replay: (id: string, windowDays: number) => step(id, 'replay', { window_days: windowDays }),
  tune: (id: string, body: { field: string; match: string; values: string[]; reason: string }) => step(id, 'tune', body),
  convert: (id: string, body: { pasted?: Record<string, string>; accept_reason?: string }) => step(id, 'convert', body),
  shadow: (id: string, reason: string) => step(id, 'shadow', { reason }),
  live: (id: string, reason: string) => step(id, 'live', { reason }),
  reject: (id: string, reason: string) => step(id, 'reject', { reason }),
  shadowReport: (id: string) => api.get<ShadowReport>(`${BASE}/proposals/${encodeURIComponent(id)}/shadow-report`).then((r) => r.data),
  targets: () => api.get<TargetsReport>(`${BASE}/targets`).then((r) => r.data),
  coverage: () => api.get<Coverage>(`${BASE}/coverage`).then((r) => r.data),
  rules: () => api.get<RulesReport>(`${BASE}/rules`).then((r) => r.data),
  logSources: () => api.get<LogSourcesReport>(`${BASE}/log-sources`).then((r) => r.data),
  threatModel: () => api.get<ThreatModel>(`${BASE}/threat-model`).then((r) => r.data),
  saveThreatModel: (body: ThreatModel) => api.put<ThreatModel>(`${BASE}/threat-model`, body).then((r) => r.data),
  redTeamRuns: () => api.get<{ runs: RedTeamRun[] }>(`${BASE}/red-team`).then((r) => r.data.runs),
  uploadRun: (body: { name: string; events: unknown[]; window_minutes: number }) =>
    api.post<RedTeamRun>(`${BASE}/red-team`, body).then((r) => r.data),
}
