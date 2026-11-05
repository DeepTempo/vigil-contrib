import api from './api'

/** Wire shapes of core/incidents/story.py and core/incidents/alert_kinds.py. */

export type Coverage = 'rule_fired' | 'rule_declared' | 'no_rule' | 'unknown'
export type EvidenceKind = 'finding' | 'log_search' | 'approval'
export type VerdictValue = 'true_positive' | 'false_positive' | 'undetermined'
export type ActionEffect = 'cloudflare' | 'no_executor' | 'run_resumes' | 'record_only'

export interface Technique {
  id: string
  name: string
  tactic: string | null
  confidence: number | null
}

export interface Step {
  finding_id: string
  at: string
  label: string
  source: string
  severity: string | null
  technique: Technique | null
  other_techniques: Technique[]
  labels: string[]
  anomaly_score: number | null
  coverage: Coverage
  caught_by: string | null
  coverage_note: string
}

export interface Evidence {
  kind: EvidenceKind
  ref: string
  label: string
}

export interface Reason {
  kind: string
  text: string
  evidence: Evidence[]
}

export interface IncidentAction {
  action_id: string
  title: string
  description: string
  target: string
  action_type: string
  status: string
  reason: string
  confidence: number
  reversibility: string
  created_at: string
  created_by: string
  approved_by: string | null
  approved_at: string | null
  executed_at: string | null
  rejection_reason: string | null
  workflow_run_id: string | null
  effect: ActionEffect
  does: string
  missing: string | null
  result: string | null
  evidence: Evidence[]
}

export interface StoryEntity {
  kind: string
  value: string
  /** The first of a long list. named_by counts them all. */
  finding_ids: string[]
  named_by: number
}

export interface IntelItem {
  kind: string
  value: string
  threat_level: string | null
  source: string | null
  confidence: number | null
  reputation: number | null
  context: string | null
}

export interface Verdict {
  value: VerdictValue
  label: string
  by: string | null
  basis: string
  model_words: string | null
}

export interface IncidentReport {
  text: string
  origin: string
  ref: string
  at: string | null
}

export interface SourceCount {
  source: string
  alerts: number
}

export interface Story {
  case_id: string
  title: string
  summary: string
  status: string
  priority: string
  opened_at: string
  alerts: number
  sources: SourceCount[]
  verdict: Verdict
  report: IncidentReport | null
  /** The first page of steps. steps_total counts them all. */
  steps: Step[]
  steps_total: number
  reasons: Reason[]
  actions: IncidentAction[]
  entities: StoryEntity[]
  entities_total: number
  intel: IntelItem[]
  unmatched_steps: Step[]
  unmatched_total: number
  log_events: number
  rules_loaded: number
  viewer: { can_read_approvals: boolean; can_decide: boolean }
}

export interface IncidentRow {
  case_id: string
  title: string
  status: string
  priority: string
  opened_at: string
  alerts: number
  sources: SourceCount[]
  verdict: Verdict
  /** Null on a case too large to walk for a list. */
  unmatched_steps: number | null
  log_events: number
  pending_approvals: number | null
}

export interface StepPage {
  steps: Step[]
  total: number
  offset: number
}

export interface IncidentList {
  total: number
  items: IncidentRow[]
}

export interface OutcomeCount {
  state: string
  label: string
  alerts: number
}

export interface AlertKind {
  key: string
  title: string
  source: string
  alerts: number
  severities: { severity: string; alerts: number }[]
  outcomes: OutcomeCount[]
  median_seconds_to_outcome: number | null
  timed_outcomes: number
  latest_at: string | null
  finding_ids: string[]
  case_ids: string[]
}

export interface AlertTriage {
  hours: number
  alerts: number
  outcomes: OutcomeCount[]
  kinds: AlertKind[]
  truncated: boolean
}

export const incidentsApi = {
  list: (params?: { status?: 'open' | 'all'; limit?: number; offset?: number }) => api.get<IncidentList>('/incidents', { params }),
  get: (caseId: string) => api.get<Story>(`/incidents/${encodeURIComponent(caseId)}`),
  steps: (caseId: string, params: { offset: number; limit: number }) =>
    api.get<StepPage>(`/incidents/${encodeURIComponent(caseId)}/steps`, { params }),
  alertTriage: (hours: number) => api.get<AlertTriage>('/alert-triage', { params: { hours } }),
}
