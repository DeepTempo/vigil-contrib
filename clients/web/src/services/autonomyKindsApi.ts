import api from './api'

/** Autonomy earned per kind of alert: services/api/routers/kind_autonomy.py. */

export type KindMode = 'ask' | 'close' | 'suspended' | 'expired'

export interface KindTrackRecord {
  alerts_seen: number
  /** People's labels in the window, closed here and imported together. */
  reviewed: number
  /** The labels that said benign. */
  agreed: number
  real: number
  closed_here_benign: number
  closed_here_real: number
  imported_benign: number
  imported_real: number
  overturned: number
  closed_by_vigil: number
  above_scope: number
  bulk_ignored: number
  last_real_at: string | null
  /** Upper bound on how often this kind is really an attack, at 95% confidence. Null with any real label or none clean. */
  miss_bound: number | null
}

export interface KindAdoption {
  policy_id: number
  by: string
  by_label: string | null
  at: string
  expires_at: string
  reason: string
  clean_labels: number
}

export interface AlertKind {
  key: string
  signature: string
  source: string
  title: string
  mode: KindMode
  mode_reason: string | null
  track_record: KindTrackRecord
  eligible: boolean
  why_not: { rule: string; why: string }[]
  adoption: KindAdoption | null
}

export interface KindsView {
  close_enabled: boolean
  bar: number
  window_days: number
  lifetime_days: number
  auto_severities: string[]
  summary: { kinds: number; closing: number; closed_by_vigil: number; overturned: number }
  daily: { day: string; asked: number; closed: number }[]
  kinds: AlertKind[]
}

export interface KindEvent {
  id: number
  event: string | null
  from_mode: string
  to_mode: string
  actor: string
  actor_label: string | null
  reason: string
  evidence: Record<string, unknown>
  clean_labels: number
  at: string
}

export interface ClosedAlert {
  finding_id: string
  title: string | null
  severity: string | null
  observed_at: string | null
  closed_at: string | null
  policy_reason: string
}

const path = (key: string) => `/kind-autonomy/${encodeURIComponent(key)}`

export const autonomyKindsApi = {
  list: () => api.get<KindsView>('/kind-autonomy'),
  setClosing: (close_enabled: boolean) =>
    api.put<{ close_enabled: boolean }>('/kind-autonomy/settings', { close_enabled }),
  adopt: (key: string, reason?: string) => api.post(`${path(key)}/adopt`, { reason }),
  revoke: (key: string, reason?: string) => api.post(`${path(key)}/revoke`, { reason }),
  events: (key: string) => api.get<{ events: KindEvent[] }>(`${path(key)}/events`),
  closed: (key: string, sample = false) =>
    api.get<{ total: number; alerts: ClosedAlert[] }>(`${path(key)}/closed`, {
      params: { limit: sample ? 10 : 25, sample },
    }),
  overturn: (key: string, findingId: string, reason?: string) =>
    api.post(`${path(key)}/closed/${encodeURIComponent(findingId)}/overturn`, { reason }),
}
