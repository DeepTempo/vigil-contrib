import type { ReactNode } from 'react'
import { errorText } from '../../shared/errorText'
import type { Coverage, ProposalState, RuleHealth, TargetStatus, TechniqueState } from '../../services/detectionsApi'
import type { TagTone } from '../shared/x1'

/** A refused step answers `{detail: {message}}`; everything else `errorText` reads. */
export function refusal(error: unknown, fallback: string): string {
  const detail = (error as { response?: { data?: { detail?: { message?: unknown } } } })?.response?.data?.detail
  if (typeof detail?.message === 'string') return detail.message
  return errorText(error, fallback)
}

/** The number is rounded down, so a real validation never reads as none. */
export function percentLabel({ percent_validated: percent, counted_validated: validated }: Coverage['summary']): string {
  return percent === 0 && validated > 0 ? 'under 1%' : `${percent}%`
}

export function percentLine(coverage: Coverage): string {
  const { basis, counted, counted_validated: validated } = coverage.summary
  if (counted === 0) return 'No technique has a rule, an alert or a priority yet'
  return basis === 'priority'
    ? `${validated} of ${counted} priority techniques validated by replay`
    : `${validated} of ${counted} techniques in the map validated by replay. Name priorities in the threat model to narrow this.`
}

export const TECHNIQUE_STATES: Record<TechniqueState, string> = {
  validated: 'Validated by replay',
  unproven: 'Rule exists, unproven',
  no_rule: 'No rule',
}

export const HEALTH: Record<RuleHealth, { label: string; tone: TagTone | undefined }> = {
  fails_to_run: { label: 'Fails to run', tone: 'poor' },
  data_silent: { label: 'Data silent', tone: 'poor' },
  missing_field: { label: 'Missing field', tone: 'poor' },
  disabled: { label: 'Disabled', tone: 'fair' },
  never_fired: { label: 'Never fired', tone: 'fair' },
  fires: { label: 'Fires', tone: 'good' },
}

export const TARGET_STATUS: Record<TargetStatus, { label: string; tone: TagTone }> = {
  converted: { label: 'Converted', tone: 'good' },
  pasted: { label: 'Pasted by a person', tone: 'ac' },
  needs_field_mapping: { label: 'Needs a field mapping', tone: 'fair' },
  not_installed: { label: 'Not installed', tone: 'fair' },
  failed: { label: 'Failed', tone: 'poor' },
}

export const STATE_TONE: Record<ProposalState, TagTone | undefined> = {
  draft: undefined,
  linted: 'ac',
  replayed: 'ac',
  converted: 'ac',
  shadow: 'fair',
  live: 'good',
  rejected: 'poor',
}

export function when(iso: string | null | undefined): string {
  if (!iso) return ''
  const date = new Date(iso)
  return Number.isNaN(date.getTime()) ? iso : date.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
}

export function Failure({ children }: { children: ReactNode }) {
  return <div className="x1-card x1-error" role="alert">{children}</div>
}

export function Note({ children }: { children: ReactNode }) {
  return <div className="x1-card x1-note">{children}</div>
}

export function Empty({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="x1-card" style={{ display: 'grid', gap: 6 }}>
      <b style={{ color: 'var(--tx0)', fontSize: 13.5 }}>{title}</b>
      <span className="x1-muted" style={{ fontSize: 12.5 }}>{children}</span>
    </div>
  )
}
