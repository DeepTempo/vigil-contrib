import type { ReactNode } from 'react'
import VendorLogo, { vendorMark } from './VendorLogo'
import './x1.css'

export type TagTone = 'ac' | 'vio' | 'fair' | 'good' | 'poor'

export function Tag({ tone, title, children }: { tone?: TagTone; title?: string; children: ReactNode }) {
  return <span className={`x1-tag${tone ? ` ${tone}` : ''}`} title={title}>{children}</span>
}

/** `source` is the stored key, `label` the name to show. */
export function SourceChip({ source, label = source }: { source: string; label?: string }) {
  const name = `${label} ${source}`
  return (
    <span className={`x1-src x1-src-${source}`} title={label}>
      {vendorMark(name) ? <VendorLogo name={name} size={12} /> : <i aria-hidden="true" />}
      {label}
    </span>
  )
}

export function SevDot({ level }: { level: string }) {
  return <span className={`x1-sev ${level}`} title={level} aria-label={level} />
}

export function LoglmMeter({ value }: { value: number | null }) {
  if (value === null) return <span className="x1-muted" title="LogLM did not score this event">Not scored</span>
  return (
    <span className="x1-meter" title={`LogLM anomaly confidence ${value.toFixed(2)}`}>
      <span className="track"><span className={`fill${value >= 0.7 ? ' hot' : ''}`} style={{ width: `${Math.round(value * 100)}%` }} /></span>
      <span className="x1-mono">{value.toFixed(2)}</span>
    </span>
  )
}

export function Stat({ value, label }: { value: ReactNode; label: string }) {
  return (
    <div className="x1-card x1-stat">
      <b>{value}</b>
      <span>{label}</span>
    </div>
  )
}
