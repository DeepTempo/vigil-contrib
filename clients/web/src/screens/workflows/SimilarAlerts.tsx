// Alerts that look like the picked finding, so a run can take them on together.
// Each says why it matched: the same host, user or indicator, or the same behaviour.
import { useEffect, useState } from 'react'
import { findingsApi, type SimilarFinding } from '../../services/api'

export function relatedContext(picked: SimilarFinding[]): string {
  if (picked.length === 0) return ''
  const lines = picked.map((f) => `- ${f.finding_id}: ${f.title}${f.reasons.length ? ` (${f.reasons.join('; ')})` : ''}`)
  return `Related alerts to investigate with this one:\n${lines.join('\n')}`
}

export default function SimilarAlerts({ findingId, known, picked, onChange }: {
  findingId: string
  /** ids the console already knows exist, so typing half an id does not query */
  known: Set<string>
  picked: SimilarFinding[]
  onChange: (picked: SimilarFinding[]) => void
}) {
  const [state, setState] = useState<{ id: string; method: string; compared: number; rows: SimilarFinding[] } | 'loading' | 'error' | null>(null)
  const id = findingId.trim()

  useEffect(() => {
    // a listed id, or a whole pasted one
    if (!known.has(id) && !/^[a-z]+-\d{8}-[0-9a-f]{8}$/i.test(id)) {
      setState(null)
      return
    }
    let cancelled = false
    setState('loading')
    const t = setTimeout(() => {
      Promise.resolve().then(() => findingsApi.similar(id)).then((r) => {
        if (!cancelled) setState({ id, method: r.data.method, compared: r.data.compared, rows: r.data.similar })
      }).catch(() => { if (!cancelled) setState('error') })
    }, 250)
    return () => { cancelled = true; clearTimeout(t) }
  }, [id, known])

  if (state === null) return null
  const isPicked = (f: SimilarFinding) => picked.some((p) => p.finding_id === f.finding_id)
  const toggle = (f: SimilarFinding) => onChange(isPicked(f) ? picked.filter((p) => p.finding_id !== f.finding_id) : [...picked, f])

  return (
    <div className="rounded-[9px] border border-line-soft bg-bg px-3 py-2.5 flex flex-col gap-2">
      <div className="flex items-baseline justify-between gap-2">
        <span className="text-[12px] font-semibold text-tx">Similar alerts</span>
        {typeof state === 'object' && (
          <span className="text-[11.5px] text-tx-3">
            {state.rows.length} of {state.compared} recent · {state.method}
          </span>
        )}
      </div>
      {state === 'loading' && <span className="text-[12px] text-tx-3">Comparing with recent alerts…</span>}
      {state === 'error' && <span className="text-[12px] text-tx-3">Could not compare this finding right now.</span>}
      {typeof state === 'object' && state.rows.length === 0 && (
        <span className="text-[12px] text-tx-3">Nothing recent looks like this one.</span>
      )}
      {typeof state === 'object' && state.rows.length > 0 && (
        <>
          <ul className="flex flex-col gap-1 m-0 p-0 list-none max-h-[220px] overflow-y-auto">
            {state.rows.map((f) => (
              <li key={f.finding_id}>
                <label className="flex items-start gap-2 text-[12.5px] cursor-pointer">
                  <input type="checkbox" className="mt-[3px]" checked={isPicked(f)} onChange={() => toggle(f)} />
                  <span className="flex flex-col min-w-0">
                    <span className="flex items-center gap-1.5 text-tx min-w-0">
                      <span className="truncate">{f.title || f.finding_id}</span>
                      <span className="text-tx-3 font-mono text-[11px] shrink-0">{Math.round(f.score * 100)}%</span>
                    </span>
                    <span className="text-[11.5px] text-tx-3 truncate">{[f.severity, ...f.reasons].filter(Boolean).join(' · ')}</span>
                  </span>
                </label>
              </li>
            ))}
          </ul>
          <div className="flex items-center gap-3 text-[12px]">
            <button type="button" className="btn ghost" onClick={() => onChange(state.rows)}>Add all {state.rows.length}</button>
            {picked.length > 0 && <button type="button" className="btn ghost" onClick={() => onChange([])}>Clear</button>}
            <span className="text-tx-3">{picked.length ? `${picked.length} added to the run's context` : 'Picked alerts go to the run with this finding.'}</span>
          </div>
        </>
      )}
    </div>
  )
}
