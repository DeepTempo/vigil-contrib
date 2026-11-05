import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { incidentsApi, type IncidentList } from '../../services/incidentsApi'
import { Tag } from '../shared/x1'

const plural = (n: number, word: string) => `${n} ${word}${n === 1 ? '' : 's'}`

/** Shown over the triage queue while a real incident is open. A role that cannot read one gets a 404 and no banner. */
export default function IncidentBanner() {
  const [list, setList] = useState<IncidentList | null>(null)
  useEffect(() => {
    let gone = false
    incidentsApi.list({ status: 'open', limit: 1 }).then(
      (res) => { if (!gone) setList(res.data) },
      () => { if (!gone) setList(null) },
    )
    return () => { gone = true }
  }, [])
  const top = list?.items[0]
  if (!list || !top) return null
  const facts = [
    `${plural(top.alerts, 'alert')} from ${plural(top.sources.length, 'source')} on one case`,
    top.verdict.label,
    top.unmatched_steps != null && top.unmatched_steps > 0 ? `${plural(top.unmatched_steps, 'step')} no rule covers` : null,
    top.pending_approvals ? `${plural(top.pending_approvals, 'action')} waiting for a person` : null,
  ].filter(Boolean)
  const here = encodeURIComponent(top.case_id)
  return (
    <div className="x1-strip" role="region" aria-label="Open incident" style={{ margin: '0 0 12px' }}>
      <div style={{ display: 'grid', gap: 3, minWidth: 0 }}>
        <div className="x1-row">
          <Tag tone="poor">{top.priority}</Tag>
          <b>{top.case_id} · {top.title}</b>
        </div>
        <span className="x1-muted" style={{ fontSize: 12.5 }}>{facts.join(' · ')}</span>
      </div>
      <div className="x1-row">
        {list.total > 1 && <Link className="btn ghost" to="/incident">All {list.total} open incidents</Link>}
        {top.log_events > 0 && <Link className="btn ghost" to={`/logs?case=${here}`}>See the {top.log_events} events</Link>}
        <Link className="btn primary" to={`/incident?case=${here}`}>Open incident</Link>
      </div>
    </div>
  )
}
