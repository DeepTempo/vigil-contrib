// An agent's latest runs, newest first, in its drawer: how each ended, what it was part
// of, how long it took, what it cost and the alert it worked. A row opens the run.
import { useEffect, useState } from 'react'
import { findingsApi, workflowApi } from '../../services/api'
import { fmtCost } from '../../shared/cost'
import { utcDayClock } from '../../shared/utc'
import { fmtDuration, runStatusColor, shownStatus, type WfRun } from './runRead'

const SHOWN = 5
const WORD: Record<string, string> = {
  completed: 'Done', failed: 'Failed', cancelled: 'Stopped', rejected: 'Rejected', running: 'Running', paused: 'Waiting for approval', pending: 'Starting',
}

export default function AgentRuns({ agentId, onWatch }: { agentId: string; onWatch: (runId: string) => void }) {
  const [runs, setRuns] = useState<WfRun[] | null>(null)
  const [failed, setFailed] = useState(false)
  const [titles, setTitles] = useState<Record<string, string>>({})

  useEffect(() => {
    let cancelled = false
    Promise.resolve()
      .then(() => workflowApi.listAgentRuns(agentId, SHOWN))
      .then((r) => {
        if (cancelled) return
        const rows = ((r?.data as { runs?: WfRun[] })?.runs ?? []).slice(0, SHOWN)
        setRuns(rows)
        // the alert each one worked, by its title rather than its id
        for (const id of new Set(rows.map(alertOf).filter((x): x is string => !!x))) {
          Promise.resolve().then(() => findingsApi.getById(id)).then((f) => {
            const title = (f?.data as { title?: string })?.title
            if (!cancelled && title) setTitles((held) => ({ ...held, [id]: title }))
          }).catch(() => {})
        }
      })
      .catch(() => { if (!cancelled) setFailed(true) })
    return () => { cancelled = true }
  }, [agentId])

  return (
    <div className="flex flex-col gap-2">
      <span className="vg-side-title">Recent runs</span>
      {failed && <span className="vg-side-hint">Couldn’t load its runs.</span>}
      {!failed && runs === null && <span className="vg-side-hint">Loading…</span>}
      {runs?.length === 0 && <span className="vg-side-hint">Not run yet. Run it on an alert or use it in a workflow, and its runs show here.</span>}
      {runs && runs.length > 0 && (
        <ul className="ag-runs" aria-label="Recent runs">
          {runs.map((run) => {
            const status = shownStatus(run)
            const alert = alertOf(run)
            return (
              <li key={run.run_id}>
                <button type="button" onClick={() => onWatch(run.run_id)} title="Open in Watch it run">
                  <span className="ag-run-status" style={{ color: runStatusColor(status) }}>{WORD[status] ?? status}</span>
                  <span className="ag-run-alert">{alert ? titles[alert] ?? alert : 'No alert'}</span>
                  <span className="ag-run-meta">
                    {run.workflow_name ? `${run.workflow_name} · ` : ''}{utcDayClock(run.started_at) ?? '—'} · {fmtDuration(run.duration_ms)} · {fmtCost(run.total_cost_usd, undefined, 3)}
                  </span>
                </button>
              </li>
            )
          })}
        </ul>
      )}
    </div>
  )
}

function alertOf(run: WfRun): string | null {
  const id = run.trigger_context?.finding_id
  return typeof id === 'string' && id ? id : null
}
