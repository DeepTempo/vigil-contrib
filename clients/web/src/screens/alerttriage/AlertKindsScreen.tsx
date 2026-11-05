import { useEffect, useState, type KeyboardEvent } from 'react'
import { Link } from 'react-router-dom'
import { incidentsApi, type AlertKind, type AlertTriage, type OutcomeCount } from '../../services/incidentsApi'
import { errorText } from '../../shared/errorText'
import { EmptyState } from '../../shared/ui'
import { usePageSnapshot } from '../../shell/pageSnapshot'
import type { ConsoleScreenProps } from '../../shared/types'
import FindingPopup from '../dashboard/FindingPopup'
import VendorLogo from '../shared/VendorLogo'
import { SevDot, Stat, Tag, type TagTone } from '../shared/x1'

const WINDOWS: [number, string][] = [[24, 'Last 24 hours'], [24 * 7, 'Last 7 days'], [24 * 30, 'Last 30 days']]

/** What each of alert_outcomes' states means, in the tone a row shows it. */
const STATES: Record<string, { tone?: TagTone; means: string }> = {
  dismissed: { tone: 'good', means: 'Someone or something marked it as noise.' },
  resolved_person: { tone: 'good', means: 'It is on a case a person closed.' },
  resolved_auto: { tone: 'good', means: 'It is on a case an agent closed.' },
  needs_you: { tone: 'poor', means: 'Its case has a decision waiting for a person.' },
  working: { tone: 'ac', means: 'It is on an open case with a run going, or no run yet.' },
  case_idle: { tone: 'fair', means: 'It is on an open case whose runs have ended.' },
  scoring: { tone: 'vio', means: 'It is queued for triage.' },
  excluded: { means: 'It names an excluded address, so the daemon skips it.' },
  waiting: { means: 'Nothing has picked it up.' },
}

const onActivate = (fn: () => void) => (e: KeyboardEvent) => {
  if (e.key === 'Enter' || e.key === ' ') {
    e.preventDefault()
    fn()
  }
}

const count = (outcomes: OutcomeCount[], ...states: string[]) =>
  outcomes.filter((o) => states.includes(o.state)).reduce((sum, o) => sum + o.alerts, 0)

const span = (seconds: number) => {
  if (seconds < 90) return `${Math.round(seconds)}s`
  if (seconds < 5400) return `${Math.round(seconds / 60)} min`
  if (seconds < 172800) return `${(seconds / 3600).toFixed(1)} h`
  return `${(seconds / 86400).toFixed(1)} days`
}

const OutcomeTag = ({ outcome }: { outcome: OutcomeCount }) => (
  <Tag tone={STATES[outcome.state]?.tone} title={STATES[outcome.state]?.means}>{outcome.label} {outcome.alerts}</Tag>
)

const autonomyLink = (key: string) => `/autonomy?kind=${encodeURIComponent(key)}`

function KindDetail({ kind, openFinding, openCase }: { kind: AlertKind; openFinding: (id: string) => void; openCase: (id: string) => void }) {
  return (
    <div className="x1-card" style={{ display: 'grid', gap: 10, alignContent: 'start', minWidth: 0 }}>
      <h3 style={{ margin: 0 }}>{kind.title}</h3>
      <div className="x1-row x1-muted" style={{ fontSize: 12.5 }}>
        <VendorLogo name={kind.source} size={14} /><span>{kind.source}</span><span>{kind.alerts} in this window</span>
        {kind.latest_at && <span>Latest {new Date(kind.latest_at).toISOString().slice(0, 16).replace('T', ' ')} UTC</span>}
      </div>
      <div>
        <div style={{ fontWeight: 600, color: 'var(--tx0)', marginBottom: 4 }}>What happened</div>
        <ul className="x1-reasons" style={{ fontSize: 12.5 }}>
          {kind.outcomes.map((o) => <li key={o.state}><OutcomeTag outcome={o} /> <span className="x1-muted">{STATES[o.state]?.means}</span></li>)}
        </ul>
      </div>
      <div className="x1-muted" style={{ fontSize: 12.5 }}>
        {kind.median_seconds_to_outcome !== null
          ? `Median ${span(kind.median_seconds_to_outcome)} from arrival to outcome, over the ${kind.timed_outcomes} of ${kind.alerts} alerts with a stored outcome time.`
          : 'No alert of this kind has a stored outcome time yet. Only a dismissal or a closed case records one.'}
      </div>
      <div>
        <div style={{ fontWeight: 600, color: 'var(--tx0)', marginBottom: 4 }}>Newest alerts</div>
        <div className="x1-row">
          {kind.finding_ids.map((id) => <button key={id} type="button" className="x1-chipbtn x1-mono" onClick={() => openFinding(id)}>{id}</button>)}
        </div>
      </div>
      {kind.case_ids.length > 0 && (
        <div>
          <div style={{ fontWeight: 600, color: 'var(--tx0)', marginBottom: 4 }}>Cases</div>
          <div className="x1-row">
            {kind.case_ids.map((id) => <button key={id} type="button" className="x1-chipbtn x1-mono" onClick={() => openCase(id)}>{id}</button>)}
          </div>
        </div>
      )}
      <div className="x1-row">
        <Link className="btn ghost" to={autonomyLink(kind.key)}>Autonomy mode for this kind</Link>
      </div>
    </div>
  )
}

export default function AlertKindsScreen({ go, goSettings, openCase }: ConsoleScreenProps) {
  const [hours, setHours] = useState(24)
  const [triage, setTriage] = useState<AlertTriage | null>(null)
  const [failed, setFailed] = useState<string | null>(null)
  const [selected, setSelected] = useState<string | null>(null)
  const [popup, setPopup] = useState<string | null>(null)

  useEffect(() => {
    let gone = false
    setFailed(null)
    incidentsApi.alertTriage(hours).then(
      (res) => { if (!gone) setTriage(res.data) },
      (err) => { if (!gone) setFailed(errorText(err, 'Could not read alert triage')) },
    )
    return () => { gone = true }
  }, [hours])

  usePageSnapshot('alerts', triage ? [
    `Alert triage, last ${triage.hours} hours: ${triage.alerts} alerts of ${triage.kinds.length} kinds.`,
    'Kinds (source | title | alerts | what happened | median to outcome):',
    ...triage.kinds.map((k) => [k.source, k.title, k.alerts, k.outcomes.map((o) => `${o.label} ${o.alerts}`).join(', '), k.median_seconds_to_outcome === null ? 'none stored' : span(k.median_seconds_to_outcome)].join(' | ')),
  ].join('\n') : '')

  const windows = (
    <div className="x1-row">
      {WINDOWS.map(([value, label]) => (
        <button key={value} type="button" className="x1-chipbtn" aria-pressed={hours === value} onClick={() => { setSelected(null); setHours(value) }}>{label}</button>
      ))}
    </div>
  )

  if (failed) return <EmptyState error icon="alert" title="Couldn’t read alert triage" body={failed} />
  if (!triage) return <EmptyState loading icon="clock" title="Loading alert triage…" />

  const kind = triage.kinds.find((k) => k.key === selected) ?? triage.kinds[0]

  return (
    <div className="x1">
      {windows}
      {triage.kinds.length === 0 ? (
        <EmptyState
          icon="alert"
          title={`No alerts arrived in the last ${triage.hours} hours`}
          body="This page groups real alerts by kind once they arrive. Connect a source of alerts, or upload your history in Day one setup."
          primary={{ label: 'Connect a source', onClick: () => goSettings('integrations') }}
          secondary={{ label: 'Day one setup', onClick: () => go('start') }}
        />
      ) : (
        <>
          <div className="x1-stats5">
            <Stat value={triage.alerts.toLocaleString()} label={`Alerts in the last ${triage.hours} hours`} />
            <Stat value={triage.kinds.length.toLocaleString()} label="Kinds of alert, by source and masked title" />
            <Stat value={count(triage.outcomes, 'dismissed', 'resolved_auto', 'resolved_person').toLocaleString()} label="Dropped as noise or closed on a case" />
            <Stat value={count(triage.outcomes, 'working', 'case_idle', 'needs_you').toLocaleString()} label="On a case still open" />
            <Stat value={count(triage.outcomes, 'needs_you').toLocaleString()} label="On a case waiting for a person" />
          </div>
          {triage.truncated && <div className="x1-card x1-note">This window holds more alerts than one read takes, so these counts cover the newest {triage.alerts.toLocaleString()}. Pick a shorter window for a full count.</div>}
          <div className="x1-split">
            <div className="x1-card" style={{ minWidth: 0 }}>
              <h3>Kinds of alert</h3>
              <div className="x1-table-wrap">
                <table className="x1-table">
                  <thead><tr><th>Kind</th><th>Alerts</th><th>Severity</th><th>What happened</th><th>Median to outcome</th></tr></thead>
                  <tbody>
                    {triage.kinds.map((row) => (
                      <tr
                        key={row.key}
                        tabIndex={0}
                        className="x1-rowbtn"
                        aria-selected={row.key === kind?.key}
                        onClick={() => setSelected(row.key)}
                        onKeyDown={onActivate(() => setSelected(row.key))}
                      >
                        <td>
                          <div style={{ color: 'var(--tx0)', overflowWrap: 'anywhere' }}>{row.title}</div>
                          <div className="x1-muted" style={{ fontSize: 12, display: 'flex', alignItems: 'center', gap: 5 }}><VendorLogo name={row.source} size={12} />{row.source}</div>
                        </td>
                        <td className="x1-mono">{row.alerts}</td>
                        <td>
                          <div className="x1-row" style={{ gap: 6 }}>
                            {row.severities.map((s) => <span key={s.severity} className="x1-row" style={{ gap: 3 }} title={s.severity}><SevDot level={s.severity} /><span className="x1-mono">{s.alerts}</span></span>)}
                          </div>
                        </td>
                        <td><div className="x1-row" style={{ gap: 4 }}>{row.outcomes.map((o) => <OutcomeTag key={o.state} outcome={o} />)}</div></td>
                        <td className="x1-mono" title={row.timed_outcomes ? `Over ${row.timed_outcomes} of ${row.alerts} alerts` : 'No stored outcome time'}>{row.median_seconds_to_outcome === null ? '-' : span(row.median_seconds_to_outcome)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
            {kind && <KindDetail key={kind.key} kind={kind} openFinding={setPopup} openCase={openCase} />}
          </div>
        </>
      )}
      <FindingPopup id={popup} onClose={() => setPopup(null)} />
    </div>
  )
}
