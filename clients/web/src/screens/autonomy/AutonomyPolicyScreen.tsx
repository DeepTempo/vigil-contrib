import { Fragment, useCallback, useEffect, useRef, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { useAuth } from '../../contexts/AuthContext'
import { autonomyApi, type Ceiling } from '../../services/api'
import {
  autonomyKindsApi,
  type AlertKind,
  type ClosedAlert,
  type KindEvent,
  type KindMode,
  type KindsView,
} from '../../services/autonomyKindsApi'
import type { ConsoleScreenProps } from '../../shared/types'
import { ConfirmDialog, EmptyState } from '../../shared/ui'
import { errorText } from '../../shared/errorText'
import { utcDayClock } from '../../shared/utc'
import { Stat, Tag, type TagTone } from '../shared/x1'

const MODE_TAG: Partial<Record<KindMode, { tone: TagTone; word: string }>> = {
  suspended: { tone: 'poor', word: 'Suspended' },
  expired: { tone: 'fair', word: 'Expired' },
}

const EVENT_WORD: Record<string, string> = {
  adopt: 'Adopted',
  renew: 'Re-adopted',
  revoke: 'Revoked',
  suspend: 'Suspended',
  expire: 'Expired',
  overturn: 'Overturned',
}

const pct = (value: number) => `${(value * 100).toFixed(1)}%`

function Curve({ days }: { days: KindsView['daily'] }) {
  const W = 520
  const H = 120
  const max = Math.max(1, ...days.map((d) => d.asked))
  const x = (i: number) => 34 + (i * (W - 50)) / (days.length - 1)
  const y = (v: number) => 10 + (1 - v / max) * (H - 34)
  const line = days.map((d, i) => `${i ? 'L' : 'M'}${x(i)},${y(d.asked)}`).join(' ')
  const last = days.length - 1
  return (
    <svg
      className="x1-spark"
      viewBox={`0 0 ${W} ${H}`}
      role="img"
      aria-label={`Alerts left for people per day: ${days.map((d) => `${d.day} ${d.asked}`).join(', ')}`}
    >
      <line className="ax" x1={34} x2={W - 16} y1={H - 24} y2={H - 24} />
      <path className="ar" d={`${line} L${x(last)},${H - 24} L${x(0)},${H - 24} Z`} />
      <path className="ln" d={line} />
      {days.map((d, i) => (
        <circle key={d.day} className="pt" cx={x(i)} cy={y(d.asked)} r={i === last ? 4 : 2.5}>
          <title>{`${d.day}: ${d.asked} left for people, ${d.closed} closed by Vigil`}</title>
        </circle>
      ))}
      <text x={x(0)} y={H - 8} textAnchor="start">{days[0].day.slice(5)}</text>
      <text x={x(last)} y={H - 8} textAnchor="end">{days[last].day.slice(5)}</text>
      <text x={x(0) + 6} y={y(days[0].asked) - 6}>{days[0].asked}</text>
      <text x={x(last) - 8} y={y(days[last].asked) - 8} textAnchor="end">{days[last].asked}</text>
    </svg>
  )
}

function ModePill({ mode }: { mode: KindMode }) {
  const close = mode === 'close'
  const tag = MODE_TAG[mode]
  return (
    <span className="x1-row" style={{ flexWrap: 'nowrap', gap: 6 }}>
      <span className="x1-mode" aria-label={close ? 'Mode: closes on its own' : 'Mode: asks a person'}>
        <span className={`observe${close ? '' : ' on'}`}>Ask a person</span>
        <span className={`act${close ? ' on' : ''}`}>Close</span>
      </span>
      {tag && <Tag tone={tag.tone}>{tag.word}</Tag>}
    </span>
  )
}

function whatChangesIt(kind: AlertKind, view: KindsView): string {
  if (kind.adoption) {
    return `Closes alerts rated ${view.auto_severities.join(' or ')}. Expires ${utcDayClock(kind.adoption.expires_at)} unless a person re-adopts it. One real closure suspends it.`
  }
  if (kind.mode_reason && kind.mode !== 'ask') return `${kind.mode_reason} A person must re-adopt it.`
  if (kind.eligible) return 'Eligible. A person can adopt close for this kind.'
  return kind.why_not.map((r) => r.why).join(' ')
}

function CeilingCard({ ceiling, failed, goSettings }: { ceiling: Ceiling | null; failed: boolean; goSettings: ConsoleScreenProps['goSettings'] }) {
  const raised = ceiling && !ceiling.stopped && !ceiling.environment_locked && (ceiling.act_reversible || ceiling.act_irreversible)
  return (
    <div className="x1-card" style={{ display: 'grid', gap: 8, alignContent: 'start' }}>
      <h3 style={{ margin: 0 }}>The install-wide ceiling</h3>
      {failed && <p className="x1-muted" style={{ margin: 0, fontSize: 12.5 }}>The ceiling could not be read, or you cannot see it. Treat it as unknown.</p>}
      {ceiling && (
        <dl className="x1-kv">
          <dt>State</dt>
          <dd>{ceiling.stopped ? 'Stopped. Nothing closes on its own.' : 'Running'}</dd>
          <dt>Reversible actions</dt>
          <dd>{ceiling.act_reversible && !ceiling.environment_locked ? 'May run without a person' : 'Ask a person'}</dd>
          <dt>Irreversible actions</dt>
          <dd>{ceiling.act_irreversible && !ceiling.environment_locked ? 'May run without a person' : 'Ask a person'}</dd>
        </dl>
      )}
      <p style={{ margin: 0, fontSize: 12.5, color: 'var(--tx0)' }}>
        {ceiling && !raised && <b>Containment always asks a person. </b>}
        A per-kind policy only marks an alert as noise. It cannot block, isolate or remove anything, and it never touches an approval.
      </p>
      {raised && (
        <p className="x1-note x1-card" style={{ margin: 0 }}>
          A person raised this ceiling for the whole install, so outside tools in the classes above may run with no approval. Until it is lowered, containment through those tools does not ask. Per-kind policies have no part in that.
        </p>
      )}
      <div><button type="button" className="x1-link" onClick={() => goSettings('autoinvestigate')}>Open Limits & autonomy</button></div>
    </div>
  )
}

function EarnCard({ view }: { view: KindsView }) {
  return (
    <div className="x1-card" style={{ display: 'grid', gap: 8, alignContent: 'start' }}>
      <h3 style={{ margin: 0 }}>How a kind of alert earns this</h3>
      <ul className="x1-reasons" style={{ fontSize: 12.5 }}>
        <li>Every kind starts on Ask a person.</li>
        <li>People make at least {view.bar} separate decisions that it is benign in {view.window_days} days, and none that it is real. One closed case is one decision, however many alerts it holds, and a burst of closes counts for nothing.</li>
        <li>No alert of the kind was rated high or critical in that time.</li>
        <li>It is exactly one rule in its source, by that source's rule identifier. A kind known only by its title cannot be adopted, because an alert can write its own title.</li>
        <li>A signed-in person adopts it. Vigil never adopts for itself.</li>
        <li>Vigil then closes only alerts of that same rule rated {view.auto_severities.join(' or ')}, and only when triage recommends dismissing them. It writes the policy id as the reason. What it closes never counts toward its own record.</li>
        <li>One real closure or one overturn suspends it. It expires after {view.lifetime_days} days unless a person re-adopts it.</li>
      </ul>
    </div>
  )
}

function KindDetail({
  kind,
  view,
  reload,
}: {
  kind: AlertKind
  view: KindsView
  reload: () => Promise<void>
}) {
  const { hasPermission } = useAuth()
  const [events, setEvents] = useState<KindEvent[] | null>(null)
  const [closed, setClosed] = useState<{ total: number; alerts: ClosedAlert[] } | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [reason, setReason] = useState('')
  const [confirm, setConfirm] = useState<'adopt' | 'revoke' | null>(null)
  const [overturning, setOverturning] = useState<ClosedAlert | null>(null)
  const canReadFindings = hasPermission('findings.read') && !view.redacted
  const canAdopt = hasPermission('ai_autonomy.write') && canReadFindings
  const canRevoke = hasPermission('ai_autonomy.stop')
  const canOverturn = hasPermission('findings.write')
  const track = kind.track_record

  const loadHistory = useCallback(async (sample = false) => {
    try {
      const ev = await autonomyKindsApi.events(kind.key)
      setEvents(ev.data.events)
      if (canReadFindings) setClosed((await autonomyKindsApi.closed(kind.key, sample)).data)
    } catch (err) {
      setError(errorText(err, 'Could not read this kind’s history.'))
    }
  }, [kind.key, canReadFindings])

  useEffect(() => { void loadHistory() }, [loadHistory])

  const act = async (work: () => Promise<unknown>, failure: string) => {
    setBusy(true)
    setError(null)
    try {
      await work()
      setReason('')
      await reload()
      await loadHistory()
    } catch (err) {
      setError(errorText(err, failure))
    } finally {
      setBusy(false)
      setConfirm(null)
      setOverturning(null)
    }
  }

  return (
    <div style={{ display: 'grid', gap: 12, padding: '4px 2px 8px' }}>
      {error && <div className="x1-card x1-error" role="alert">{error}</div>}
      <div className="x1-grid2">
        <div style={{ display: 'grid', gap: 8, alignContent: 'start' }}>
          <dl className="x1-kv">
            {kind.title !== null && <><dt>Source rule</dt><dd className="x1-mono" data-testid="kind-rule">{kind.rule_id ?? 'None. Known only by its title.'}</dd></>}
            <dt>Closed here by people</dt><dd>{track.closed_here_benign} benign, {track.closed_here_real} real</dd>
            <dt>Imported from cold start</dt><dd>{track.imported_benign} benign, {track.imported_real} real. Tickets from your history, not closures here.</dd>
            <dt>Overturned</dt><dd>{track.overturned}</dd>
            <dt>Closed by Vigil</dt><dd>{track.closed_by_vigil}. Not counted as evidence.</dd>
            {track.bulk_ignored > 0 && <><dt>Ignored as a burst</dt><dd>{track.bulk_ignored}</dd></>}
            <dt>Miss bound</dt><dd>{track.miss_bound === null ? 'None' : `At most ${pct(track.miss_bound)} of this kind is really an attack, at 95% confidence`}</dd>
            {kind.adoption && <><dt>Adopted by</dt><dd>{kind.adoption.by_label ?? kind.adoption.by}, {utcDayClock(kind.adoption.at)} UTC.{kind.adoption.reason ? ` ${kind.adoption.reason}` : ''}</dd></>}
          </dl>
          <div className="x1-row">
            {(canAdopt || canRevoke) && (
              <input
                aria-label="Reason, kept in the record"
                placeholder="Reason, kept in the record"
                value={reason}
                onChange={(e) => setReason(e.target.value)}
                style={{ flex: '1 1 220px', height: 30, padding: '0 8px', borderRadius: 7, border: '1px solid var(--ln1)', background: 'var(--bg2)', color: 'var(--tx0)', fontSize: 12.5 }}
              />
            )}
            {canAdopt && (
              <button type="button" className="btn primary" disabled={!kind.eligible || busy} onClick={() => setConfirm('adopt')}>
                {kind.adoption ? 'Re-adopt' : 'Adopt close'}
              </button>
            )}
            {canRevoke && kind.adoption && (
              <button type="button" className="btn ghost" disabled={busy} onClick={() => setConfirm('revoke')}>Revoke</button>
            )}
          </div>
          {!kind.eligible && !kind.adoption && (
            <ul className="x1-reasons" style={{ fontSize: 12.5 }}>
              {kind.why_not.map((r) => <li key={r.rule}>{r.why}</li>)}
            </ul>
          )}
        </div>
        <div style={{ display: 'grid', gap: 6, alignContent: 'start' }}>
          <h3 style={{ margin: 0, fontSize: 11, textTransform: 'uppercase', letterSpacing: '.6px', color: 'var(--tx2)' }}>Record</h3>
          {events?.length === 0 && <span className="x1-muted" style={{ fontSize: 12.5 }}>No one has adopted this kind.</span>}
          {events?.map((e) => (
            <div key={e.id} style={{ fontSize: 12.5 }}>
              <b style={{ color: 'var(--tx0)' }}>{EVENT_WORD[e.event ?? ''] ?? e.event}</b>{' '}
              <span className="x1-muted">{utcDayClock(e.at)} UTC by {e.actor_label ?? e.actor}.</span> {e.reason}
            </div>
          ))}
        </div>
      </div>
      {canReadFindings && <div style={{ display: 'grid', gap: 6 }}>
        <div className="x1-row" style={{ justifyContent: 'space-between' }}>
          <h3 style={{ margin: 0, fontSize: 11, textTransform: 'uppercase', letterSpacing: '.6px', color: 'var(--tx2)' }}>
            What this policy closed{closed ? ` (${closed.total})` : ''}
          </h3>
          {(closed?.total ?? 0) > 0 && (
            <button type="button" className="x1-link" onClick={() => void loadHistory(true)}>Sample 10 at random</button>
          )}
        </div>
        {closed?.total === 0 && <span className="x1-muted" style={{ fontSize: 12.5 }}>Nothing yet.</span>}
        {closed?.alerts.map((alert) => (
          <div key={alert.finding_id} className="x1-action">
            <span>
              <span style={{ color: 'var(--tx0)' }}>{alert.title ?? alert.finding_id}</span>{' '}
              <span className="x1-muted x1-mono">{alert.severity} · {utcDayClock(alert.closed_at)} UTC · {alert.policy_reason}</span>
            </span>
            {canOverturn && (
              <button type="button" className="btn ghost" disabled={busy} onClick={() => setOverturning(alert)}>This was real</button>
            )}
          </div>
        ))}
      </div>}
      <ConfirmDialog
        open={confirm === 'adopt'}
        title="Let Vigil close this kind on its own?"
        danger={false}
        busy={busy}
        confirmLabel={kind.adoption ? 'Re-adopt' : 'Adopt close'}
        body={`Vigil will mark ${view.auto_severities.join(' and ')} alerts of “${kind.title}” as noise once triage has run. Your name goes on the record. It expires in ${view.lifetime_days} days.${view.close_enabled ? '' : ' Per-kind closing is off for this install, so nothing closes until it is turned on.'}`}
        onClose={() => setConfirm(null)}
        onConfirm={() => void act(() => autonomyKindsApi.adopt(kind.key, reason || undefined), 'Adoption was refused.')}
      />
      <ConfirmDialog
        open={confirm === 'revoke'}
        title="Revoke this adoption?"
        danger={false}
        busy={busy}
        confirmLabel="Revoke"
        body="Vigil goes back to asking a person about this kind. What it already closed stays closed."
        onClose={() => setConfirm(null)}
        onConfirm={() => void act(() => autonomyKindsApi.revoke(kind.key, reason || undefined), 'Could not revoke.')}
      />
      <ConfirmDialog
        open={overturning !== null}
        title="Overturn this closure?"
        busy={busy}
        confirmLabel="This was real"
        body="The alert goes back in the queue. This counts as a real closure, so the policy is suspended and the kind cannot be adopted again until the real label leaves the window."
        onClose={() => setOverturning(null)}
        onConfirm={() => overturning && void act(() => autonomyKindsApi.overturn(kind.key, overturning.finding_id), 'Could not overturn.')}
      />
    </div>
  )
}

export default function AutonomyPolicyScreen({ goSettings }: ConsoleScreenProps) {
  const { hasPermission } = useAuth()
  const [params] = useSearchParams()
  const wanted = params.get('kind')
  const [view, setView] = useState<KindsView | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [ceiling, setCeiling] = useState<Ceiling | null>(null)
  const [ceilingFailed, setCeilingFailed] = useState(false)
  const [open, setOpen] = useState<string | null>(null)
  const [toggling, setToggling] = useState(false)
  const [confirmOn, setConfirmOn] = useState(false)
  const focused = useRef<HTMLTableRowElement | null>(null)

  const reload = useCallback(async () => {
    try {
      const { data } = await autonomyKindsApi.list()
      setView(data)
      setError(null)
    } catch (err) {
      setError(errorText(err, 'Could not read the kinds of alert.'))
    }
  }, [])

  useEffect(() => {
    void reload()
    autonomyApi.get().then(({ data }) => setCeiling(data)).catch(() => setCeilingFailed(true))
  }, [reload])

  const focusKey = view?.kinds.find((k) => k.key === wanted || (k.signature !== null && k.signature === wanted))?.key ?? null
  useEffect(() => {
    if (focusKey) setOpen(focusKey)
  }, [focusKey])
  useEffect(() => {
    if (focusKey) focused.current?.scrollIntoView?.({ block: 'center' })
  }, [focusKey])

  const setClosing = async (on: boolean) => {
    setToggling(true)
    try {
      await autonomyKindsApi.setClosing(on)
      await reload()
    } catch (err) {
      setError(errorText(err, 'Could not change the setting.'))
    } finally {
      setToggling(false)
      setConfirmOn(false)
    }
  }

  if (!view) {
    return (
      <div className="x1">
        {error
          ? <EmptyState error icon="alert" title="Couldn’t load autonomy" body={error} primary={{ label: 'Try again', onClick: () => void reload() }} />
          : <EmptyState loading icon="graph" title="Loading autonomy…" />}
      </div>
    )
  }

  const canToggle = view.close_enabled ? hasPermission('ai_autonomy.stop') : hasPermission('ai_autonomy.write')
  const firstDay = view.daily.findIndex((d) => d.asked + d.closed > 0)
  const chartDays = firstDay === -1 ? [] : view.daily.slice(firstDay)

  return (
    <div className="x1">
      {error && <div className="x1-card x1-error" role="alert">{error}</div>}
      <div className="x1-grid3">
        <Stat value={`${view.summary.closing} of ${view.summary.kinds}`} label={`kinds of alert Vigil closes on its own, ${view.summary.closed_by_vigil} closed in the last ${view.window_days} days`} />
        {chartDays.length === 0 && <Stat value="No alerts yet" label="alerts left for people per day, once alerts arrive" />}
        {chartDays.length === 1 && <Stat value={chartDays[0].asked} label="alerts left for people on the one day with alerts so far" />}
        {chartDays.length >= 2 && (
          <Stat
            value={`${chartDays[0].asked} → ${chartDays[chartDays.length - 1].asked}`}
            label={`alerts left for people per day, over the last ${chartDays.length} days`}
          />
        )}
        <Stat value="None" label="containment a per-kind policy can take. It only marks alerts as noise." />
      </div>

      {view.redacted && (
        <div className="x1-card x1-note" data-testid="kinds-redacted">
          You can see each policy and its counts. Reading what fired, and what a policy closed, needs permission to read findings.
        </div>
      )}
      {view.incomplete && (
        <div className="x1-card x1-note" data-testid="kinds-incomplete">
          This install holds more alerts than one read may take, so these records are incomplete and no kind can be adopted.
        </div>
      )}
      {view.kinds_shown < view.summary.kinds && (
        <div className="x1-card x1-note" data-testid="kinds-shown">
          Showing the first {view.kinds_shown.toLocaleString()} of {view.summary.kinds.toLocaleString()} kinds, adopted and eligible kinds first.
        </div>
      )}

      <div className={`x1-card ${view.close_enabled ? 'x1-note' : ''}`} style={{ display: 'flex', flexWrap: 'wrap', gap: 12, alignItems: 'center', justifyContent: 'space-between' }}>
        <span style={{ fontSize: 13, color: 'var(--tx0)' }}>
          <span className={`x1-dot${view.close_enabled ? '' : ' off'}`} />
          <b>Per-kind closing is {view.close_enabled ? 'on' : 'off'}.</b>{' '}
          {view.close_enabled
            ? 'The daemon closes alerts of an adopted kind on its own.'
            : 'This is the default. Vigil asks a person about every alert, adopted kinds included.'}
        </span>
        {canToggle && (
          <button
            type="button"
            className={`btn ${view.close_enabled ? 'ghost' : 'primary'}`}
            disabled={toggling}
            onClick={() => (view.close_enabled ? void setClosing(false) : setConfirmOn(true))}
          >
            {view.close_enabled ? 'Turn off' : 'Turn on'}
          </button>
        )}
      </div>

      <div className="x1-grid2">
        <div className="x1-card">
          <h3>Alerts left for people per day</h3>
          {chartDays.length >= 2
            ? <Curve days={chartDays} />
            : <p className="x1-muted" style={{ fontSize: 12.5, margin: 0 }}>{chartDays.length === 1 ? 'One day of alerts so far. The line starts on the second day.' : 'No alerts in the last two weeks.'}</p>}
          <p className="x1-muted" style={{ fontSize: 12, margin: '6px 0 0' }}>
            Each alert of a day that Vigil did not close under a policy counts once. Closing an alert as noise changes nothing in your systems.
          </p>
        </div>
        <CeilingCard ceiling={ceiling} failed={ceilingFailed} goSettings={goSettings} />
      </div>

      {view.kinds.length === 0 ? (
        <>
          <EmptyState icon="info" title="No kinds of alert yet" body="A kind appears here once alerts arrive or a cold start run goes live. It starts on Ask a person." />
          <EarnCard view={view} />
        </>
      ) : (
        <>
          <div className="x1-table-wrap">
            <table className="x1-table">
              <thead>
                <tr>
                  <th>Kind of alert</th>
                  <th>What Vigil may do</th>
                  <th className="num">Seen</th>
                  <th className="num">Reviewed by people</th>
                  <th className="num">People agreed</th>
                  <th className="num">Real</th>
                  <th>Since</th>
                  <th>What changes it</th>
                </tr>
              </thead>
              <tbody>
                {view.kinds.map((kind) => {
                  const track = kind.track_record
                  const isOpen = open === kind.key
                  return (
                    <Fragment key={kind.key}>
                      <tr
                        ref={kind.key === focusKey ? focused : undefined}
                        className={`x1-rowbtn click${isOpen ? ' open' : ''}`}
                        aria-selected={kind.key === focusKey}
                        aria-expanded={isOpen}
                        tabIndex={0}
                        onClick={() => setOpen(isOpen ? null : kind.key)}
                        onKeyDown={(e) => {
                          if (e.key === 'Enter' || e.key === ' ') {
                            e.preventDefault()
                            setOpen(isOpen ? null : kind.key)
                          }
                        }}
                      >
                        <td style={{ color: 'var(--tx0)' }}>
                          {kind.title ?? <span className="x1-muted">Kind {kind.key}</span>}
                          {kind.source !== null && <div className="x1-muted" style={{ fontSize: 12 }}>{kind.source}</div>}
                        </td>
                        <td><ModePill mode={kind.mode} /></td>
                        <td className="num">{track.alerts_seen}</td>
                        <td className="num">{track.reviewed}</td>
                        <td className="num">
                          {track.agreed}
                          {track.reviewed > 0 && <span className="x1-muted"> ({Math.round((track.agreed / track.reviewed) * 100)}%)</span>}
                        </td>
                        <td className="num">{track.real}</td>
                        <td className="x1-ts">{kind.adoption ? utcDayClock(kind.adoption.at) : '—'}</td>
                        <td className="x1-muted">{whatChangesIt(kind, view)}</td>
                      </tr>
                      {isOpen && (
                        <tr>
                          <td colSpan={8}><KindDetail kind={kind} view={view} reload={reload} /></td>
                        </tr>
                      )}
                    </Fragment>
                  )
                })}
              </tbody>
            </table>
          </div>
          <EarnCard view={view} />
        </>
      )}
      <ConfirmDialog
        open={confirmOn}
        title="Turn per-kind closing on?"
        danger={false}
        busy={toggling}
        confirmLabel="Turn on"
        body={`The daemon will close ${view.auto_severities.join(' and ')} alerts of the ${view.summary.closing} adopted kinds with no person in the loop. A person can overturn any of them here.`}
        onClose={() => setConfirmOn(false)}
        onConfirm={() => void setClosing(true)}
      />
    </div>
  )
}
