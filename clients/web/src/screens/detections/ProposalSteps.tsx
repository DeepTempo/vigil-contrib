import { useEffect, useState } from 'react'
import type { ConsoleScreenProps } from '../../shared/types'
import {
  detectionsApi, type EventSample, type Proposal, type ProposalState, type ShadowReport, type TargetRow, type TargetsReport,
} from '../../services/detectionsApi'
import { Stat, Tag } from '../shared/x1'
import { Failure, Note, STATE_TONE, TARGET_STATUS, refusal, when } from './shared'

type Step = 'draft' | 'lint' | 'replay' | 'tune' | 'convert' | 'shadow' | 'live'

const STEPS: { id: Step; label: string; what: string }[] = [
  { id: 'draft', label: 'Draft', what: 'Sigma from a step no rule caught' },
  { id: 'lint', label: 'Lint', what: 'Refuses brittle rules' },
  { id: 'replay', label: 'Replay', what: 'Attack rows hit, other rows quiet' },
  { id: 'tune', label: 'Tune', what: 'A person adds an exclusion' },
  { id: 'convert', label: 'Convert', what: 'One status per SIEM' },
  { id: 'shadow', label: 'Shadow', what: 'A person stages it' },
  { id: 'live', label: 'Live', what: 'A person promotes it' },
]

const VIEW_FOR_STATE: Record<ProposalState, Step> = {
  draft: 'draft',
  linted: 'lint',
  replayed: 'replay',
  converted: 'convert',
  shadow: 'shadow',
  live: 'live',
  rejected: 'draft',
}

const ORDER: ProposalState[] = ['draft', 'linted', 'replayed', 'converted', 'shadow', 'live']

function stepDone(step: Step, proposal: Proposal): boolean {
  const reached = ORDER.indexOf(proposal.state)
  if (step === 'tune') return Boolean(proposal.latest.tune?.judges_current_text) && reached >= ORDER.indexOf('replayed')
  const needed: Record<Exclude<Step, 'tune'>, ProposalState> = { draft: 'linted', lint: 'linted', replay: 'replayed', convert: 'converted', shadow: 'shadow', live: 'live' }
  return reached >= ORDER.indexOf(needed[step])
}

interface Props {
  proposal: Proposal
  canWrite: boolean
  applied: (next: Proposal) => void
  go: ConsoleScreenProps['go']
  openCase: ConsoleScreenProps['openCase']
}

export default function ProposalSteps({ proposal, canWrite, applied, go, openCase }: Props) {
  const [view, setView] = useState<Step>(VIEW_FOR_STATE[proposal.state])
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [rejecting, setRejecting] = useState(false)
  const [rejectReason, setRejectReason] = useState('')
  const id = proposal.proposal_id

  useEffect(() => { setView(VIEW_FOR_STATE[proposal.state]); setError(null) }, [id, proposal.state])

  const run = async (action: () => Promise<Proposal>, then?: Step) => {
    setBusy(true)
    setError(null)
    try {
      const next = await action()
      applied(next)
      if (then) setView(then)
    } catch (e) {
      setError(refusal(e, 'That step did not run.'))
    } finally {
      setBusy(false)
    }
  }

  const open = proposal.state !== 'live' && proposal.state !== 'rejected'
  const context = { proposal, canWrite, busy, run }

  return (
    <>
      <div className="x1-card" style={{ display: 'grid', gap: 10 }}>
        <div className="x1-row" style={{ justifyContent: 'space-between' }}>
          <div style={{ display: 'grid', gap: 2, minWidth: 0 }}>
            <h2>{proposal.title}</h2>
            <span className="x1-muted" style={{ fontSize: 12.5 }}>
              {proposal.technique ?? 'No technique'} · Started by {proposal.created_by}, {when(proposal.created_at)}
              {proposal.case_id && <> · <button type="button" className="x1-link" onClick={() => openCase(proposal.case_id!)}>Case {proposal.case_id}</button></>}
            </span>
          </div>
          <div className="x1-row">
            <Tag tone={STATE_TONE[proposal.state]}>{proposal.state}</Tag>
            {proposal.case_id && <button type="button" className="btn ghost" onClick={() => go('logs', { search: `?case=${encodeURIComponent(proposal.case_id!)}` })}>See the events</button>}
            {canWrite && open && <button type="button" className="btn ghost" onClick={() => setRejecting((r) => !r)}>Reject</button>}
          </div>
        </div>
        {rejecting && (
          <div className="x1-row">
            <input className="de-text" style={{ flex: '1 1 260px' }} aria-label="Why this proposal is rejected" placeholder="Why it is rejected" value={rejectReason} onChange={(e) => setRejectReason(e.target.value)} />
            <button type="button" className="btn primary" disabled={!rejectReason.trim() || busy} onClick={() => run(() => detectionsApi.reject(id, rejectReason))}>Reject this proposal</button>
          </div>
        )}
        {proposal.state === 'rejected' && <Note>Rejected by {proposal.latest.reject?.actor}: {proposal.latest.reject?.reason}</Note>}
        <div className="x1-flow" role="tablist" aria-label="Steps" data-testid="de-stepper">
          {STEPS.map((s) => (
            <button key={s.id} type="button" role="tab" aria-selected={view === s.id} className={`${stepDone(s.id, proposal) ? 'done' : ''}${view === s.id ? ' on' : ''}`} onClick={() => setView(s.id)}>
              <b>{s.label}</b>
              <span>{s.what}</span>
            </button>
          ))}
        </div>
      </div>
      {error && <Failure>{error}</Failure>}
      {view === 'draft' && <DraftStep {...context} setView={setView} />}
      {view === 'lint' && <LintStep {...context} setView={setView} />}
      {view === 'replay' && <ReplayStep {...context} setView={setView} />}
      {view === 'tune' && <TuneStep {...context} setView={setView} />}
      {view === 'convert' && <ConvertStep {...context} />}
      {view === 'shadow' && <ShadowStep {...context} />}
      {view === 'live' && <LiveStep {...context} />}
      <div className="x1-card">
        <h3>What happened, on the record</h3>
        <ol className="de-history" data-testid="de-history">
          {proposal.events.map((e) => (
            <li key={e.id}>
              <span className="x1-ts">{when(e.at)}</span>
              <span>
                <b>{e.actor}</b> · {e.evidence.step}
                {e.from_state !== e.to_state ? ` · ${e.from_state ?? 'new'} to ${e.to_state}` : ' · stayed ' + e.to_state}
                {e.evidence.tool ? <span className="x1-muted"> · {e.evidence.tool}</span> : null}
                {e.reason ? <div className="x1-muted">{e.reason}</div> : null}
              </span>
            </li>
          ))}
        </ol>
      </div>
    </>
  )
}

interface StepProps {
  proposal: Proposal
  canWrite: boolean
  busy: boolean
  run: (action: () => Promise<Proposal>, then?: Step) => Promise<void>
}

function DraftStep({ proposal, canWrite, busy, run, setView }: StepProps & { setView: (s: Step) => void }) {
  const [text, setText] = useState(proposal.sigma)
  const [reason, setReason] = useState('')
  useEffect(() => setText(proposal.sigma), [proposal.sigma])
  const draft = proposal.latest.draft?.evidence
  const editable = canWrite && proposal.state !== 'live' && proposal.state !== 'rejected'
  const changed = text !== proposal.sigma
  return (
    <div className="x1-grid2">
      <div className="x1-card de-form">
        <h3 style={{ margin: 0 }}>Proposed Sigma rule</h3>
        <textarea className="de-text mono" rows={18} spellCheck={false} aria-label="Sigma rule" data-testid="de-sigma" value={text} readOnly={!editable} onChange={(e) => setText(e.target.value)} />
        {changed && <input className="de-text" aria-label="Why it changed" placeholder="Why it changed (optional)" value={reason} onChange={(e) => setReason(e.target.value)} />}
        {editable && (
          <div className="x1-row">
            {changed && <button type="button" className="btn ghost" disabled={busy} onClick={() => run(() => detectionsApi.edit(proposal.proposal_id, text, reason))}>Save the change</button>}
            {proposal.state === 'draft' && !changed && <button type="button" className="btn primary" disabled={busy} onClick={() => run(() => detectionsApi.lint(proposal.proposal_id), 'lint')}>Run lint</button>}
            {proposal.state !== 'draft' && !changed && <span className="x1-muted" style={{ fontSize: 12 }}>Saving a change sends it back here: the checks it passed judged the old text.</span>}
          </div>
        )}
      </div>
      <div className="x1-card" style={{ display: 'grid', gap: 8, alignContent: 'start' }}>
        <h3 style={{ margin: 0 }}>How it was drafted</h3>
        <span style={{ fontSize: 13 }}>{draft?.source ?? 'Not recorded'}{draft?.asked_by ? ` (${draft.asked_by})` : ''}.</span>
        {draft?.tool && <span className="x1-mono x1-muted">{draft.tool}</span>}
        {(draft?.filled_in?.length ?? 0) > 0 && <span className="x1-muted" style={{ fontSize: 12.5 }}>Vigil filled in: {draft?.filled_in?.join(', ')}.</span>}
        <span className="x1-muted" style={{ fontSize: 12.5 }}>Nothing here is taken on the drafter&apos;s word. The next steps are tool runs, and a person moves each stage after them.</span>
        {proposal.state !== 'draft' && <button type="button" className="x1-link" onClick={() => setView('lint')}>See the checks</button>}
      </div>
    </div>
  )
}

function LintStep({ proposal, canWrite, busy, run, setView }: StepProps & { setView: (s: Step) => void }) {
  const event = proposal.latest.lint
  const evidence = event?.evidence
  if (!event || !evidence) {
    return (
      <div className="x1-card" style={{ display: 'grid', gap: 8 }}>
        <span className="x1-muted">Lint has not run on this rule.</span>
        {canWrite && proposal.state === 'draft' && <div><button type="button" className="btn primary" disabled={busy} onClick={() => run(() => detectionsApi.lint(proposal.proposal_id))}>Run lint</button></div>}
      </div>
    )
  }
  return (
    <div className="x1-card" style={{ display: 'grid', gap: 8 }} data-testid="de-lint">
      <div className="x1-row" style={{ justifyContent: 'space-between' }}>
        <h3 style={{ margin: 0 }}>Checked by tools, not the drafter&apos;s own report</h3>
        <Tag tone={evidence.passed ? 'good' : 'poor'}>{evidence.passed ? 'Passed' : 'Refused'}</Tag>
      </div>
      {(evidence.checks ?? []).map((c) => (
        <div key={c.name} className="x1-check" style={{ alignItems: 'flex-start' }}>
          <span className={c.passed === false ? 'no' : c.passed ? 'ok' : 'x1-muted'}>{c.passed === false ? '✕' : c.passed ? '✓' : '–'}</span>
          <span>{c.name}{!c.blocking && c.passed === false ? <span className="x1-muted"> (advice)</span> : null}{c.detail ? <div className="x1-muted" style={{ fontSize: 12 }}>{c.detail}</div> : null}</span>
        </div>
      ))}
      {!event.judges_current_text && <span className="x1-muted" style={{ fontSize: 12 }}>This result judged an earlier version of the rule.</span>}
      <div className="x1-row">
        {canWrite && proposal.state === 'draft' && <button type="button" className="btn primary" disabled={busy} onClick={() => run(() => detectionsApi.lint(proposal.proposal_id))}>Run lint again</button>}
        {canWrite && proposal.state === 'linted' && <button type="button" className="btn primary" disabled={busy} onClick={() => run(() => detectionsApi.replay(proposal.proposal_id, 30), 'replay')}>Replay on stored events</button>}
        {proposal.state === 'draft' && <button type="button" className="btn ghost" onClick={() => setView('draft')}>Edit the rule</button>}
      </div>
    </div>
  )
}

function SampleTable({ title, rows }: { title: string; rows: EventSample[] }) {
  if (rows.length === 0) return null
  return (
    <div className="x1-table-wrap">
      <table className="x1-table">
        <caption className="x1-muted" style={{ textAlign: 'left', padding: '8px 10px', fontSize: 12 }}>{title}</caption>
        <thead><tr><th>Time</th><th>Source</th><th>Host</th><th>User</th><th>Event</th></tr></thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.event_id}><td className="x1-ts">{when(r.time)}</td><td>{r.source}</td><td>{r.src_host ?? ''}</td><td>{r.user_name ?? ''}</td><td>{r.summary}</td></tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function ReplayStep({ proposal, canWrite, busy, run, setView }: StepProps & { setView: (s: Step) => void }) {
  const [windowDays, setWindowDays] = useState(30)
  const event = proposal.latest.replay
  const evidence = event?.evidence
  const replayable = proposal.state === 'linted' || proposal.state === 'replayed'
  const action = canWrite && replayable && (
    <div className="x1-row">
      <label className="x1-muted" style={{ fontSize: 12 }}>Other rows from the last <input className="de-text" style={{ width: 70, display: 'inline-block' }} type="number" min={1} max={365} value={windowDays} onChange={(e) => setWindowDays(Number(e.target.value) || 30)} /> days</label>
      <button type="button" className="btn primary" disabled={busy} onClick={() => run(() => detectionsApi.replay(proposal.proposal_id, windowDays))}>{event ? 'Replay again' : 'Replay on stored events'}</button>
    </div>
  )
  if (!evidence) return <div className="x1-card" style={{ display: 'grid', gap: 8 }}><span className="x1-muted">Replay has not run. It needs a rule that passed lint, and events on the Logs screen.</span>{action}</div>
  if (!evidence.evaluated) {
    return (
      <div className="x1-card" style={{ display: 'grid', gap: 8 }} data-testid="de-replay">
        <h3 style={{ margin: 0 }}>Not replayed</h3>
        <span>{evidence.reason}</span>
        {action}
      </div>
    )
  }
  const falsePositives = evidence.false_positives ?? 0
  return (
    <div style={{ display: 'grid', gap: 12 }} data-testid="de-replay">
      <div className="x1-grid3">
        <Stat value={<span className={`de-big ${(evidence.hits ?? 0) > 0 ? 'good' : 'bad'}`}>{evidence.hits}/{evidence.attack_rows}</span>} label={`attack rows matched (${evidence.attack_basis})`} />
        <Stat value={<span className={`de-big ${falsePositives ? 'bad' : 'good'}`}>{falsePositives}/{evidence.benign_rows}</span>} label={`other rows matched, last ${evidence.window_days} days${evidence.benign_truncated ? ', newest rows only' : ''}`} />
        <Stat value={evidence.benign_rows_holding_fields ?? 0} label="of those rows hold a field the rule reads" />
      </div>
      <div className={`x1-card ${evidence.proven ? '' : 'x1-note'}`}>
        <b style={{ color: 'var(--tx0)' }}>{evidence.proven ? 'Proven on these rows.' : 'Not proven yet.'}</b>{' '}
        {evidence.unproven_because}
        <p className="de-note" style={{ marginTop: 6 }}>
          &quot;Other rows&quot; are rows no case claims. Vigil assumes they are normal, so a match may be a real attack nobody linked. Evaluated by {evidence.engine === 'vigil' ? "Vigil's Sigma evaluator" : 'the pySigma condition tree'}.
          {!event?.judges_current_text ? ' This result judged an earlier version of the rule.' : ''}
        </p>
      </div>
      <SampleTable title="Other rows the rule matched" rows={evidence.false_positive_samples ?? []} />
      <SampleTable title="Attack rows the rule matched" rows={evidence.hit_samples ?? []} />
      <div className="x1-row">
        {action}
        {falsePositives > 0 && canWrite && <button type="button" className="btn ghost" onClick={() => setView('tune')}>Tune it</button>}
        {proposal.state === 'replayed' && <button type="button" className="btn ghost" onClick={() => setView('convert')}>Go to convert</button>}
      </div>
    </div>
  )
}

function TuneStep({ proposal, canWrite, busy, run, setView }: StepProps & { setView: (s: Step) => void }) {
  const [field, setField] = useState('')
  const [match, setMatch] = useState('contains')
  const [value, setValue] = useState('')
  const [reason, setReason] = useState('')
  const tune = proposal.latest.tune
  const replay = proposal.latest.replay
  const before = tune?.evidence.before
  const tunable = canWrite && proposal.state !== 'live' && proposal.state !== 'rejected'
  return (
    <div className="x1-grid2">
      <div className="x1-card de-form">
        <h3 style={{ margin: 0 }}>Add an exclusion</h3>
        <p className="de-note">A person decides what is safe to exclude. Vigil then runs lint and replay again on the same attack rows. Lint refuses an exclusion keyed to one host, address or account, so key it on what the activity does.</p>
        <label>Field<input className="de-text mono" placeholder="ParentCommandLine" value={field} disabled={!tunable} onChange={(e) => setField(e.target.value)} /></label>
        <label>Match
          <select className="de-text" value={match} disabled={!tunable} onChange={(e) => setMatch(e.target.value)}>
            <option value="contains">contains</option><option value="startswith">starts with</option><option value="endswith">ends with</option><option value="equals">equals</option>
          </select>
        </label>
        <label>Value<input className="de-text mono" value={value} disabled={!tunable} onChange={(e) => setValue(e.target.value)} /></label>
        <label>Why this is safe<input className="de-text" value={reason} disabled={!tunable} onChange={(e) => setReason(e.target.value)} /></label>
        {tunable && (
          <div className="x1-row">
            <button type="button" className="btn primary" disabled={busy || !field.trim() || !value.trim() || !reason.trim()} onClick={() => run(() => detectionsApi.tune(proposal.proposal_id, { field: field.trim(), match, values: [value], reason }), 'tune')}>Apply and replay</button>
          </div>
        )}
      </div>
      <div className="x1-card" style={{ display: 'grid', gap: 8, alignContent: 'start' }} data-testid="de-tune">
        <h3 style={{ margin: 0 }}>Before and after</h3>
        {!tune && <span className="x1-muted">No exclusion yet.</span>}
        {tune && (
          <>
            <span style={{ fontSize: 13 }}>{tune.actor} excluded {tune.evidence.exclusion?.field} {tune.evidence.exclusion?.match} {tune.evidence.exclusion?.values.join(', ')}. {tune.reason}</span>
            {before && <span>Before: {before.hits}/{before.attack_rows} hits, {before.false_positives}/{before.benign_rows} other rows.</span>}
            {replay?.judges_current_text && replay.evidence.evaluated
              ? <span>After: {replay.evidence.hits}/{replay.evidence.attack_rows} hits, {replay.evidence.false_positives}/{replay.evidence.benign_rows} other rows.</span>
              : <span className="x1-muted">Not replayed since: see Lint for why.</span>}
            {proposal.state === 'draft' && <button type="button" className="x1-link" onClick={() => setView('lint')}>See the lint result</button>}
          </>
        )}
      </div>
    </div>
  )
}

function OutputRow({ row }: { row: TargetRow }) {
  const [open, setOpen] = useState(false)
  const status = TARGET_STATUS[row.status]
  const download = () => {
    const url = URL.createObjectURL(new Blob([row.output], { type: 'text/plain' }))
    const a = document.createElement('a')
    a.href = url
    a.download = row.file ?? `${row.target}.txt`
    a.click()
    URL.revokeObjectURL(url)
  }
  return (
    <>
      <tr>
        <td style={{ color: 'var(--tx0)' }}>{row.platform}</td>
        <td><Tag tone={status.tone}>{status.label}</Tag></td>
        <td className="x1-mono">{row.pipeline.join('+') || (row.status === 'converted' ? 'no field mapping applied' : '')}</td>
        <td className="num">{row.measured_valid_pct != null ? `${row.measured_valid_pct}%` : ''}</td>
        <td>
          {row.output && <span className="x1-row" style={{ gap: 10 }}><button type="button" className="x1-link" aria-expanded={open} onClick={() => setOpen((o) => !o)}>{open ? 'Hide' : 'Show'}</button><button type="button" className="x1-link" onClick={download}>Download</button></span>}
          {!row.output && row.error && row.status !== 'not_installed' && <span className="x1-muted" style={{ fontSize: 12 }}>{row.error}</span>}
          {row.status === 'not_installed' && <span className="x1-muted" style={{ fontSize: 12 }}>No backend for this target here</span>}
        </td>
      </tr>
      {open && <tr><td colSpan={5}><div className="de-output x1-mono x1-muted">{row.file}</div><pre className="x1-pre">{row.output}</pre></td></tr>}
    </>
  )
}

function ConvertStep({ proposal, canWrite, busy, run }: StepProps) {
  const [report, setReport] = useState<TargetsReport | null>(null)
  const [splunk, setSplunk] = useState('')
  const [elastic, setElastic] = useState('')
  const [accept, setAccept] = useState('')
  useEffect(() => { detectionsApi.targets().then(setReport).catch(() => setReport(null)) }, [])
  const event = proposal.latest.convert
  const rows = [...(event?.evidence.targets ?? [])].sort((a, b) => Number(Boolean(b.output)) - Number(Boolean(a.output)))
  const replay = proposal.latest.replay
  const unproven = replay?.judges_current_text && !replay.evidence.proven
  const convertible = proposal.state === 'replayed' || proposal.state === 'converted'
  const convert = () => run(() => detectionsApi.convert(proposal.proposal_id, {
    accept_reason: accept.trim() || undefined,
    pasted: splunk.trim() || elastic.trim() ? { ...(splunk.trim() ? { splunk } : {}), ...(elastic.trim() ? { elastic } : {}) } : undefined,
  }))
  return (
    <div style={{ display: 'grid', gap: 12 }}>
      <Note>Conversion produces text. Vigil writes nothing to your SIEM: download a file and load it yourself, disabled where the format allows.</Note>
      {report?.not_installed && <Note>{report.not_installed}</Note>}
      {rows.length > 0 && (
        <div className="x1-table-wrap">
          <table className="x1-table" data-testid="de-targets">
            <thead><tr><th>Target</th><th>This rule</th><th>Field mapping</th><th className="num">Measured</th><th>Output</th></tr></thead>
            <tbody>{rows.map((row) => <OutputRow key={row.target} row={row} />)}</tbody>
          </table>
        </div>
      )}
      {report && <p className="de-note">Measured: {report.measured}</p>}
      {canWrite && convertible && (
        <div className="x1-card de-form">
          <h3 style={{ margin: 0 }}>Convert</h3>
          {unproven && (
            <label>The replay did not prove this rule. Say why to go on anyway, or tune it first. The heat map still counts it unproven.
              <input className="de-text" value={accept} onChange={(e) => setAccept(e.target.value)} />
            </label>
          )}
          <details>
            <summary style={{ cursor: 'pointer', fontSize: 12.5 }}>Paste your own query for a target</summary>
            <div className="de-form" style={{ marginTop: 8 }}>
              <p className="de-note">Vigil&apos;s overlay stages a Splunk or an Elastic copy. Without pySigma, a pasted query is how a rule reaches shadow, and it stays labelled as pasted.</p>
              <label>Splunk search<textarea className="de-text mono" rows={3} spellCheck={false} data-testid="de-paste-splunk" value={splunk} onChange={(e) => setSplunk(e.target.value)} /></label>
              <label>Elastic Lucene query<textarea className="de-text mono" rows={3} spellCheck={false} value={elastic} onChange={(e) => setElastic(e.target.value)} /></label>
            </div>
          </details>
          <div className="x1-row">
            <button type="button" className="btn primary" disabled={busy} onClick={convert}>{rows.length ? 'Convert again' : 'Convert for every SIEM'}</button>
          </div>
        </div>
      )}
      {canWrite && proposal.state === 'converted' && (
        <StageAction label="Move to shadow" id={proposal.proposal_id} busy={busy} run={run} action={detectionsApi.shadow} then="shadow" requireReason={false}
          note="Saves the rule's copies into Vigil's overlay, at the shadow stage. It needs you signed in as a person." />
      )}
    </div>
  )
}

function StageAction({ label, id, busy, run, action, then, requireReason, note }: {
  label: string
  id: string
  busy: boolean
  run: StepProps['run']
  action: (id: string, reason: string) => Promise<Proposal>
  then: Step
  requireReason: boolean
  note: string
}) {
  const [reason, setReason] = useState('')
  return (
    <div className="x1-card de-form">
      <p className="de-note">{note}</p>
      <label>{requireReason ? 'Why it is ready' : 'Why (optional)'}<input className="de-text" value={reason} onChange={(e) => setReason(e.target.value)} /></label>
      <div className="x1-row">
        <button type="button" className="btn primary" disabled={busy || (requireReason && !reason.trim())} onClick={() => run(() => action(id, reason), then)}>{label}</button>
      </div>
    </div>
  )
}

function Stages({ proposal }: { proposal: Proposal }) {
  if (proposal.stages.length === 0) return null
  return (
    <div className="x1-card">
      <h3>Rollout stages, from detection_rule_stages</h3>
      <ol className="de-history">
        {proposal.stages.map((s, i) => (
          <li key={`${s.rule_id}-${i}`}>
            <span className="x1-ts">{when(s.at)}</span>
            <span><b>{s.stage}</b> · rule {s.rule_id} version {s.version} · {s.actor}{s.reason ? <span className="x1-muted"> · {s.reason}</span> : null}</span>
          </li>
        ))}
      </ol>
    </div>
  )
}

function ShadowReportCard({ report }: { report: ShadowReport | null }) {
  if (!report) return null
  if (!report.evaluated) return <Note>{report.reason}</Note>
  return (
    <div style={{ display: 'grid', gap: 10 }}>
      <div className="x1-grid3" data-testid="de-shadow-report">
        <Stat value={report.rows ?? 0} label={`rows stored since ${when(report.since)}`} />
        <Stat value={report.matches ?? 0} label="the rule would have matched" />
        <Stat value={report.matches_unclaimed ?? 0} label="of those are on rows no case claims" />
      </div>
      {report.rows === 0 && <Note>No events have arrived since shadow began, so this measures nothing yet.</Note>}
      <SampleTable title="Rows the rule would have matched" rows={report.samples ?? []} />
    </div>
  )
}

function useShadowReport(proposal: Proposal): ShadowReport | null {
  const [report, setReport] = useState<ShadowReport | null>(null)
  const reached = proposal.state === 'shadow'
  useEffect(() => {
    if (!reached) return
    detectionsApi.shadowReport(proposal.proposal_id).then(setReport).catch(() => setReport(null))
  }, [reached, proposal.proposal_id])
  return report
}

function ShadowStep({ proposal, canWrite, busy, run }: StepProps) {
  const report = useShadowReport(proposal)
  return (
    <div style={{ display: 'grid', gap: 12 }}>
      <Note>Shadow is a stage in Vigil&apos;s overlay, not a query running in your SIEM. Vigil measures it by running the rule over rows stored since it entered shadow.</Note>
      {proposal.state === 'converted' && canWrite && (
        <StageAction label="Move to shadow" id={proposal.proposal_id} busy={busy} run={run} action={detectionsApi.shadow} then="shadow" requireReason={false}
          note="Saves the rule's copies into Vigil's overlay, at the shadow stage. It needs you signed in as a person." />
      )}
      {!['converted', 'shadow', 'live'].includes(proposal.state) && <span className="x1-muted">A rule reaches shadow after it converts.</span>}
      <ShadowReportCard report={report} />
      <Stages proposal={proposal} />
    </div>
  )
}

function LiveStep({ proposal, canWrite, busy, run }: StepProps) {
  const report = useShadowReport(proposal)
  const live = proposal.latest.live
  return (
    <div style={{ display: 'grid', gap: 12 }}>
      <Note>Live never happens on its own. It records that a person approved this rule in Vigil. Vigil writes nothing to your SIEM, so loading and enabling it there stays with you. A staged rollout to a small group of hosts does not exist.</Note>
      {live && <div className="x1-card" data-testid="de-live">Promoted by <b>{live.actor}</b>, {when(live.at)}. {live.reason}</div>}
      {proposal.state === 'shadow' && <ShadowReportCard report={report} />}
      {proposal.state === 'shadow' && canWrite && (
        <StageAction label="Promote to live" id={proposal.proposal_id} busy={busy} run={run} action={detectionsApi.live} then="live" requireReason
          note="What shadow measured goes on the record with your name and reason. It needs you signed in as a person." />
      )}
      {!['shadow', 'live'].includes(proposal.state) && <span className="x1-muted">A rule reaches live from shadow.</span>}
      <Stages proposal={proposal} />
    </div>
  )
}
