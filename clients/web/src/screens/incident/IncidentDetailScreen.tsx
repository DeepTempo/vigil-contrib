import { Fragment, useCallback, useEffect, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { approvalsApi } from '../../services/api'
import {
  incidentsApi,
  type Evidence,
  type IncidentAction,
  type IncidentList,
  type Step,
  type Story,
} from '../../services/incidentsApi'
import { errorText } from '../../shared/errorText'
import { EmptyState } from '../../shared/ui'
import { usePageSnapshot } from '../../shell/pageSnapshot'
import type { ConsoleScreenProps } from '../../shared/types'
import FindingPopup from '../dashboard/FindingPopup'
import { SevDot, SourceChip, Tag, type TagTone } from '../shared/x1'

const POLL_MS = 10_000
const ENTITIES_SHOWN = 30
const REPORT_SHOWN = 900

const STATUS_TAGS: Record<string, { label: string; tone: TagTone }> = {
  approved: { label: 'Approved', tone: 'ac' },
  executed: { label: 'Executed', tone: 'good' },
  failed: { label: 'Failed', tone: 'poor' },
  rejected: { label: 'Rejected', tone: 'fair' },
}

const VERDICT_TONES: Record<Story['verdict']['value'], TagTone | undefined> = {
  true_positive: 'poor',
  false_positive: 'good',
  undetermined: undefined,
}

const utc = (iso: string, withDate = false) => {
  const text = new Date(iso).toISOString()
  return withDate ? `${text.slice(0, 10)} ${text.slice(11, 16)} UTC` : text.slice(11, 16)
}
const short = (text: string, length = 44) => (text.length > length ? `${text.slice(0, length - 1)}…` : text)
const plural = (n: number, word: string) => `${n} ${word}${n === 1 ? '' : 's'}`
const stepsSpanDays = (steps: Step[]) => new Set(steps.map((s) => s.at.slice(0, 10))).size > 1
const waitsForExecutor = (a: IncidentAction) => a.status === 'approved' && (a.effect === 'cloudflare' || a.effect === 'no_executor')
const whyHeading = (story: Story) => (story.verdict.value === 'true_positive' ? 'Why this is called a true positive' : 'What ties these alerts together')
const detectionLink = (caseId: string, findingId: string) =>
  `/detections?case=${encodeURIComponent(caseId)}&finding=${encodeURIComponent(findingId)}`

function ModelWords({ children }: { children: string }) {
  const [all, setAll] = useState(false)
  const cut = children.length > REPORT_SHOWN && !all
  return (
    <div style={{ display: 'grid', gap: 6 }}>
      <div className="x1-row"><Tag tone="vio">The model’s words</Tag><span className="x1-muted" style={{ fontSize: 12 }}>Written by a model during a run. Vigil did not derive this text.</span></div>
      <p style={{ margin: 0, color: 'var(--tx1)', whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{cut ? `${children.slice(0, REPORT_SHOWN)}…` : children}</p>
      {children.length > REPORT_SHOWN && (
        <button type="button" className="x1-link" aria-expanded={all} onClick={() => setAll(!all)}>{all ? 'Show less' : 'Show all of it'}</button>
      )}
    </div>
  )
}

function EvidenceLinks({ evidence, openFinding, openAction }: { evidence: Evidence[]; openFinding: (id: string) => void; openAction: (id: string) => void }) {
  return (
    <>
      {evidence.map((link) => {
        const label = `[${short(link.label)}]`
        if (link.kind === 'log_search') return <Fragment key={link.kind + link.ref}> <Link className="x1-link" to={`/logs?case=${encodeURIComponent(link.ref)}`}>{label}</Link></Fragment>
        const open = link.kind === 'finding' ? openFinding : openAction
        return <Fragment key={link.kind + link.ref}> <button type="button" className="x1-link" title={link.label} onClick={() => open(link.ref)}>{label}</button></Fragment>
      })}
    </>
  )
}

function StepRow({ step, story, withDate, openFinding }: { step: Step; story: Story; withDate: boolean; openFinding: (id: string) => void }) {
  const tech = step.technique
  return (
    <div className="x1-step">
      <span className="t">{withDate ? `${step.at.slice(5, 10)} ` : ''}{utc(step.at)}</span>
      <span className={`dot${step.coverage === 'no_rule' ? ' miss' : ''}`} aria-hidden="true" />
      <div style={{ minWidth: 0 }}>
        <div className="l"><button type="button" className="x1-link" style={{ color: 'var(--tx0)' }} onClick={() => openFinding(step.finding_id)}>{step.label}</button></div>
        <div className="m x1-row" style={{ gap: 6 }}>
          {step.severity && <><SevDot level={step.severity} /><span>{step.severity}</span><span>·</span></>}
          {tech && <span title={tech.tactic ?? undefined}>{tech.tactic ? `${tech.tactic} · ` : ''}<span className="x1-mono">{tech.id}</span>{tech.name !== tech.id ? ` ${tech.name}` : ''} ·</span>}
          {!tech && step.labels.length > 0 && <span>{step.labels.join(', ')} ·</span>}
          <SourceChip source={step.source} />
          {step.anomaly_score !== null && <span>· LogLM <span className="x1-mono">{step.anomaly_score.toFixed(2)}</span></span>}
          {(step.coverage === 'rule_fired' || step.coverage === 'rule_declared') && <span title={step.coverage_note}>· rule: {step.caught_by}</span>}
        </div>
        {step.coverage === 'no_rule' && (
          <div className="m">
            {step.coverage_note}{' '}
            <Link className="x1-link" style={{ color: 'var(--poor)' }} to={detectionLink(story.case_id, step.finding_id)}>Draft a detection</Link>
          </div>
        )}
        {step.coverage === 'unknown' && <div className="m">{step.coverage_note}</div>}
      </div>
    </div>
  )
}

function ActionRow({
  action,
  canDecide,
  open,
  toggle,
  busy,
  answer,
  approve,
  openFinding,
}: {
  action: IncidentAction
  canDecide: boolean
  open: boolean
  toggle: () => void
  busy: boolean
  answer: { ok: boolean; text: string } | undefined
  approve: () => void
  openFinding: (id: string) => void
}) {
  const tag = STATUS_TAGS[action.status]
  return (
    <Fragment>
      <div className="x1-action" id={`action-${action.action_id}`}>
        <div style={{ minWidth: 0 }}>
          <div style={{ color: 'var(--tx0)' }}>{action.title}</div>
          <div className="x1-muted" style={{ fontSize: 12 }}>
            <span className="x1-mono">{action.action_type}</span> on <span className="x1-mono">{action.target}</span> ·{' '}
            <button type="button" className="x1-link" aria-expanded={open} onClick={toggle}>{open ? 'hide' : 'details'}</button>
          </div>
        </div>
        {action.status === 'pending' ? (
          canDecide ? (
            <button type="button" className="btn ghost" disabled={busy} onClick={approve}>{busy ? 'Approving…' : 'Approve'}</button>
          ) : (
            <Tag tone="fair" title="Deciding takes the ai_decisions.approve permission">Waiting for an approver</Tag>
          )
        ) : tag ? (
          <Tag tone={tag.tone}>{tag.label}</Tag>
        ) : (
          <Tag>{action.status}</Tag>
        )}
      </div>
      {action.status === 'pending' && (
        <div className="x1-muted" style={{ fontSize: 12.5, paddingBottom: 8 }}>
          <b style={{ color: 'var(--tx1)', fontWeight: 600 }}>What approving does:</b> {action.does}
          {action.missing && <div style={{ color: 'var(--fair)', marginTop: 2 }}>{action.missing}</div>}
        </div>
      )}
      {action.status !== 'pending' && (
        <div className="x1-muted" style={{ fontSize: 12.5, paddingBottom: 8 }}>
          {action.approved_by && action.approved_at && <div>Approved by {action.approved_by} at {utc(action.approved_at, true)}.</div>}
          {action.rejection_reason && <div>Rejected: {action.rejection_reason}</div>}
          {waitsForExecutor(action) && <div>Waiting for the daemon’s executor. This row stays here if the daemon is not running.</div>}
          {action.effect === 'record_only' && action.status === 'approved' && <div>The decision is recorded. Nothing ran. {action.missing}</div>}
          {action.effect === 'run_resumes' && action.status === 'approved' && <div>The decision went to workflow run {action.workflow_run_id}.</div>}
          {action.result && <div>The executor reported: {action.result}</div>}
          {action.status === 'failed' && action.missing && <div>{action.missing}</div>}
        </div>
      )}
      {answer && <div className={`x1-card ${answer.ok ? 'x1-note' : 'x1-error'}`} role="status" style={{ marginBottom: 8 }}>{answer.text}</div>}
      {open && (
        <div className="x1-route">
          <dl className="x1-kv">
            <dt>Why</dt><dd>{action.reason || action.description}</dd>
            <dt>Proposed by</dt><dd>{action.created_by} at {utc(action.created_at, true)}</dd>
            <dt>Confidence</dt><dd className="x1-mono">{action.confidence.toFixed(2)}</dd>
            <dt>Reversibility</dt><dd>{action.reversibility}</dd>
            <dt>Approving does</dt><dd>{action.does}</dd>
            {action.evidence.length > 0 && <><dt>Evidence</dt><dd><EvidenceLinks evidence={action.evidence} openFinding={openFinding} openAction={() => {}} /></dd></>}
          </dl>
        </div>
      )}
    </Fragment>
  )
}

function storySnapshot(story: Story): string {
  return [
    `Incident ${story.case_id}: ${story.title}. Priority ${story.priority}, status ${story.status}. ${story.verdict.label}: ${story.verdict.basis}`,
    `${story.alerts} alerts from ${story.sources.map((s) => s.source).join(', ')}.`,
    'Steps (time UTC | step | technique | source | rule):',
    ...story.steps.map((s) => [utc(s.at, true), s.label, s.technique?.id ?? '-', s.source, s.caught_by ?? s.coverage].join(' | ')),
    'Reasons:',
    ...story.reasons.map((r) => `- ${r.text}`),
    'Actions:',
    ...story.actions.map((a) => `- ${a.title} (${a.status}): ${a.does}`),
    `Entities: ${story.entities.slice(0, ENTITIES_SHOWN).map((e) => `${e.kind} ${e.value}`).join(', ')}.`,
  ].join('\n')
}

function StoryView({ story, reload, openChat, openCase }: { story: Story; reload: () => void } & Pick<ConsoleScreenProps, 'openChat' | 'openCase'>) {
  const [popup, setPopup] = useState<string | null>(null)
  const [open, setOpen] = useState<string | null>(null)
  const [busy, setBusy] = useState<string | null>(null)
  const [answers, setAnswers] = useState<Record<string, { ok: boolean; text: string }>>({})
  usePageSnapshot('incident', storySnapshot(story))

  const waiting = story.actions.some(waitsForExecutor)
  useEffect(() => {
    if (!waiting) return
    const timer = window.setInterval(reload, POLL_MS)
    return () => window.clearInterval(timer)
  }, [waiting, reload])

  const approve = async (action: IncidentAction) => {
    setBusy(action.action_id)
    try {
      const res = await approvalsApi.approve(action.action_id)
      const data = res.data as { action: { status: string; approved_by?: string | null }; resume_result: { success?: boolean; status?: string; error?: string } | null }
      const resumed = data.resume_result
      const text = [
        `The approvals route answered: ${data.action.status}, by ${data.action.approved_by ?? 'you'}.`,
        resumed ? (resumed.success ? `Workflow run ${action.workflow_run_id}: ${resumed.status}.` : `Workflow run ${action.workflow_run_id} did not resume: ${resumed.error}.`) : null,
      ].filter(Boolean).join(' ')
      setAnswers((all) => ({ ...all, [action.action_id]: { ok: resumed?.success !== false, text } }))
    } catch (err) {
      setAnswers((all) => ({ ...all, [action.action_id]: { ok: false, text: `Not approved. ${errorText(err, 'The approvals route refused.')}` } }))
    } finally {
      setBusy(null)
      reload()
    }
  }
  const openAction = (id: string) => {
    setOpen(id)
    document.getElementById(`action-${id}`)?.scrollIntoView({ block: 'center' })
  }

  const here = encodeURIComponent(story.case_id)
  const withDate = stepsSpanDays(story.steps)
  const hasLogs = story.log_events > 0
  const firstGap = story.unmatched_steps[0]
  const verdictTone = VERDICT_TONES[story.verdict.value]

  return (
    <div className="x1">
      <div className="x1-card" style={{ display: 'grid', gap: 10 }}>
        <div className="x1-row" style={{ justifyContent: 'space-between' }}>
          <div className="x1-row" style={{ minWidth: 0 }}>
            <SevDot level={story.priority} />
            <h2 style={{ overflowWrap: 'anywhere' }}>{story.case_id} · {story.title}</h2>
          </div>
          <div className="x1-row">
            <Tag tone={verdictTone} title={story.verdict.basis}>{story.verdict.label}</Tag>
            <Tag>{story.status}</Tag>
            <Tag>Opened {utc(story.opened_at, true)}</Tag>
          </div>
        </div>
        {story.summary && <p style={{ margin: 0, color: 'var(--tx1)', maxWidth: '90ch', whiteSpace: 'pre-wrap' }}>{story.summary}</p>}
        <div className="x1-row">
          {story.sources.map(({ source, alerts }) =>
            hasLogs ? (
              <Link key={source} className="x1-chipbtn" to={`/logs?case=${here}`} title="Open this case's events in Logs">
                <SourceChip source={source} /> <span className="n">{alerts}</span>
              </Link>
            ) : (
              <span key={source} className="x1-chipbtn" style={{ cursor: 'default' }} title={plural(alerts, 'alert')}>
                <SourceChip source={source} /> <span className="n">{alerts}</span>
              </span>
            ),
          )}
          <button type="button" className="btn ghost" onClick={() => openCase(story.case_id)}>Open the case</button>
        </div>
        <div className="x1-muted" style={{ fontSize: 12.5 }}>
          {story.verdict.basis}
        </div>
        {story.verdict.model_words && <ModelWords>{story.verdict.model_words}</ModelWords>}
      </div>

      <div className="x1-grid2">
        <div className="x1-card" style={{ alignSelf: 'start' }}>
          <h3>What happened</h3>
          <div className="x1-steps">
            {story.steps.map((step) => (
              <StepRow key={step.finding_id} step={step} story={story} withDate={withDate} openFinding={setPopup} />
            ))}
          </div>
          {story.rules_loaded === 0 && story.unmatched_steps.length > 0 && (
            <div className="x1-card x1-note" style={{ marginTop: 10 }}>The rule inventory is empty, so nothing here can be matched to a rule. Rules appear under Detections once a source of rules is synced.</div>
          )}
        </div>
        <div className="x1" style={{ gap: 16 }}>
          <div className="x1-card">
            <h3>{whyHeading(story)}</h3>
            {story.reasons.length > 0 ? (
              <ol className="x1-reasons">
                {story.reasons.map((reason) => (
                  <li key={reason.kind + reason.text}>
                    {reason.text}
                    <EvidenceLinks evidence={reason.evidence} openFinding={setPopup} openAction={openAction} />
                  </li>
                ))}
              </ol>
            ) : (
              <p className="x1-muted" style={{ margin: 0 }}>Vigil has no stored evidence that ties these alerts together: they name no common entity, come from one source, and no run or person has concluded anything. Someone put them on one case.</p>
            )}
          </div>
          {story.report && (
            <div className="x1-card">
              <h3>What the investigation wrote</h3>
              <ModelWords>{story.report.text}</ModelWords>
              <div className="x1-muted" style={{ fontSize: 12, marginTop: 6 }}>From {story.report.origin === 'workflow_run' ? 'workflow run' : 'investigation'} <span className="x1-mono">{story.report.ref}</span>{story.report.at ? ` at ${utc(story.report.at, true)}` : ''}.</div>
            </div>
          )}
          <div className="x1-card">
            <h3>Next actions</h3>
            {!story.viewer.can_read_approvals && <p className="x1-muted" style={{ margin: 0 }}>Reading this case’s proposed actions takes the ai_decisions.read permission, which your role does not hold.</p>}
            {story.viewer.can_read_approvals && story.actions.length === 0 && (
              <p className="x1-muted" style={{ margin: 0 }}>No run or person has proposed an action on this case. A proposal appears here when an investigation files one for approval.</p>
            )}
            {story.actions.map((action) => (
              <ActionRow
                key={action.action_id}
                action={action}
                canDecide={story.viewer.can_decide}
                open={open === action.action_id}
                toggle={() => setOpen(open === action.action_id ? null : action.action_id)}
                busy={busy === action.action_id}
                answer={answers[action.action_id]}
                approve={() => void approve(action)}
                openFinding={setPopup}
              />
            ))}
            {firstGap && (
              <div className="x1-action">
                <div>
                  <div style={{ color: 'var(--tx0)' }}>Draft a detection for {short(firstGap.label, 60)}</div>
                  <div className="x1-muted" style={{ fontSize: 12 }}>{plural(story.unmatched_steps.length, 'step')} without a rule behind {story.unmatched_steps.length === 1 ? 'it' : 'them'}.</div>
                </div>
                <Link className="btn primary" to={detectionLink(story.case_id, firstGap.finding_id)}>Draft detection</Link>
              </div>
            )}
            {story.viewer.can_read_approvals && story.actions.length > 0 && (
              <p className="x1-muted" style={{ fontSize: 12, margin: '8px 0 0' }}>
                This install has no relay inside your network. An approval does only what its row says, and Vigil shows the result it actually got.
              </p>
            )}
          </div>
        </div>
      </div>

      <div className="x1-grid2">
        <div className="x1-card">
          <h3>Entities</h3>
          {story.entities.length === 0 && <p className="x1-muted" style={{ margin: 0 }}>These alerts name no host, user, address, domain, URL or hash.</p>}
          <div className="x1-row">
            {story.entities.slice(0, ENTITIES_SHOWN).map((entity) => {
              const inner = <>{entity.kind} {entity.value} <span className="n">{entity.finding_ids.length}</span></>
              const key = entity.kind + entity.value
              const title = `Named by ${plural(entity.finding_ids.length, 'alert')}`
              if (!hasLogs) return <span key={key} className="x1-chipbtn" style={{ cursor: 'default' }} title={title}>{inner}</span>
              const target = entity.kind === 'host' || entity.kind === 'ip' ? `/graph?case=${here}` : `/logs?case=${here}`
              return <Link key={key} className="x1-chipbtn" to={target} title={title}>{inner}</Link>
            })}
          </div>
          {story.entities.length > ENTITIES_SHOWN && <p className="x1-muted" style={{ fontSize: 12, margin: '8px 0 0' }}>And {story.entities.length - ENTITIES_SHOWN} more.</p>}
        </div>
        <div className="x1-card">
          <h3>Threat intel</h3>
          {story.intel.length === 0 && <p className="x1-muted" style={{ margin: 0 }}>No indicator on this case has a rating. A rating appears when a person, an agent or an enrichment records one on the case’s IOCs.</p>}
          <div className="x1-intel">
            {story.intel.map((item) => (
              <div key={item.kind + item.value} className="x1-action" style={{ alignItems: 'start' }}>
                <div>
                  <div style={{ color: 'var(--tx0)' }}>
                    <span className="x1-mono">{item.value}</span>{' '}
                    {item.threat_level && <Tag tone={item.threat_level === 'critical' || item.threat_level === 'high' ? 'poor' : 'fair'}>{item.threat_level}</Tag>}
                  </div>
                  <div className="x1-muted" style={{ fontSize: 12 }}>
                    {[item.kind, item.source ? `from ${item.source}` : null, item.reputation !== null ? `reputation ${item.reputation}` : null, item.context].filter(Boolean).join(' · ')}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="x1-card">
        <h3>Keep going</h3>
        <div className="x1-row">
          {hasLogs && <Link className="btn ghost" to={`/graph?case=${here}`}>Show the attack path on the entity graph</Link>}
          {hasLogs && <Link className="btn ghost" to={`/logs?case=${here}`}>See the {story.log_events} raw events</Link>}
          <button type="button" className="btn ghost" onClick={() => openChat(`Summarise incident ${story.case_id} in five sentences.`)}>Ask Vigil about this incident</button>
        </div>
        {!hasLogs && <p className="x1-muted" style={{ fontSize: 12.5, margin: '8px 0 0' }}>No stored log events are tied to this case, so Logs and the Entity graph have nothing to show for it yet. They fill in once events tied to this case are ingested.</p>}
      </div>

      <FindingPopup id={popup} onClose={() => setPopup(null)} onChanged={reload} />
    </div>
  )
}

function IncidentIndex({ go, openChat }: Pick<ConsoleScreenProps, 'go' | 'openChat'>) {
  const [list, setList] = useState<IncidentList | null>(null)
  const [failed, setFailed] = useState<string | null>(null)
  useEffect(() => {
    let gone = false
    incidentsApi.list({ status: 'all' }).then(
      (res) => { if (!gone) setList(res.data) },
      (err) => { if (!gone) setFailed(errorText(err, 'Could not read incidents')) },
    )
    return () => { gone = true }
  }, [])
  usePageSnapshot('incident', list ? `${list.total} incidents. ${list.items.map((i) => `${i.case_id}: ${i.title} (${i.status})`).join('; ')}` : '')
  if (failed) return <EmptyState error icon="alert" title="Couldn’t read incidents" body={failed} />
  if (!list) return <EmptyState loading icon="clock" title="Loading incidents…" />
  if (list.items.length === 0) {
    return (
      <EmptyState
        icon="alert"
        title="No incidents yet"
        body="An incident is a case with 2 or more alerts. One appears here when the daemon adds a matching alert to an open case, or when someone links a second alert to a case."
        primary={{ label: 'Open the triage queue', onClick: () => go('triage') }}
        secondary={{ label: 'Ask Vigil', onClick: () => openChat() }}
      />
    )
  }
  return (
    <div className="x1">
      <div className="x1-table-wrap">
        <table className="x1-table">
          <thead><tr><th>Incident</th><th>Alerts</th><th>Sources</th><th>Verdict</th><th>Status</th><th>Waiting for a person</th></tr></thead>
          <tbody>
            {list.items.map((row) => (
              <tr key={row.case_id}>
                <td><Link className="x1-link" to={`/incident?case=${encodeURIComponent(row.case_id)}`}>{row.case_id} · {row.title}</Link></td>
                <td className="x1-mono">{row.alerts}</td>
                <td>{row.sources.map((s) => s.source).join(', ')}</td>
                <td>{row.verdict.label}</td>
                <td>{row.status}</td>
                <td className="x1-mono">{row.pending_approvals ?? '-'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function IncidentCase({ caseId, openChat, openCase, go }: { caseId: string } & Pick<ConsoleScreenProps, 'openChat' | 'openCase' | 'go'>) {
  const [story, setStory] = useState<Story | null>(null)
  const [failed, setFailed] = useState<string | null>(null)
  const load = useCallback(() => {
    incidentsApi.get(caseId).then(
      (res) => { setStory(res.data); setFailed(null) },
      (err) => { setStory(null); setFailed(errorText(err, 'Could not read this incident')) },
    )
  }, [caseId])
  useEffect(() => {
    setStory(null)
    setFailed(null)
    load()
  }, [load])
  if (failed) {
    return <EmptyState icon="alert" title={`No incident at ${caseId}`} body={failed} primary={{ label: 'All incidents', onClick: () => go('incident', { search: '' }) }} secondary={{ label: 'Open the case', onClick: () => openCase(caseId) }} />
  }
  if (!story) return <EmptyState loading icon="clock" title="Loading the incident…" />
  return <StoryView story={story} reload={load} openChat={openChat} openCase={openCase} />
}

export default function IncidentDetailScreen({ go, openChat, openCase }: ConsoleScreenProps) {
  const [params] = useSearchParams()
  const caseId = params.get('case')
  if (caseId) return <IncidentCase key={caseId} caseId={caseId} go={go} openChat={openChat} openCase={openCase} />
  return <IncidentIndex go={go} openChat={openChat} />
}
