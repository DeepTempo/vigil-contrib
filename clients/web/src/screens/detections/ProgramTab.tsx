import { useEffect, useState } from 'react'
import { useAuth } from '../../contexts/AuthContext'
import type { SettingsSectionKey } from '../../shared/types'
import {
  detectionsApi, type Coverage, type LogSourcesReport, type RedTeamRun, type RuleHealth, type RulesReport, type TechniqueCell, type TechniqueState, type ThreatModel,
} from '../../services/detectionsApi'
import { Stat, Tag, type TagTone } from '../shared/x1'
import { Empty, Failure, HEALTH, Note, TECHNIQUE_STATES, refusal, when } from './shared'

type Section = 'threat' | 'map' | 'rules' | 'redteam'

const SECTIONS: { id: Section; label: string; what: string }[] = [
  { id: 'threat', label: 'Threat model', what: 'What a person says matters, and the logs that exist' },
  { id: 'map', label: 'Heat map', what: 'Each technique and whether it is proven' },
  { id: 'rules', label: 'Existing rules', what: 'The inventory and what is broken in it' },
  { id: 'redteam', label: 'Red team', what: 'Attacks you ran, marked step by step' },
]

interface Props {
  coverage: Coverage | null
  coverageError: string | null
  reloadCoverage: () => void
  openProposal: (id: string) => void
  draftFor: (technique: string) => void
  goSettings: (section: SettingsSectionKey) => void
}

export default function ProgramTab({ coverage, coverageError, reloadCoverage, openProposal, draftFor, goSettings }: Props) {
  const [section, setSection] = useState<Section>('threat')
  return (
    <>
      <div className="x1-flow" role="tablist" aria-label="Program">
        {SECTIONS.map((s) => (
          <button key={s.id} type="button" role="tab" aria-selected={section === s.id} className={section === s.id ? 'on' : ''} onClick={() => setSection(s.id)}>
            <b>{s.label}</b>
            <span>{s.what}</span>
          </button>
        ))}
      </div>
      {section === 'threat' && <ThreatSection onSaved={reloadCoverage} onHeatMap={() => setSection('map')} />}
      {section === 'map' && (coverageError
        ? <Failure>{coverageError}</Failure>
        : <HeatMap coverage={coverage} openProposal={openProposal} draftFor={draftFor} goSettings={goSettings} />)}
      {section === 'rules' && <RulesSection openProposal={openProposal} goSettings={goSettings} reloadCoverage={reloadCoverage} />}
      {section === 'redteam' && <RedTeamSection draftFor={draftFor} />}
    </>
  )
}

const MODEL_FIELDS: { key: 'sector' | 'crown_jewels' | 'exposure' | 'advisories' | 'notes'; label: string; hint: string }[] = [
  { key: 'sector', label: 'Sector and region', hint: 'Who you are, and who tends to attack that' },
  { key: 'crown_jewels', label: 'Crown jewels', hint: 'What an attacker would come for' },
  { key: 'exposure', label: 'Exposure', hint: 'What faces the internet or a third party' },
  { key: 'advisories', label: 'Advisories', hint: 'Sector advisories you are tracking' },
  { key: 'notes', label: 'Notes', hint: 'Anything else that should shape the program' },
]

function ThreatSection({ onSaved, onHeatMap }: { onSaved: () => void; onHeatMap: () => void }) {
  const canWrite = useAuth().hasPermission('detections.write')
  const [model, setModel] = useState<ThreatModel | null>(null)
  const [priorities, setPriorities] = useState('')
  const [sources, setSources] = useState<LogSourcesReport | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    detectionsApi.threatModel().then((m) => { setModel(m); setPriorities(m.priority_techniques.join(', ')) })
      .catch((e) => setError(refusal(e, 'The threat model did not load.')))
    detectionsApi.logSources().then(setSources).catch((e) => setError(refusal(e, 'Log sources did not load.')))
  }, [])

  const save = async () => {
    if (!model) return
    setSaving(true)
    setError(null)
    try {
      const saved = await detectionsApi.saveThreatModel({
        ...model,
        priority_techniques: priorities.split(/[\s,]+/).map((t) => t.trim()).filter(Boolean),
      })
      setModel(saved)
      setPriorities(saved.priority_techniques.join(', '))
      onSaved()
    } catch (e) {
      setError(refusal(e, 'The threat model was not saved.'))
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="x1-grid2">
      <div className="x1-card de-form">
        <h3 style={{ margin: 0 }}>Threat model, in your words</h3>
        <p className="de-note">A person writes this. Vigil does not generate or score it. Priority techniques set the percentage at the top of this page.</p>
        {error && <Failure>{error}</Failure>}
        {model && MODEL_FIELDS.map((f) => (
          <label key={f.key}>
            {f.label}
            <textarea className="de-text" rows={2} placeholder={f.hint} value={model[f.key]} disabled={!canWrite} onChange={(e) => setModel({ ...model, [f.key]: e.target.value })} />
          </label>
        ))}
        {model && (
          <label>
            Priority ATT&amp;CK techniques
            <input className="de-text mono" placeholder="T1059.001, T1486" value={priorities} disabled={!canWrite} onChange={(e) => setPriorities(e.target.value)} />
          </label>
        )}
        <div className="x1-row">
          {canWrite && <button type="button" className="btn primary" disabled={!model || saving} onClick={save}>{saving ? 'Saving…' : 'Save the threat model'}</button>}
          {model?.updated_by && <span className="x1-muted" style={{ fontSize: 12 }}>Saved by {model.updated_by}, {when(model.updated_at)}</span>}
        </div>
      </div>
      <div className="x1-card" style={{ display: 'grid', gap: 10, alignContent: 'start' }}>
        <h3 style={{ margin: 0 }}>Log sources read from this install</h3>
        {!sources && !error && <span className="x1-muted">Reading…</span>}
        {sources && (
          <>
            <div className="x1-row">
              {sources.kinds.map((k) => (
                <Tag key={k.kind} tone={k.rows ? 'good' : k.configured ? 'fair' : 'poor'} title={k.rows ? `${k.rows} stored rows` : k.configured ? 'A source is configured, but log_events holds no rows' : 'No rows and no configured source'}>
                  {k.rows ? '✓' : k.configured ? '○' : '✕'} {k.kind}
                </Tag>
              ))}
            </div>
            <p className="de-note">{sources.kinds_basis} A blind spot needs data, not another rule.</p>
            {sources.total_rows === 0 && (
              <p className="de-note">log_events holds no rows. Replay and missing-field checks need events: ingest them on the Logs screen.</p>
            )}
            {sources.stored.length > 0 && (
              <div className="x1-table-wrap">
                <table className="x1-table">
                  <thead><tr><th>Source</th><th>Class</th><th className="num">Rows</th><th>Latest</th></tr></thead>
                  <tbody>
                    {sources.stored.map((s) => (
                      <tr key={`${s.source}/${s.event_class}`}><td>{s.source}</td><td>{s.event_class || 'Unclassified'}</td><td className="num">{s.rows}</td><td className="x1-ts">{when(s.last)}</td></tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            <h3 style={{ margin: '4px 0 0' }}>Federation sources</h3>
            {sources.configured.length === 0
              ? <p className="de-note">None configured. Connect a SIEM in Settings to read its alerts.</p>
              : sources.configured.map((c) => (
                <div key={c.source_id} className="x1-check">
                  <span className={c.enabled && !c.last_error ? 'ok' : 'no'}>{c.enabled && !c.last_error ? '✓' : '✕'}</span>
                  <span>{c.source_id}<span className="x1-muted"> · {c.last_error ? c.last_error : c.last_success_at ? `read ${when(c.last_success_at)}` : c.enabled ? 'not read yet' : 'off'}</span></span>
                </div>
              ))}
            <div className="x1-row"><button type="button" className="btn ghost" onClick={onHeatMap}>See the heat map</button></div>
          </>
        )}
      </div>
    </div>
  )
}

function HeatMap({ coverage, openProposal, draftFor, goSettings }: Pick<Props, 'coverage' | 'openProposal' | 'draftFor' | 'goSettings'>) {
  const canWrite = useAuth().hasPermission('detections.write')
  const [selected, setSelected] = useState<string | null>(null)
  if (!coverage) return <span className="x1-muted">Reading the heat map…</span>
  if (coverage.techniques.length === 0) {
    return (
      <Empty title="No technique to show yet">
        The map reads rule inventory, stored alerts and your priorities, and all three are empty. Add a rule source in{' '}
        <button type="button" className="x1-link" onClick={() => goSettings('data')}>Settings</button>, or name priority techniques in the threat model.
      </Empty>
    )
  }
  const cell = coverage.techniques.find((t) => t.technique === selected) ?? null
  return (
    <div className="x1-card" style={{ display: 'grid', gap: 12 }}>
      <div className="x1-row" style={{ justifyContent: 'space-between' }}>
        <div className="x1-legend">
          {(Object.keys(TECHNIQUE_STATES) as TechniqueState[]).map((s) => (
            <span key={s}><span className={`de-swatch ${s}`} />{TECHNIQUE_STATES[s]} · {coverage.summary[s]}</span>
          ))}
        </div>
        <span className="x1-muted" style={{ fontSize: 12 }}>{coverage.rule_total} active rules in the inventory</span>
      </div>
      <div className="de-matrix-wrap">
        <div className="de-matrix" data-testid="de-matrix">
          {coverage.tactics.map((tactic) => (
            <div key={tactic} className="de-col">
              <h4>{tactic}</h4>
              {coverage.techniques.filter((t) => t.tactic === tactic).map((t) => (
                <button key={t.technique} type="button" className={`de-cell ${t.state}${t.priority ? ' priority' : ''}${selected === t.technique ? ' on' : ''}`} aria-pressed={selected === t.technique} onClick={() => setSelected(t.technique)}>
                  <b>{t.name}</b>
                  <span className="x1-mono">{t.technique}{t.rules ? ` · ${t.rules} rule${t.rules === 1 ? '' : 's'}` : ''}</span>
                </button>
              ))}
            </div>
          ))}
        </div>
      </div>
      {cell && <CellDetail cell={cell} canWrite={canWrite} openProposal={openProposal} draftFor={draftFor} />}
      <p className="de-note">
        Only a replay on stored events turns a cell green, and a change to the rule turns it back. Technique names come from a short built-in list, so an unlisted one shows its id, and an unlisted technique with no single declared tactic sits under Unmapped.
      </p>
    </div>
  )
}

function CellDetail({ cell, canWrite, openProposal, draftFor }: { cell: TechniqueCell; canWrite: boolean; openProposal: (id: string) => void; draftFor: (technique: string) => void }) {
  return (
    <div className="x1-card" style={{ display: 'grid', gap: 8 }} data-testid="de-cell-detail">
      <div className="x1-row" style={{ justifyContent: 'space-between' }}>
        <b style={{ color: 'var(--tx0)' }}>{cell.name} <span className="x1-mono x1-muted">{cell.technique}</span></b>
        <Tag tone={cell.state === 'validated' ? 'good' : cell.state === 'unproven' ? 'fair' : 'poor'}>{TECHNIQUE_STATES[cell.state]}</Tag>
      </div>
      <span className="x1-muted" style={{ fontSize: 12.5 }}>
        {cell.rules} active rule{cell.rules === 1 ? '' : 's'}. Seen {cell.seen} time{cell.seen === 1 ? '' : 's'} in stored alerts and logs.{cell.priority ? ' A priority in your threat model.' : ''}
      </span>
      {cell.proof && <span style={{ fontSize: 12.5 }}>Replay matched {cell.proof.hits} of {cell.proof.attack_rows} attack rows and none of {cell.proof.benign_rows} other rows, {when(cell.proof.at)}.</span>}
      {cell.rules_failing_checks > 0 && <span style={{ fontSize: 12.5 }}>{cell.rules_failing_checks} of its SIEM rules fail a run or data check, so this may need data before another rule. See Existing rules.</span>}
      <div className="x1-row">
        {cell.proposal
          ? <button type="button" className="btn ghost" onClick={() => openProposal(cell.proposal!.proposal_id)}>Open the {cell.proposal.state} proposal</button>
          : canWrite && <button type="button" className="btn primary" onClick={() => draftFor(cell.technique)}>Draft a rule for this</button>}
      </div>
    </div>
  )
}

function RulesSection({ openProposal, goSettings, reloadCoverage }: { openProposal: (id: string) => void; goSettings: Props['goSettings']; reloadCoverage: () => void }) {
  const canWrite = useAuth().hasPermission('detections.write')
  const [report, setReport] = useState<RulesReport | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [filter, setFilter] = useState<RuleHealth | 'all'>('all')

  useEffect(() => {
    detectionsApi.rules().then(setReport).catch((e) => setError(refusal(e, 'Rule health did not load.')))
  }, [])

  const prove = async (ruleId: number) => {
    setError(null)
    try {
      const proposal = await detectionsApi.fromRule(ruleId)
      reloadCoverage()
      openProposal(proposal.proposal_id)
    } catch (e) {
      setError(refusal(e, 'That rule could not start a proposal.'))
    }
  }

  if (error && !report) return <Failure>{error}</Failure>
  if (!report) return <span className="x1-muted">Reading the inventory…</span>
  if (report.total === 0) {
    return (
      <Empty title="The inventory is empty">
        Add a rule repository in <button type="button" className="x1-link" onClick={() => goSettings('data')}>Settings</button>, or enable the Elastic or Wazuh integration. Vigil reads rules from those and tags them from what they declare. Splunk saved searches are not read yet.
      </Empty>
    )
  }
  const rows = filter === 'all' ? report.rules : report.rules.filter((r) => r.health === filter)
  return (
    <div className="de-split">
      <div style={{ display: 'grid', gap: 10 }}>
        <Stat value={report.total} label="rules in the inventory" />
        <Stat value={report.mapped} label="declare an ATT&CK technique" />
        <Stat value={report.validated} label="validated by replay" />
        <div className="x1-card x1-saved">
          <h3 style={{ marginBottom: 4 }}>Health</h3>
          <button type="button" className={filter === 'all' ? 'on' : ''} onClick={() => setFilter('all')}>All · {report.total}</button>
          {(Object.keys(HEALTH) as RuleHealth[]).map((h) => (
            <button key={h} type="button" className={filter === h ? 'on' : ''} onClick={() => setFilter(h)}>{HEALTH[h].label} · {report.counts[h]}</button>
          ))}
        </div>
      </div>
      <div style={{ display: 'grid', gap: 10, minWidth: 0 }}>
        {error && <Failure>{error}</Failure>}
        <div className="x1-table-wrap">
          <table className="x1-table" data-testid="de-rules">
            <thead><tr><th>Rule</th><th>Technique</th><th>Where</th><th>Health</th><th>Why</th><th /></tr></thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.rule_id}>
                  <td style={{ color: 'var(--tx0)' }}>{r.name}{r.validated && <> <Tag tone="good">Validated</Tag></>}</td>
                  <td className="x1-mono">{r.techniques.join(', ') || 'None declared'}</td>
                  <td>{r.tool} · {r.language}</td>
                  <td><Tag tone={HEALTH[r.health].tone}>{HEALTH[r.health].label}</Tag></td>
                  <td>{r.why}</td>
                  <td>{canWrite && r.language === 'sigma' && !r.validated && <button type="button" className="x1-link" style={{ whiteSpace: 'nowrap' }} onClick={() => prove(r.rule_id)}>Prove it</button>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {report.total > report.rules.length && <p className="de-note">Showing the worst {report.rules.length} of {report.total}. The counts cover them all.</p>}
        <p className="de-note">{report.limits}</p>
      </div>
    </div>
  )
}

const VERDICT: Record<string, { label: string; tone: TagTone | undefined }> = {
  rule: { label: 'Rule caught it', tone: 'good' },
  loglm: { label: 'LogLM caught it', tone: 'ac' },
  both: { label: 'Both caught it', tone: 'good' },
  missed: { label: 'Missed', tone: 'poor' },
}

/** A JSON array, an object with `events` or `steps`, or one JSON object per line. */
function parseRunFile(text: string): unknown[] {
  const trimmed = text.trim()
  try {
    const doc = JSON.parse(trimmed)
    if (Array.isArray(doc)) return doc
    if (Array.isArray(doc?.events)) return doc.events
    if (Array.isArray(doc?.steps)) return doc.steps
    return [doc]
  } catch {
    return trimmed.split('\n').filter((line) => line.trim()).map((line) => JSON.parse(line))
  }
}

function RedTeamSection({ draftFor }: { draftFor: (technique: string) => void }) {
  const canWrite = useAuth().hasPermission('detections.write')
  const [runs, setRuns] = useState<RedTeamRun[] | null>(null)
  const [shown, setShown] = useState(0)
  const [name, setName] = useState('')
  const [windowMinutes, setWindowMinutes] = useState(15)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    detectionsApi.redTeamRuns().then(setRuns).catch((e) => setError(refusal(e, 'Past runs did not load.')))
  }, [])

  const upload = async (file: File) => {
    setBusy(true)
    setError(null)
    try {
      const run = await detectionsApi.uploadRun({ name: name || file.name, events: parseRunFile(await file.text()), window_minutes: windowMinutes })
      setRuns((old) => [run, ...(old ?? [])])
      setShown(0)
    } catch (e) {
      setError(refusal(e, 'That file could not be read as a run. It needs JSON or one JSON object per line.'))
    } finally {
      setBusy(false)
    }
  }

  const run = runs?.[shown]
  return (
    <div className="x1-grid2">
      <div className="x1-card de-form">
        <h3 style={{ margin: 0 }}>Upload a run</h3>
        <Note>Vigil does not run Atomic Red Team or any attack. Run it yourself in a range built from this install&apos;s profile, never on the live estate, then upload what it did.</Note>
        <p className="de-note">
          Each event needs a time and a host, address or user, or it cannot be joined to a finding. Vigil reads technique_id, hostname, user, src_ip, started_at and ended_at, and the columns of an Invoke-AtomicRedTeam execution log.
        </p>
        {canWrite && (
          <>
            <label>Name<input className="de-text" value={name} placeholder="Quarterly range run" onChange={(e) => setName(e.target.value)} /></label>
            <label>Minutes after a step to look for a finding, when it has no end time
              <input className="de-text" type="number" min={1} max={1440} value={windowMinutes} onChange={(e) => setWindowMinutes(Number(e.target.value) || 15)} />
            </label>
            <label>Run events (JSON or JSONL)
              <input type="file" accept=".json,.jsonl,.ndjson,application/json" data-testid="de-run-file" disabled={busy} onChange={(e) => { const f = e.target.files?.[0]; if (f) void upload(f); e.target.value = '' }} />
            </label>
          </>
        )}
        {busy && <span className="x1-muted">Marking each step…</span>}
        {error && <Failure>{error}</Failure>}
        {runs && runs.length > 1 && (
          <div className="x1-saved">
            <h3 style={{ marginBottom: 4 }}>Past runs</h3>
            {runs.map((r, i) => (
              <button key={`${r.uploaded_at}-${i}`} type="button" className={i === shown ? 'on' : ''} onClick={() => setShown(i)}>{r.name} · {when(r.uploaded_at)}</button>
            ))}
          </div>
        )}
      </div>
      <div style={{ display: 'grid', gap: 10, alignContent: 'start', minWidth: 0 }}>
        {!run && <Empty title="No run uploaded yet">Upload a run&apos;s events to see which steps a rule caught, which LogLM caught, and which nothing caught. A missed step can start a draft.</Empty>}
        {run && (
          <>
            <div className="x1-card">
              <h3>{run.name}</h3>
              <div className="x1-row">
                {(['rule', 'loglm', 'both', 'missed'] as const).map((v) => <Tag key={v} tone={VERDICT[v].tone}>{VERDICT[v].label}: {run.counts[v]}</Tag>)}
              </div>
              <p className="de-note" style={{ marginTop: 8 }}>Uploaded by {run.uploaded_by}, {when(run.uploaded_at)}. Marked against findings Vigil holds.</p>
            </div>
            <div className="x1-table-wrap">
              <table className="x1-table" data-testid="de-run-steps">
                <thead><tr><th>Step</th><th>Technique</th><th>Host</th><th>Result</th><th /></tr></thead>
                <tbody>
                  {run.steps.map((s) => (
                    <tr key={s.index} className={s.verdict === 'missed' ? 'hit' : ''}>
                      <td style={{ color: 'var(--tx0)' }}>{s.name || s.id || `Step ${s.index + 1}`}</td>
                      <td className="x1-mono">{s.technique_id || 'Not given'}</td>
                      <td>{s.hostname || s.user || 'Not given'}</td>
                      <td>
                        <Tag tone={VERDICT[s.verdict].tone}>{VERDICT[s.verdict].label}</Tag>
                        {s.could_not_correlate && <div className="x1-muted" style={{ fontSize: 12 }}>This step has no time or entity, so nothing could be joined to it.</div>}
                        {s.citations.map((c) => <div key={c.finding_id} className="x1-muted" style={{ fontSize: 12 }}>{c.rule_name || c.data_source} · {c.finding_id}</div>)}
                      </td>
                      <td>{canWrite && s.verdict === 'missed' && s.technique_id && <button type="button" className="x1-link" style={{ whiteSpace: 'nowrap' }} onClick={() => draftFor(s.technique_id!)}>Draft a rule</button>}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        )}
      </div>
    </div>
  )
}
