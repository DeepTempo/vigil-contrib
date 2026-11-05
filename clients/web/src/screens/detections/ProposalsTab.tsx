import { useCallback, useEffect, useRef, useState } from 'react'
import type { SetURLSearchParams } from 'react-router-dom'
import { useAuth } from '../../contexts/AuthContext'
import type { ConsoleScreenProps } from '../../shared/types'
import { detectionsApi, type Proposal, type ProposalRow, type ProposalState } from '../../services/detectionsApi'
import { Tag } from '../shared/x1'
import ProposalSteps from './ProposalSteps'
import { Empty, Failure, STATE_TONE, refusal, when } from './shared'

interface Props {
  params: URLSearchParams
  setParams: SetURLSearchParams
  onCount: (count: number) => void
  onMoved: () => void
  go: ConsoleScreenProps['go']
  openCase: ConsoleScreenProps['openCase']
}

export default function ProposalsTab({ params, setParams, onCount, onMoved, go, openCase }: Props) {
  const canWrite = useAuth().hasPermission('detections.write')
  const [rows, setRows] = useState<ProposalRow[] | null>(null)
  const [proposal, setProposal] = useState<Proposal | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [starting, setStarting] = useState(false)

  const selected = params.get('proposal')
  const caseId = params.get('case')
  const findingId = params.get('finding')
  const technique = params.get('technique')
  const fromUrl = Boolean(caseId || findingId)

  const reload = useCallback(() => {
    detectionsApi.listProposals().then((list) => { setRows(list); onCount(list.length) })
      .catch((e) => setError(refusal(e, 'Proposals did not load.')))
  }, [onCount])
  useEffect(reload, [reload])

  useEffect(() => {
    if (!selected) { setProposal(null); return }
    let stale = false
    detectionsApi.getProposal(selected)
      .then((p) => { if (!stale) { setProposal(p); setError(null) } })
      .catch((e) => { if (!stale) setError(refusal(e, 'That proposal did not load.')) })
    return () => { stale = true }
  }, [selected])

  const open = useCallback((p: Proposal) => {
    setProposal(p)
    setParams({ proposal: p.proposal_id }, { replace: true })
    reload()
    onMoved()
  }, [setParams, reload, onMoved])

  const drafting = useRef('')
  const draftWithModel = useCallback(async (body: { case_id?: string; finding_id?: string; technique?: string; notes?: string }) => {
    setStarting(true)
    setError(null)
    try {
      open(await detectionsApi.draft(body))
    } catch (e) {
      setError(refusal(e, 'The model did not write a draft. You can paste Sigma instead.'))
    } finally {
      setStarting(false)
    }
  }, [open])

  // Arriving from an incident's missed step starts its draft. The server hands back one already started.
  useEffect(() => {
    if (!fromUrl || !canWrite) return
    const key = `${caseId}/${findingId}`
    if (drafting.current === key) return
    drafting.current = key
    void draftWithModel({ case_id: caseId ?? undefined, finding_id: findingId ?? undefined })
  }, [fromUrl, canWrite, caseId, findingId, draftWithModel])

  const applied = (next: Proposal) => {
    setProposal(next)
    reload()
    onMoved()
  }

  return (
    <div className="de-split">
      <div style={{ display: 'grid', gap: 10 }}>
        {canWrite && (
          <button type="button" className="btn primary" onClick={() => setParams({ tab: 'proposals' })}>New proposal</button>
        )}
        {rows && rows.length > 0 && (
          <div className="de-list" data-testid="de-proposals">
            {rows.map((row) => (
              <button key={row.proposal_id} type="button" className={row.proposal_id === selected ? 'on' : ''} onClick={() => setParams({ proposal: row.proposal_id })}>
                <b>{row.title}</b>
                <span className="x1-row" style={{ gap: 6 }}>
                  <Tag tone={STATE_TONE[row.state as ProposalState]}>{row.state}</Tag>
                  {row.technique && <span className="x1-mono">{row.technique}</span>}
                </span>
                <span className="x1-muted" style={{ fontSize: 11.5 }}>
                  {row.replay?.evaluated ? `${row.replay.hits}/${row.replay.attack_rows} hits, ${row.replay.false_positives}/${row.replay.benign_rows} false · ` : ''}{row.created_by}, {when(row.created_at)}
                </span>
              </button>
            ))}
          </div>
        )}
        {rows && rows.length === 0 && <p className="de-note">No proposals yet.</p>}
      </div>
      <div style={{ display: 'grid', gap: 12, minWidth: 0, alignContent: 'start' }}>
        {error && <Failure>{error}</Failure>}
        {starting && <div className="x1-card x1-muted">The model is drafting from that step. Tools check whatever it writes.</div>}
        {proposal
          ? <ProposalSteps proposal={proposal} canWrite={canWrite} applied={applied} go={go} openCase={openCase} />
          : !selected && !starting && (canWrite
            ? <NewProposal caseId={caseId} findingId={findingId} technique={technique} draftWithModel={draftWithModel} onPasted={open} onError={setError} />
            : <Empty title="Nothing selected">Pick a proposal. Starting one takes the detections write permission.</Empty>)}
      </div>
    </div>
  )
}

function NewProposal({ caseId, findingId, technique: initial, draftWithModel, onPasted, onError }: {
  caseId: string | null
  findingId: string | null
  technique: string | null
  draftWithModel: (body: { case_id?: string; finding_id?: string; technique?: string; notes?: string }) => Promise<void>
  onPasted: (proposal: Proposal) => void
  onError: (message: string | null) => void
}) {
  const [sigma, setSigma] = useState('')
  const [technique, setTechnique] = useState(initial ?? '')
  const [notes, setNotes] = useState('')
  const [busy, setBusy] = useState(false)

  useEffect(() => setTechnique(initial ?? ''), [initial])

  const paste = async () => {
    setBusy(true)
    onError(null)
    try {
      onPasted(await detectionsApi.paste({ sigma, technique: technique || undefined, case_id: caseId ?? undefined, finding_id: findingId ?? undefined }))
    } catch (e) {
      onError(refusal(e, 'That was not saved.'))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="x1-card de-form" data-testid="de-new">
      <h2>New proposal</h2>
      <p className="de-note">
        A proposal starts from a step no rule caught. Open one from an incident&apos;s missed step, a heat map gap or a red team miss, or write it here. Whatever the model writes is only a draft: lint and replay check it, and a person moves every later stage.
      </p>
      {caseId && <span style={{ fontSize: 12.5 }}>From case <span className="x1-mono">{caseId}</span>{findingId ? <> and finding <span className="x1-mono">{findingId}</span></> : null}.</span>}
      <label>ATT&amp;CK technique<input className="de-text mono" placeholder="T1059.001" value={technique} onChange={(e) => setTechnique(e.target.value)} /></label>
      <label>What the model should know (optional)<textarea className="de-text" rows={2} value={notes} onChange={(e) => setNotes(e.target.value)} /></label>
      <div className="x1-row">
        <button type="button" className="btn primary" disabled={!technique.trim() && !notes.trim() && !caseId} onClick={() => void draftWithModel({ case_id: caseId ?? undefined, finding_id: findingId ?? undefined, technique: technique.trim() || undefined, notes: notes.trim() || undefined })}>Draft with the model</button>
      </div>
      <label>Or paste Sigma<textarea className="de-text mono" rows={12} spellCheck={false} data-testid="de-paste" placeholder={'title: ...\nlogsource: ...\ndetection: ...'} value={sigma} onChange={(e) => setSigma(e.target.value)} /></label>
      <div className="x1-row">
        <button type="button" className="btn ghost" disabled={!sigma.trim() || busy} onClick={paste}>{busy ? 'Saving…' : 'Save as a draft'}</button>
      </div>
    </div>
  )
}
