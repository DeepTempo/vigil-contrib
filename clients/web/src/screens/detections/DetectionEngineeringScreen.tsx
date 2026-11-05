import { useCallback, useEffect, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import type { ConsoleScreenProps } from '../../shared/types'
import { detectionsApi, type Coverage } from '../../services/detectionsApi'
import { errorText } from '../../shared/errorText'
import ProgramTab from './ProgramTab'
import ProposalsTab from './ProposalsTab'
import { percentLabel, percentLine } from './shared'
import '../shared/x1.css'
import './detections.css'

type Tab = 'program' | 'proposals'

export default function DetectionEngineeringScreen({ go, goSettings, openCase }: ConsoleScreenProps) {
  const [params, setParams] = useSearchParams()
  const startsADraft = Boolean(params.get('case') || params.get('finding') || params.get('technique') || params.get('proposal'))
  const tab: Tab = params.get('tab') === 'proposals' || startsADraft ? 'proposals' : 'program'
  const [coverage, setCoverage] = useState<Coverage | null>(null)
  const [coverageError, setCoverageError] = useState<string | null>(null)
  const [proposalCount, setProposalCount] = useState<number | null>(null)

  const reloadCoverage = useCallback(() => {
    detectionsApi.coverage().then((c) => { setCoverage(c); setCoverageError(null) })
      .catch((e) => setCoverageError(errorText(e, 'The heat map did not load.')))
  }, [])
  useEffect(reloadCoverage, [reloadCoverage])
  useEffect(() => {
    detectionsApi.listProposals().then((list) => setProposalCount(list.length)).catch(() => setProposalCount(null))
  }, [])

  const show = (next: Tab) => setParams(next === 'program' ? {} : { tab: next })
  const openProposal = (id: string) => setParams({ proposal: id })
  const draftFor = (technique: string) => setParams({ technique })

  return (
    <div className="x1">
      <div className="x1-card de-band">
        <div>
          <h2>This install</h2>
          <span className="x1-muted" style={{ fontSize: 12.5 }}>
            One Vigil install is one client. Vigil does not run several clients from one console, and this page lists none.
          </span>
        </div>
        <div className="de-pct" data-testid="de-percent">
          {coverage?.summary.percent_validated != null ? <b>{percentLabel(coverage.summary)}</b> : <b>No data</b>}
          <span>{coverage ? percentLine(coverage) : 'Reading the heat map'}</span>
        </div>
      </div>
      <div className="x1-tabs" role="tablist" aria-label="Detection engineering">
        <button type="button" role="tab" aria-selected={tab === 'program'} onClick={() => show('program')}>Program</button>
        <button type="button" role="tab" aria-selected={tab === 'proposals'} onClick={() => show('proposals')}>
          Proposals{proposalCount != null ? ` · ${proposalCount}` : ''}
        </button>
      </div>
      {tab === 'program'
        ? <ProgramTab coverage={coverage} coverageError={coverageError} reloadCoverage={reloadCoverage} openProposal={openProposal} draftFor={draftFor} goSettings={goSettings} />
        : <ProposalsTab params={params} setParams={setParams} onCount={setProposalCount} onMoved={reloadCoverage} go={go} openCase={openCase} />}
    </div>
  )
}
