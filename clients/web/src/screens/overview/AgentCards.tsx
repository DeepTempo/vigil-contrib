import { Link } from 'react-router-dom'
import { Icon } from '../../shared/icons'
import { InfoTip } from '../../shared/InfoTip'
import { LevelBadge } from '../../shared/LevelBadge'
import type { ConsoleScreenProps } from '../../shared/types'
import type { OverviewAgent, OverviewPayload } from '../../services/api'

const CONNECT_DATA = '/settings?section=data'

// A built-in workflow's name is its id ("incident-response"): read it as words
const named = (name: string) =>
  !name.includes(' ') && name.includes('-') ? name.charAt(0).toUpperCase() + name.slice(1).replace(/-/g, ' ') : name

const pct = (n: number) => Math.round(n * 100)

function fmtRate(rate: number | null): string {
  if (rate === null) return '—'
  return `${(rate * 100).toFixed(1)}%`
}

function AgentCard({ agent, onOpen }: { agent: OverviewAgent; onOpen?: (agent: OverviewAgent) => void }) {
  const doing = agent.current_step ? `${agent.running} running · ${agent.current_step}` : `${agent.running} running`
  const measured = agent.sample_size > 0 && agent.level !== null
  return (
    <div
      role="listitem"
      className={`ov-agent${agent.level === 'fair' || agent.level === 'poor' ? ` ${agent.level}` : ''}${onOpen ? ' clickable' : ''}`}
      tabIndex={onOpen ? 0 : undefined}
      aria-label={onOpen ? `${agent.name}: show what it does and its runs` : undefined}
      onClick={onOpen ? () => onOpen(agent) : undefined}
      onKeyDown={
        onOpen
          ? (e) => {
              if (e.key !== 'Enter' && e.key !== ' ') return
              e.preventDefault()
              onOpen(agent)
            }
          : undefined
      }
    >
      <b title={named(agent.name)}>{named(agent.name)}</b>
      <span className="ov-agent-doing" title={doing}>{doing}</span>
      <div className="ov-agent-rate">
        {measured ? (
          <>
            <LevelBadge level={agent.level} variant="pill" />
            <span title={`${fmtRate(agent.rate)} of ${agent.sample_size} runs completed, last 30 days`}>{fmtRate(agent.rate)}</span>
          </>
        ) : (
          <span title="No finished runs in the last 30 days">—</span>
        )}
        {(agent.rejected ?? 0) > 0 && <span className="ov-agent-rejected" title="Stopped by a person at an approval; not counted in the rate">{agent.rejected} rejected</span>}
      </div>
    </div>
  )
}

/** "Agents running now": one card per workflow, with its level pill and 30-day rate. */
export default function AgentCards({
  data,
  go,
  autoOpsOff,
  onOpen,
}: {
  data: OverviewPayload
  autoOpsOff: boolean | null
  /** Opens one agent's record. */
  onOpen?: (agent: OverviewAgent) => void
} & Pick<ConsoleScreenProps, 'go'>) {
  const agents = [...data.agents].sort((a, b) => b.running - a.running || a.name.localeCompare(b.name))
  const idle = agents.every((a) => a.running === 0 && a.sample_size === 0)
  return (
    <section className="ov-agents">
      <div className="ov-agents-h">
        <div>
          <div className="ov-agents-t">
            <h2>Agents running now</h2>
            <InfoTip
              align="start"
              label="About agents running now"
              source={`${data.running_source} ${data.step_source}`}
              calculation={data.rate_info}
            />
          </div>
          <p>
            Good means it finishes {pct(data.good_at)}% or more of its runs; Fair {pct(data.fair_at)} to {pct(data.good_at)}%; Poor under{' '}
            {pct(data.fair_at)}%.
          </p>
        </div>
        <button type="button" className="ov-agents-link" onClick={() => go('workflows')}>
          Agents &amp; workflows →
        </button>
      </div>
      {idle ? (
        <div className="ov-agents-empty">
          <span className="ov-tile accent"><Icon name="bot" size={18} /></span>
          <div className="ov-txt">
            <b>{autoOpsOff ? 'No agents running: AutoOps is off' : 'No agents running yet'}</b>
            <span>
              {autoOpsOff
                ? 'Agents pick up alerts only while AutoOps is on.'
                : 'Agents pick up work on their own once alerts arrive from a connected source.'}
            </span>
          </div>
          {data.empty && <Link className="btn primary no-underline" to={CONNECT_DATA}>Connect data</Link>}
        </div>
      ) : (
        <div className="ov-agents-grid" role="list">
          {agents.map((a) => <AgentCard key={a.workflow_id} agent={a} onOpen={onOpen} />)}
        </div>
      )}
      {(data.standalone ?? []).length > 0 && (
        <div className="ov-standalone" role="list" aria-label="Agents run on their own">
          <span className="ov-standalone-t">Agents run on their own, last 30 days</span>
          {data.standalone!.map((a) => (
            <button key={a.workflow_id} type="button" role="listitem" className="ov-standalone-a" onClick={() => onOpen?.(a)} aria-label={`${a.name}: show its runs`}>
              <b>{a.name}</b>
              <span>
                Ran {a.runs} {a.runs === 1 ? 'time' : 'times'}
                {a.rate !== null && ` · ${(a.rate * 100).toFixed(1)}% succeeded`}
                {a.rejected ? ` · ${a.rejected} rejected` : ''}
              </span>
            </button>
          ))}
        </div>
      )}
    </section>
  )
}
