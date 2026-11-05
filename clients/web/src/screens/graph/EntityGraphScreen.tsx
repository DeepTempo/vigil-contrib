import { useEffect, useMemo, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import type { ConsoleScreenProps } from '../../shared/types'
import { errorText } from '../../shared/errorText'
import { fetchEntityGraph, type EntityGraph, type GraphBlock, type ZeroTrustFinding } from '../../services/graphApi'
import '../shared/x1.css'

const GROUP_COLOR: Record<string, string> = {
  'Identity & naming': '#7c5cff',
  Servers: 'var(--ac)',
  Workstations: '#14b8a6',
  Admin: '#eab308',
  Monitoring: '#ec4899',
  Network: '#ff7a45',
  OT: '#e01f3d',
  Infrastructure: '#0078d4',
  Unknown: 'var(--tx3)',
  External: 'var(--tx2)',
}

const COL_W = 330
const NODE_DX = 100
const NODE_DY = 52
const PER_ROW = 3
const BLOCK_PAD = 30
const X0 = 170
/** A subnet this large gets two columns. One this small shares a column with its peers. */
const WIDE_SUBNET = 15
const SMALL_SUBNET = 4
const INTERNET = 'internet'

const WINDOWS = [
  { hours: 1, label: 'Last hour', range: '1h' },
  { hours: 4, label: 'Last 4 hours', range: '4h' },
  { hours: 24, label: 'Last 24 hours', range: '24h' },
  { hours: 168, label: 'Last 7 days', range: '7d' },
  { hours: 720, label: 'Last 30 days', range: null },
]
const DEFAULT_HOURS = 24

interface Pos { x: number; y: number }
interface Column { title: string; blocks: GraphBlock[] }

function columnsOf(blocks: GraphBlock[]): Column[] {
  const bySubnet = new Map<string, GraphBlock[]>()
  for (const b of blocks) {
    if (b.subnet !== INTERNET) bySubnet.set(b.subnet, [...(bySubnet.get(b.subnet) ?? []), b])
  }
  const size = (list: GraphBlock[]) => list.reduce((n, b) => n + b.hosts.length, 0)
  const subnets = [...bySubnet.values()].sort((a, b) => size(a) - size(b))
  const small = subnets.filter((s) => size(s) <= SMALL_SUBNET)
  const rest = small.length > 1 ? subnets.filter((s) => size(s) > SMALL_SUBNET) : subnets
  const cols: Column[] = small.length > 1 ? [{ title: 'Smaller subnets', blocks: small.flat() }] : []
  for (const list of rest) {
    const title = list[0].zone
    if (size(list) < WIDE_SUBNET) {
      cols.push({ title, blocks: list })
      continue
    }
    const left: GraphBlock[] = []
    const right: GraphBlock[] = []
    let lh = 0
    let rh = 0
    for (const b of [...list].sort((a, c) => c.hosts.length - a.hosts.length)) {
      const h = Math.ceil(b.hosts.length / PER_ROW)
      if (lh <= rh) { left.push(b); lh += h + 1 } else { right.push(b); rh += h + 1 }
    }
    cols.push({ title, blocks: left }, { title: '', blocks: right })
  }
  return cols
}

/** Blocks in zone columns, smallest subnets first, with every outside host as one Internet node. */
function layout(blocks: GraphBlock[]) {
  const cols = columnsOf(blocks)
  const pos = new Map<string, Pos>()
  const rects: { b: GraphBlock; x: number; y: number; w: number; h: number }[] = []
  let maxY = 0
  cols.forEach((col, ci) => {
    let y = 46
    const x = X0 + ci * COL_W
    for (const b of col.blocks) {
      const rows = Math.ceil(b.hosts.length / PER_ROW)
      const h = BLOCK_PAD + rows * NODE_DY + 8
      rects.push({ b, x, y, w: COL_W - 26, h })
      b.hosts.forEach((ip, i) => {
        pos.set(ip, { x: x + 46 + (i % PER_ROW) * NODE_DX, y: y + BLOCK_PAD + 14 + Math.floor(i / PER_ROW) * NODE_DY })
      })
      y += h + 16
    }
    maxY = Math.max(maxY, y)
  })
  pos.set(INTERNET, { x: 70, y: Math.max(160, maxY / 2) })
  const drawnAs = (id: string) => (pos.has(id) ? id : INTERNET)
  return { pos, rects, cols, drawnAs, width: X0 + Math.max(cols.length, 1) * COL_W, height: maxY + 10 }
}

const shortName = (n: string) => (n.length > 15 ? `${n.slice(0, 14)}…` : n)

function fmtBytes(n: number | null): string {
  if (n === null) return 'not in these logs'
  if (n < 1024) return `${n} B`
  if (n < 1024 ** 2) return `${(n / 1024).toFixed(1)} KB`
  if (n < 1024 ** 3) return `${(n / 1024 ** 2).toFixed(1)} MB`
  return `${(n / 1024 ** 3).toFixed(1)} GB`
}

function windowLabel(hours: number) {
  return (WINDOWS.find((w) => w.hours === hours)?.label ?? `Last ${hours} hours`).toLowerCase()
}

function logsSearch(q: string, g: EntityGraph) {
  const named = WINDOWS.find((w) => w.hours === g.window.hours)?.range
  const range = named ?? `${Date.parse(g.window.start)}-${Date.parse(g.window.end)}`
  return `?q=${encodeURIComponent(q)}&range=${encodeURIComponent(range)}`
}

/** The notes that say what this picture cannot show, each only when it is true. */
function limitsOf(g: EntityGraph): string[] {
  const out: string[] = []
  const { coverage: c, rows, truncated } = g
  if (rows.capped > 0) {
    out.push(`Showing the newest ${rows.cap.toLocaleString()} of ${(rows.read + rows.capped).toLocaleString()} flow events in this window. Narrow the window to see the rest.`)
  }
  if (truncated.edges > 0) {
    out.push(`${truncated.edges.toLocaleString()} links are not drawn. The ones kept are those behind a finding or the attack path, then the busiest.`)
  }
  if (c.with_bytes < c.flows) {
    out.push(`${(c.flows - c.with_bytes).toLocaleString()} of ${c.flows.toLocaleString()} flows have no byte counts. Roles from them stop at possible, and findings that need a service to have answered are marked unconfirmed.`)
  }
  if (c.with_port < c.flows) {
    out.push(`${(c.flows - c.with_port).toLocaleString()} of ${c.flows.toLocaleString()} flows have no destination port, so they count as links and say nothing about roles.`)
  }
  return out
}

function FindingButton({ f, on, open, hover }: { f: ZeroTrustFinding; on: boolean; open: (f: ZeroTrustFinding) => void; hover: (id: string | null) => void }) {
  return (
    <button
      type="button"
      className={`${f.severity}${on ? ' on' : ''}`}
      title={`${f.why} Often harmless when: ${f.false_positive_note}`}
      onClick={() => open(f)}
      onMouseEnter={() => hover(f.id)}
      onMouseLeave={() => hover(null)}
      onFocus={() => hover(f.id)}
      onBlur={() => hover(null)}
    >
      <b>{f.title}</b>
      {f.detail}
      <span className="x1-muted" style={{ display: 'block', fontSize: 11.5, marginTop: 2 }}>
        {f.flows_total} {f.flows_total === 1 ? 'link' : 'links'} behind this{f.confirmed ? '' : ' · unconfirmed: no byte count shows the service answered'}
      </span>
    </button>
  )
}

export default function EntityGraphScreen({ go }: ConsoleScreenProps) {
  const [params, setParams] = useSearchParams()
  const caseId = params.get('case')
  const hours = Number(params.get('hours')) || DEFAULT_HOURS
  const sel = params.get('host')

  const [graph, setGraph] = useState<EntityGraph | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [reload, setReload] = useState(0)
  const [showPath, setShowPath] = useState(true)
  const [anomOnly, setAnomOnly] = useState(false)
  const [zt, setZt] = useState<string | null>(null)

  useEffect(() => {
    const ctl = new AbortController()
    setLoading(true)
    fetchEntityGraph(hours, caseId, ctl.signal)
      .then((g) => { setGraph(g); setError(null) })
      .catch((e) => { if (!ctl.signal.aborted) setError(errorText(e, 'Could not read the entity graph.')) })
      .finally(() => { if (!ctl.signal.aborted) setLoading(false) })
    return () => ctl.abort()
  }, [hours, caseId, reload])

  const setParam = (key: string, value: string | null) => {
    setParams((prev) => {
      const next = new URLSearchParams(prev)
      if (value === null) next.delete(key)
      else next.set(key, value)
      return next
    }, { replace: true })
  }
  const pick = (id: string | null) => {
    setZt(null)
    setParam('host', id)
  }
  const openFinding = (f: ZeroTrustFinding) => {
    if (graph) go('logs', { search: logsSearch(f.logs_query, graph) })
  }

  const L = useMemo(() => layout(graph?.blocks ?? []), [graph])
  const byId = useMemo(() => new Map((graph?.nodes ?? []).map((n) => [n.id, n])), [graph])
  const pathOn = showPath && graph?.path != null

  const drawn = useMemo(() => {
    const merged = new Map<string, { id: string; a: Pos; b: Pos; source: string; target: string; anomalous: boolean; onPath: boolean }>()
    for (const e of graph?.edges ?? []) {
      const source = L.drawnAs(e.source)
      const target = L.drawnAs(e.target)
      if (source === target) continue
      const id = `${source}|${target}`
      const was = merged.get(id)
      merged.set(id, {
        id,
        a: L.pos.get(source)!,
        b: L.pos.get(target)!,
        source: e.source,
        target: e.target,
        anomalous: (was?.anomalous ?? false) || e.loglm.anomalous > 0,
        onPath: (was?.onPath ?? false) || e.on_path,
      })
    }
    return [...merged.values()]
  }, [graph, L])

  const ztHosts = useMemo(() => new Set((graph?.findings.find((f) => f.id === zt)?.hosts ?? []).map(L.drawnAs)), [graph, zt, L])
  const neighbours = useMemo(() => {
    if (!sel || !graph || !byId.has(sel)) return null
    const s = new Set([L.drawnAs(sel)])
    for (const e of graph.edges) {
      if (e.source === sel) s.add(L.drawnAs(e.target))
      if (e.target === sel) s.add(L.drawnAs(e.source))
    }
    return s
  }, [sel, graph, L, byId])

  if (!graph) {
    if (error) {
      return (
        <div className="x1">
          <div className="x1-card x1-error" role="alert">
            <p style={{ margin: '0 0 8px' }}>{error}</p>
            <button type="button" className="btn ghost" onClick={() => setReload((n) => n + 1)}>Try again</button>
          </div>
        </div>
      )
    }
    return <div className="x1"><p className="x1-muted" role="status">Reading stored flows…</p></div>
  }

  const windowSelect = (
    <select className="x1-range" aria-label="Time window" value={hours} onChange={(ev) => setParam('hours', ev.target.value)}>
      {!WINDOWS.some((w) => w.hours === hours) && <option value={hours}>Last {hours} hours</option>}
      {WINDOWS.map((w) => <option key={w.hours} value={w.hours}>{w.label}</option>)}
    </select>
  )
  const skipped = graph.rows.skipped > 0 && (
    <span>{graph.rows.skipped.toLocaleString()} {graph.rows.skipped === 1 ? 'event has' : 'events have'} no source or no destination and {graph.rows.skipped === 1 ? 'is' : 'are'} not drawn.</span>
  )

  if (graph.rows.flows === 0) {
    return (
      <div className="x1">
        <div className="x1-row" style={{ justifyContent: 'flex-end' }}>{windowSelect}</div>
        <div className="x1-card" style={{ display: 'grid', gap: 10 }}>
          <h2>No flows to draw in the {windowLabel(hours)}</h2>
          <p className="x1-muted" style={{ margin: 0 }}>
            The entity graph is built from stored log events that name both a source and a destination, as network, firewall and sign-in logs do.
            Port and byte counts sharpen the roles. LogLM scores add the anomaly overlay.
          </p>
          {sel && <p className="x1-muted" style={{ margin: 0 }}>{sel} cannot be shown until a window holds flows. Choose a wider window to look for it.</p>}
          {skipped && <p className="x1-muted" style={{ margin: 0 }}>{skipped}</p>}
          {error && <p className="x1-error" role="alert" style={{ margin: 0 }}>{error}</p>}
          <div className="x1-row">
            <button type="button" className="btn primary" onClick={() => go('logs')}>Open Logs</button>
          </div>
        </div>
      </div>
    )
  }

  const host = sel ? byId.get(sel) : undefined
  const hostEdges = host ? graph.edges.filter((e) => e.source === host.id || e.target === host.id).sort((a, b) => b.flows - a.flows) : []
  const edges = drawn.filter((e) => !anomOnly || e.anomalous || (pathOn && e.onPath))
  const internalHosts = graph.nodes.filter((n) => n.internal).length
  const externalHosts = graph.nodes.length - internalHosts
  const notes = limitsOf(graph)
  const path = graph.path

  return (
    <div className={`x1${loading ? ' x1-dim' : ''}`}>
      <div className="x1-muted" style={{ fontSize: 12.5 }} title={`Treated as internal: ${graph.internal_ranges.join(', ')}`}>
        {graph.rows.flows.toLocaleString()} flows · {graph.coverage.scored.toLocaleString()} scored by LogLM · {internalHosts.toLocaleString()} internal hosts · {graph.findings.length.toLocaleString()} zero-trust findings
        {skipped && <> · {skipped}</>}
      </div>
      {error && <div className="x1-card x1-error" role="alert">{error}</div>}
      {sel && !host && (
        <div className="x1-card x1-note" role="status">
          {sel} has no flow drawn in the {windowLabel(hours)}. Choose a wider window to look for it.
        </div>
      )}
      {!graph.loglm && (
        <div className="x1-card x1-note">
          The anomaly overlay is off. No flow in this window has a LogLM score, so nothing is marked unusual and check ZT9 did not run. Roles and flows below come from the logs alone.
        </div>
      )}
      {notes.length > 0 && (
        <div className="x1-card x1-note">
          {notes.map((n) => <div key={n}>{n}</div>)}
        </div>
      )}
      {path && (
        <div className="x1-strip">
          <div>
            <b>{path.title}</b>
            <div className="x1-muted" style={{ fontSize: 12.5 }}>
              {path.hops.length > 0
                ? `${path.hops.length} ${path.hops.length === 1 ? 'link' : 'links'} between ${path.entities.length} of this case's entities in this window.`
                : `No flow in this window links this case's entities. ${path.entities.length} of them appear here.`}
              {path.not_seen.length > 0 && ` Not seen in these flows: ${path.not_seen.join(', ')}.`}
            </div>
          </div>
          <button type="button" className="btn ghost" onClick={() => go('incident', { search: `?case=${encodeURIComponent(path.case_id)}` })}>Open the incident</button>
        </div>
      )}
      <div className="x1-row" style={{ justifyContent: 'space-between' }}>
        <div className="x1-row">
          {path && (
            <button type="button" className="x1-chipbtn" aria-pressed={showPath} onClick={() => setShowPath(!showPath)}>{path.case_id} attack path</button>
          )}
          <button
            type="button"
            className="x1-chipbtn"
            aria-pressed={anomOnly}
            disabled={!graph.loglm}
            title={graph.loglm ? undefined : 'Needs LogLM scores on the stored events'}
            onClick={() => setAnomOnly(!anomOnly)}
          >
            Only links LogLM found unusual
          </button>
          {sel && <button type="button" className="btn ghost" onClick={() => pick(null)}>Clear selection</button>}
          {windowSelect}
        </div>
        <div className="x1-legend">
          {Object.entries(GROUP_COLOR).map(([g, c]) => <span key={g}><i style={{ background: c }} />{g}</span>)}
          {path && <span><i className="ln" />attack path</span>}
          {graph.loglm && <span><i className="ln anom" />Unusual (LogLM)</span>}
        </div>
      </div>
      <div className="x1-graph-wrap">
        <div className="x1-canvas">
          <svg viewBox={`0 0 ${L.width} ${L.height}`} style={{ width: '100%', minWidth: 900, height: 'auto' }} role="img" aria-label="Entity graph of the stored flows">
            {L.cols.map((c, i) => c.title && (
              <text key={c.title} className="x1-zone-label" x={X0 + i * COL_W} y={28}>{c.title}</text>
            ))}
            <text className="x1-zone-label" x={30} y={28}>Internet</text>
            {L.rects.map(({ b, x, y, w, h }) => (
              <g key={b.id}>
                <rect className="x1-block-rect" x={x} y={y} width={w} height={h} rx={9} />
                <text className="x1-block-label" x={x + 12} y={y + 18}>{b.group} · {b.zone}</text>
              </g>
            ))}
            {edges.map((e) => {
              const onSel = sel !== null && (e.source === sel || e.target === sel)
              const mx = (e.a.x + e.b.x) / 2
              const my = (e.a.y + e.b.y) / 2 - Math.min(60, Math.abs(e.a.x - e.b.x) / 6)
              const cls = pathOn && e.onPath ? 'path' : onSel ? 'sel' : e.anomalous ? 'anom' : ''
              return <path key={e.id} className={`x1-edge ${cls}`} d={`M${e.a.x},${e.a.y} Q${mx},${my} ${e.b.x},${e.b.y}`} />
            })}
            {[...L.pos.entries()].map(([id, p]) => {
              const isInternet = id === INTERNET
              const n = byId.get(id)
              const group = n?.role.group ?? 'External'
              const dim = (neighbours && !neighbours.has(id)) || (zt !== null && !ztHosts.has(id))
              const onPath = pathOn && (isInternet ? graph.nodes.some((x) => !x.internal && x.on_path) : (n?.on_path ?? false))
              const r = isInternet ? 18 : 10 + Math.min(6, Math.log10(1 + (n?.stats.flows_in ?? 0) + (n?.stats.flows_out ?? 0)))
              return (
                <g
                  key={id}
                  className={`x1-node${dim ? ' dim' : ''}${sel === id ? ' on' : ''}${onPath ? ' path' : ''}`}
                  transform={`translate(${p.x},${p.y})`}
                  tabIndex={isInternet ? -1 : 0}
                  role="button"
                  aria-label={isInternet ? `Internet, ${externalHosts} hosts` : `${n?.label ?? id}, ${n?.role.label ?? 'Unknown'}`}
                  onClick={() => { if (!isInternet) pick(id) }}
                  onKeyDown={(ev) => { if ((ev.key === 'Enter' || ev.key === ' ') && !isInternet) { ev.preventDefault(); pick(id) } }}
                >
                  <circle r={r} fill={GROUP_COLOR[group] ?? GROUP_COLOR.Unknown} />
                  {n && n.loglm.anomalous > 0 && <circle r={r + 4} fill="none" stroke="var(--fair)" strokeWidth={1.5} strokeDasharray="3 3" />}
                  <text y={r + 13} textAnchor="middle">{isInternet ? `Internet (${externalHosts})` : shortName(n?.label ?? id)}</text>
                </g>
              )
            })}
          </svg>
        </div>
        <aside className="x1" style={{ gap: 12 }}>
          {host ? (
            <div className="x1-card" style={{ display: 'grid', gap: 10 }}>
              <div>
                <h2>{host.label}</h2>
                <div className="x1-muted x1-mono">{host.id} · {host.block.replace('|', ' · ')}</div>
              </div>
              <div className="x1-row">
                <span className="x1-tag" style={{ borderColor: GROUP_COLOR[host.role.group] }}>{host.role.label}</span>
                <span className={`x1-tag ${host.role.band === 'likely' ? 'good' : host.role.band === 'possible' ? 'fair' : ''}`}>{host.role.band} · {host.role.confidence.toFixed(2)}</span>
                {path && host.on_path && <span className="x1-tag poor">In {path.case_id}</span>}
              </div>
              <div>
                <h3>Why this role</h3>
                <ul className="x1-reasons" style={{ fontSize: 12.5 }}>
                  {host.role.candidates.length
                    ? host.role.candidates[0].evidence.map((w) => <li key={w}>{w}</li>)
                    : <li>Not enough traffic to say.</li>}
                </ul>
                {host.role.candidates.length > 1 && (
                  <p className="x1-muted" style={{ fontSize: 12, margin: '6px 0 0' }}>Also considered: {host.role.candidates.slice(1).map((a) => a.label).join(', ')}</p>
                )}
                {host.role.limits.map((l) => <p key={l} className="x1-muted" style={{ fontSize: 12, margin: '6px 0 0' }}>{l}</p>)}
                <p className="x1-muted" style={{ fontSize: 12, margin: '6px 0 0' }}>Inferred from traffic only. The hostname is a display label.</p>
              </div>
              <dl className="x1-kv">
                <dt>Flows in / out</dt><dd>{host.stats.flows_in.toLocaleString()} / {host.stats.flows_out.toLocaleString()}</dd>
                <dt>Bytes in / out</dt><dd>{host.stats.bytes_in === null ? 'not in these logs' : `${fmtBytes(host.stats.bytes_in)} / ${fmtBytes(host.stats.bytes_out)}`}</dd>
                <dt>Serves</dt><dd>{host.stats.served_ports.map((s) => `${s.port}${s.proto ? `/${s.proto}` : ''}`).join(', ') || 'nothing seen'}</dd>
                <dt>LogLM</dt><dd>{graph.loglm ? `${host.loglm.anomalous} of ${host.loglm.scored} flows unusual` : 'not scored'}</dd>
              </dl>
              <div>
                <h3>Talks to</h3>
                <div className="x1-saved">
                  {hostEdges.slice(0, 6).map((e) => {
                    const other = e.source === host.id ? e.target : e.source
                    const ports = e.services.map((s) => s.port).join(', ')
                    return (
                      <button key={e.id} type="button" onClick={() => pick(other)}>
                        {e.source === host.id ? '→' : '←'} {byId.get(other)?.label ?? other} <span className="x1-muted">· {ports ? `${ports} · ` : ''}{e.flows} flows{e.loglm.anomalous ? ` · ${e.loglm.anomalous} unusual` : ''}</span>
                      </button>
                    )
                  })}
                </div>
              </div>
              {host.findings.length > 0 && (
                <div>
                  <h3>Zero-trust findings</h3>
                  <div className="x1-zt">
                    {graph.findings.filter((f) => host.findings.includes(f.id)).map((f) => (
                      <FindingButton key={f.id} f={f} on={false} open={openFinding} hover={setZt} />
                    ))}
                  </div>
                </div>
              )}
              <div className="x1-row">
                <button type="button" className="btn primary" onClick={() => go('logs', { search: logsSearch(host.logs_query, graph) })}>Show its events</button>
              </div>
            </div>
          ) : (
            <div className="x1-card">
              <h3>Zero-trust findings · {graph.findings.length}</h3>
              <p className="x1-muted" style={{ fontSize: 12.5, margin: '0 0 10px' }}>Point at a finding to light up its hosts, and click it to open its flows in Logs. Click a host to see why it has its role.</p>
              <div className="x1-zt">
                {graph.findings.map((f) => <FindingButton key={f.id} f={f} on={zt === f.id} open={openFinding} hover={setZt} />)}
              </div>
              {graph.findings.length === 0 && <p className="x1-muted" style={{ fontSize: 12.5, margin: 0 }}>No gap found in these flows.</p>}
              {graph.checks_not_run.length > 0 && (
                <p className="x1-muted" style={{ fontSize: 12, margin: '10px 0 0' }}>
                  Did not run, for lack of data: {[...new Set(graph.checks_not_run.map((c) => c.needs))].map((need) => `${graph.checks_not_run.filter((c) => c.needs === need).map((c) => c.check).join(', ')} (${need})`).join('; ')}.
                </p>
              )}
            </div>
          )}
        </aside>
      </div>
    </div>
  )
}
