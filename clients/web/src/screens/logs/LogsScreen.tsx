import { Fragment, useCallback, useEffect, useMemo, useRef, useState, type PointerEvent as ReactPointerEvent } from 'react'
import { useSearchParams } from 'react-router-dom'
import { basePath } from '../../config/basePath'
import { useAuth } from '../../contexts/AuthContext'
import { ingestLogs, logSources, logStatus, searchLogs, type LogResult, type LogRow, type LogSourceInfo, type LogStatus, type SearchArgs } from '../../services/logsApi'
import { errorText } from '../../shared/errorText'
import type { ConsoleScreenProps } from '../../shared/types'
import { usePageSnapshot } from '../../shell/pageSnapshot'
import { LoglmMeter, SevDot, SourceChip, Tag } from '../shared/x1'
import {
  DAY, RANGES, STARTER_SEARCHES, formatQuery, isRelative, loadSaved, paramsFor, parseQuery, queryFromParams, rangeFromParams, reportLine, storeSaved, termLabel, toCsv, windowOf,
  type Range, type SavedSearch,
} from './logsQuery'

const PAGE = 150
const BUCKETS = 60
const LIVE_EVERY = 5000
const MIN = 60_000
const ROUTE = `${basePath}/api/log-events/ingest`
const storeFailed = (e: unknown) => `The log store did not answer, so these results are missing. ${errorText(e, '')}`.trim()
const searchFailed = (e: unknown) => {
  const status = (e as { response?: { status?: number } }).response?.status
  return status === 422 || status === 504 ? errorText(e, 'That search could not be read.') : storeFailed(e)
}

const HELP: [string, string][] = [
  ['powershell', 'the word anywhere in the event, including the original record'],
  ['"failed logon"', 'the exact phrase'],
  ['host:wks-12', 'source or destination host contains wks-12'],
  ['ip:192.0.2.5  ip:192.0.2.', 'an exact IP, or every IP that starts that way'],
  ['user:jdoe  port:445', 'a person, a destination port'],
  ['source:sysmon,crowdstrike  beacon,c2', 'a comma means either'],
  ['sev:high  class:auth  action:deny', 'severity, event class, what happened'],
  ['mitre:T1059  case:<id>', 'an ATT&CK technique, a case'],
  ['loglm>0.7', 'LogLM scored it at least this unusual'],
  ['-source:entra  -vpn', 'a minus sign leaves matches out'],
]

// The entity graph draws the internal network; a sign-in's home or mobile address is not on it
const INTERNAL = /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/

const iso = (t: number) => new Date(t).toISOString()
const hm = (t: number) => iso(t).slice(11, 16)
const dayHm = (t: number) => `${new Date(t).toLocaleDateString('en-GB', { day: 'numeric', month: 'short', timeZone: 'UTC' })} ${hm(t)}`

/** "today 18:30–22:00", "26 Oct 18:30–22:00" or "20 Oct 16:55 – 27 Oct 16:55". */
function spanLabel(a: number, b: number, now: number): string {
  const day = (t: number) => Math.floor(t / DAY)
  if (day(a) !== day(b - 1)) return `${dayHm(a)} – ${dayHm(b)}`
  const d = day(now) - day(a)
  const name = d === 0 ? 'today' : d === 1 ? 'yesterday' : new Date(a).toLocaleDateString('en-GB', { day: 'numeric', month: 'short', timeZone: 'UTC' })
  return `${name} ${hm(a)}–${hm(b)}`
}
const fromInput = (v: string) => Date.parse(`${v}:00Z`)
const toInput = (t: number) => iso(t).slice(0, 16)

function ago(t: number | null, now: number): string {
  if (!t) return 'no events yet'
  const s = Math.max(0, Math.round((now - t) / 1000))
  if (s < 60) return `${s} s ago`
  if (s < 3600) return `${Math.round(s / 60)} min ago`
  if (s < 86400) return `${Math.round(s / 3600)} h ago`
  return `${Math.round(s / 86400)} d ago`
}

function Histogram({ result, onZoom }: { result: LogResult; onZoom: (start: number, end: number) => void }) {
  const { counts, inCase } = result.histogram
  const n = counts.length || 1
  const svg = useRef<SVGSVGElement>(null)
  const [drag, setDrag] = useState<[number, number] | null>(null)
  const [hover, setHover] = useState<number | null>(null)
  const max = Math.max(1, ...counts)
  const W = 840
  const H = 92
  const bw = W / n
  const span = (result.end - result.start) / n
  const long = result.end - result.start > DAY * 0.9
  const at = (e: ReactPointerEvent) => {
    const box = svg.current!.getBoundingClientRect()
    return Math.min(n - 1, Math.max(0, Math.floor(((e.clientX - box.left) / box.width) * n)))
  }
  const sel = drag ? [Math.min(...drag), Math.max(...drag)] : null
  return (
    <div className="x1-histwrap">
      <svg
        ref={svg}
        className="x1-hist"
        viewBox={`0 0 ${W} ${H}`}
        preserveAspectRatio="none"
        role="img"
        aria-label={`Events over time, ${counts.reduce((a, b) => a + b, 0)} in all; events in a case in red. Drag across the bars to zoom in.`}
        onPointerDown={(e) => { (e.target as Element).setPointerCapture?.(e.pointerId); const i = at(e); setDrag([i, i]) }}
        onPointerMove={(e) => { const i = at(e); setHover(i); if (drag) setDrag([drag[0], i]) }}
        onPointerLeave={() => setHover(null)}
        onPointerUp={() => {
          if (sel) onZoom(result.start + sel[0] * span, result.start + (sel[1] + 1) * span)
          setDrag(null)
        }}
      >
        {counts.map((c, i) => {
          const h = (c / max) * (H - 20)
          const hi = (inCase[i] / max) * (H - 20)
          return (
            <g key={i}>
              <rect x={i * bw} y={0} width={bw} height={H - 14} fill="transparent" />
              <rect x={i * bw + 1} y={H - 14 - h} width={Math.max(1, bw - 2)} height={h} rx={1.5} fill="var(--ac)" opacity={hover === i ? 0.6 : 0.35} />
              {hi > 0 && <rect className="x1-hist-case" x={i * bw + 1} y={H - 14 - hi} width={Math.max(1, bw - 2)} height={hi} rx={1.5} fill="var(--poor)" />}
            </g>
          )
        })}
        {sel && <rect x={sel[0] * bw} y={0} width={(sel[1] - sel[0] + 1) * bw} height={H - 14} fill="var(--ac)" opacity={0.15} stroke="var(--ac)" />}
        {[0, 0.25, 0.5, 0.75, 1].map((f) => (
          <text key={f} x={Math.min(W - (long ? 62 : 30), f * W)} y={H - 2} fontSize="10" fill="var(--tx2)">{(long ? dayHm : hm)(result.start + f * (result.end - result.start))}</text>
        ))}
      </svg>
      {hover !== null && !drag && (
        <span className="x1-histtip" style={{ left: `${((hover + 0.5) / n) * 100}%` }}>
          {(long ? dayHm : hm)(result.start + hover * span)}–{hm(result.start + (hover + 1) * span)} · {counts[hover].toLocaleString()} events{inCase[hover] ? ` · ${inCase[hover]} in a case` : ''}
        </span>
      )}
    </div>
  )
}

/** Add-to-search (+) and leave-out (−) for one field of an event. */
function Pivot({ term, onAdd }: { term: string; onAdd: (term: string) => void }) {
  return (
    <span className="x1-pivot">
      <button type="button" onClick={() => onAdd(term)} aria-label={`Search for ${term}`} title={`Search for ${term}`}>+</button>
      <button type="button" onClick={() => onAdd(`-${term}`)} aria-label={`Leave out ${term}`} title={`Leave out ${term}`}>−</button>
    </span>
  )
}

// The first call fetches the csrf_token cookie, which the second echoes: this route takes the same CSRF check as the console.
const sendCommand = (origin: string) => `curl -sS -H "Authorization: Bearer $VIGIL_TOKEN" \\
  -F file=@events.jsonl ${origin}${ROUTE}`

function SendLogs({ status, canSend, uploading, onPick }: { status: LogStatus; canSend: boolean; uploading: boolean; onPick: () => void }) {
  return (
    <div className="x1-card" data-testid="logs-empty">
      <h3>No logs yet. How to send them</h3>
      <p data-testid="logs-by-upload">
        Logs arrive by upload. Alerts from a connected SIEM or EDR are findings, and they do not fill this screen.
      </p>
      <p>
        Post a file to <code className="x1-mono">POST {ROUTE}</code>. It takes {status.formats.join(', ')} up to {status.max_upload_mb} MB, and needs the findings.write permission.
      </p>
      <pre className="x1-pre" data-testid="logs-send-command">{sendCommand(window.location.origin)}</pre>
      <p className="x1-muted">
        $VIGIL_TOKEN is the access_token from POST {basePath}/api/auth/login, asked for with curl as well, because a token only works from the kind of client that signed in. Vigil reads {status.shapes.join(', ')}, and any JSON or CSV row with a time field. A <code className="x1-mono">loglm</code> column carries a score and a <code className="x1-mono">case_id</code> column links a row to a case. Rows with no time are dropped and counted. Events are kept {status.retention_days} days.
      </p>
      {canSend && <button type="button" className="btn primary" disabled={uploading} onClick={onPick}>{uploading ? 'Uploading…' : 'Upload a log file'}</button>}
    </div>
  )
}

function LoglmNote({ status, onSettings }: { status: LogStatus; onSettings: () => void }) {
  const { loglm: { connected }, scored } = status
  if (connected && scored > 0) return null
  const line = !connected
    ? scored > 0
      ? `LogLM is not connected. ${scored.toLocaleString()} stored events carry a score that came in an uploaded file, and the rest show a dash.`
      : 'LogLM is not connected, so the Unusual column has no scores.'
    : 'LogLM is connected, but no stored event has a score yet. Scores arrive as a loglm column on ingested rows.'
  return (
    <div className="x1-card x1-note" role="status" data-testid="logs-loglm-note">
      {line}{!connected && <> <button type="button" className="x1-link" onClick={onSettings}>Open integrations</button></>}
    </div>
  )
}

export default function LogsScreen({ go, goSettings }: ConsoleScreenProps) {
  const { user, hasPermission } = useAuth()
  const canSend = hasPermission('findings.write')
  const userId = user?.user_id ?? 'anonymous'
  const [params, setParams] = useSearchParams()
  const applied = useMemo(() => queryFromParams(params), [params])
  const range = useMemo(() => rangeFromParams(params, applied), [params, applied])
  const [q, setQ] = useState(applied)
  const [prevRange, setPrevRange] = useState<Range | null>(null)
  const [off, setOff] = useState<Set<string>>(new Set())
  const [open, setOpen] = useState<string | null>(null)
  const [result, setResult] = useState<LogResult | null>(null)
  const [rows, setRows] = useState<LogRow[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [live, setLive] = useState(false)
  const [fresh, setFresh] = useState<Set<string>>(new Set())
  const [sources, setSources] = useState<LogSourceInfo[]>([])
  const [status, setStatus] = useState<LogStatus | null>(null)
  const [metaError, setMetaError] = useState<string | null>(null)
  const [help, setHelp] = useState(false)
  const [now, setNow] = useState(Date.now())
  const [saved, setSaved] = useState<SavedSearch[]>(() => loadSaved(userId))
  const [uploading, setUploading] = useState(false)
  const [uploadLine, setUploadLine] = useState<string | null>(null)
  const [uploadError, setUploadError] = useState<string | null>(null)
  const fileInput = useRef<HTMLInputElement>(null)
  const abort = useRef<AbortController | null>(null)
  // a person's search or Show more is in flight; a live tick waits so it does not cancel it
  const inflight = useRef(false)
  const shownIds = useRef<Set<string>>(new Set())

  useEffect(() => { setQ(applied) }, [applied])

  const argsFor = useCallback((offset: number, at = Date.now()): SearchArgs => {
    const page = { q: applied, hide: [...off], offset, limit: PAGE, buckets: BUCKETS }
    if (range.key === 'fit') return { ...page, fit: true }
    const [start, end] = windowOf(range, at)
    return { ...page, start, end }
  }, [applied, range, off])

  const run = useCallback(async (quiet = false) => {
    abort.current?.abort()
    const ctl = new AbortController()
    abort.current = ctl
    if (!quiet) { setLoading(true); inflight.current = true }
    try {
      const r = await searchLogs(argsFor(0), ctl.signal)
      if (ctl.signal.aborted) return
      const seen = shownIds.current
      setFresh(quiet ? new Set(r.events.filter((x) => !seen.has(x.id)).map((x) => x.id)) : new Set())
      shownIds.current = new Set(r.events.map((x) => x.id))
      setResult(r)
      setRows(r.events)
      setError(null)
    } catch (e) {
      if (ctl.signal.aborted) return
      setError(searchFailed(e))
      // a missed live poll keeps the rows it was showing, under the error; a search shows no old rows as its answer
      if (!quiet) { setResult(null); setRows([]) }
    } finally {
      if (!ctl.signal.aborted) { setLoading(false); inflight.current = false }
    }
  }, [argsFor])

  useEffect(() => { void run() }, [run])
  useEffect(() => () => abort.current?.abort(), [])

  const readMeta = useCallback(async () => {
    try {
      const [nextSources, nextStatus] = await Promise.all([logSources(), logStatus()])
      setSources(nextSources)
      setStatus(nextStatus)
      setMetaError(null)
    } catch (e) {
      setMetaError(storeFailed(e))
    }
  }, [])
  useEffect(() => { void readMeta() }, [readMeta])

  // live tail: a relative range slides forward while nobody is reading further down
  const paused = open !== null || rows.length > PAGE
  useEffect(() => {
    if (!live || !isRelative(range)) return
    const id = setInterval(() => {
      setNow(Date.now())
      if (!paused && !inflight.current) void run(true)
      void readMeta()
    }, LIVE_EVERY)
    return () => clearInterval(id)
  }, [live, range, paused, run, readMeta])
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), 30_000)
    return () => clearInterval(id)
  }, [])

  const more = async () => {
    if (!result || loading) return // a newer search is on its way; its rows are not these
    const args: SearchArgs = { ...argsFor(rows.length), fit: false, start: result.start, end: result.end }
    const ctl = abort.current // a new search aborts this one, so its page is not added under the new rows
    inflight.current = true
    try {
      const r = await searchLogs(args, ctl?.signal)
      if (ctl?.signal.aborted || ctl !== abort.current) return
      setRows((prev) => [...prev, ...r.events.filter((e) => !prev.some((p) => p.id === e.id))])
    } catch (e) {
      if (!ctl?.signal.aborted) setError(searchFailed(e))
    } finally {
      if (ctl === abort.current) inflight.current = false
    }
  }

  const show = (nextQ: string, nextRange: Range) => {
    setOpen(null)
    setParams(paramsFor(nextQ, nextRange), { replace: true })
  }
  const submit = (next: string) => {
    if (next === applied) void run() // the same search again still asks the store, e.g. after it failed
    setQ(next)
    show(next, range)
  }
  const pickRange = (r: Range) => {
    setPrevRange(null)
    show(applied, r)
  }
  const zoom = (start: number, end: number) => {
    setPrevRange((p) => p ?? range)
    setLive(false)
    show(applied, { key: 'custom', start: Math.round(start), end: Math.round(end) })
  }
  const addTerm = (term: string) => submit(applied.trim() ? `${applied.trim()} ${term}` : term)
  const terms = useMemo(() => parseQuery(applied), [applied])
  const dropTerm = (i: number) => submit(formatQuery(terms.filter((_, j) => j !== i)))

  const counts = useMemo(() => result?.bySource ?? {}, [result])
  // the chips are whatever the store holds and the search matched, never a fixed list
  const sourceKeys = useMemo(() => [...new Set([...sources.map((s) => s.source), ...Object.keys(counts)])].sort(), [sources, counts])
  const labelOf = (s: string) => sources.find((x) => x.source === s)?.label ?? s
  const toggle = (s: string) =>
    setOff((prev) => {
      const n = new Set(prev)
      if (n.has(s)) n.delete(s)
      else n.add(s)
      return n
    })
  const only = (s: string) => setOff(new Set(sourceKeys.filter((k) => k !== s)))
  const around = (r: LogRow) => {
    setPrevRange((p) => p ?? range)
    const t = r.ts * 1000
    const host = r.srcHost ?? r.dstHost
    setLive(false)
    show(host ? formatQuery([{ key: 'host', value: host, negate: false }]) : '', { key: 'custom', start: t - 5 * MIN, end: t + 5 * MIN })
  }
  const exportCsv = () => {
    const blob = new Blob([toCsv(rows)], { type: 'text/csv' })
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = `vigil-logs-${iso(Date.now()).slice(0, 16).replace(/[:T]/g, '')}.csv`
    a.click()
    URL.revokeObjectURL(a.href)
  }
  const upload = async (file: File) => {
    setUploading(true)
    setUploadLine(null)
    setUploadError(null)
    try {
      const report = await ingestLogs(file)
      setUploadLine(reportLine(file.name, report))
      await readMeta()
      // what just arrived may be older than the range on screen
      if (report.rows > 0 && range.key !== 'fit') pickRange({ key: 'fit' })
      else void run()
    } catch (e) {
      setUploadError(errorText(e, `${file.name} could not be sent.`))
    } finally {
      setUploading(false)
    }
  }
  const remember = (next: SavedSearch[]) => {
    setSaved(next)
    storeSaved(userId, next)
  }

  const allSaved = [...STARTER_SEARCHES, ...saved]
  const long = result ? result.end - result.start > DAY * 0.9 : false
  const when = (r: LogRow) => (long ? `${new Date(r.ts * 1000).toLocaleDateString('en-GB', { day: 'numeric', month: 'short', timeZone: 'UTC' })} ${r.time.slice(11, 19)}` : r.time.slice(11, 19))
  const total = result?.total ?? 0
  const stored = status?.total ?? 0
  const lastIn = sources.reduce((a, s) => Math.max(a, Date.parse(s.last)), 0) || result?.newest || null

  const line = (r: LogRow) =>
    [r.time, labelOf(r.source), r.class, `${r.srcHost ?? r.srcIp ?? '-'} -> ${r.dstHost ?? r.dstIp ?? '-'}${r.dstPort ? `:${r.dstPort}` : ''}`, r.user ?? '-', r.summary, r.loglm === null ? '' : `unusual ${r.loglm.toFixed(2)}`, r.caseId ?? '', r.mitre ?? '']
      .filter(Boolean).join(' | ')
  const snapshot = !result
    ? `Logs: ${error ?? 'loading.'}`
    : [
        `Logs: one table across ${sourceKeys.length} sources, ${stored.toLocaleString()} events stored.`,
        `Time range: ${iso(result.start)} to ${iso(result.end)}. Search: ${applied || '(none)'}. ${total.toLocaleString()} events match${off.size ? `, with ${[...off].map(labelOf).join(', ')} hidden` : ''}.`,
        `By source: ${sourceKeys.map((k) => `${labelOf(k)} ${counts[k] ?? 0}`).join(', ')}.`,
        status && !status.loglm.connected ? 'LogLM is not connected.' : '',
        'Most unusual per LogLM among loaded rows (time | source | class | from -> to | user | event | score | case | technique):',
        ...[...rows].filter((r) => r.loglm !== null).sort((a, b) => (b.loglm ?? 0) - (a.loglm ?? 0)).slice(0, 20).map(line),
        `Newest ${Math.min(25, rows.length)} of the loaded rows:`,
        ...rows.slice(0, 25).map(line),
      ].filter(Boolean).join('\n')
  usePageSnapshot('logs', snapshot)

  const hostBtn = (ip: string | null, label: string | null) =>
    ip ? (
      <button type="button" className="x1-link" onClick={(e) => { e.stopPropagation(); go('graph', { search: `?host=${encodeURIComponent(ip)}` }) }} title={`${label ?? ip}: open in the entity graph`}>
        {label ?? ip}
      </button>
    ) : label ? (
      <span title={label}>{label}</span>
    ) : (
      <span className="x1-muted">—</span>
    )
  const relative = isRelative(range)
  const [ws, we] = result ? [result.start, result.end] : windowOf(range, now)
  const isEmptyStore = status?.total === 0

  return (
    <div className="x1">
      <input
        ref={fileInput}
        type="file"
        accept=".jsonl,.ndjson,.json,.csv,.log"
        hidden
        aria-label="Log file to upload"
        onChange={(e) => {
          const file = e.target.files?.[0]
          e.target.value = ''
          if (file) void upload(file)
        }}
      />
      <div className="x1-row" style={{ justifyContent: 'space-between' }}>
        <span className="x1-muted" style={{ fontSize: 12 }} data-testid="logs-stored">
          {status ? `${stored.toLocaleString()} events stored · ${sourceKeys.length} sources · one schema · kept ${status.retention_days} days` : ''}
        </span>
        {canSend && !isEmptyStore && (
          <button type="button" className="btn ghost" disabled={uploading} onClick={() => fileInput.current?.click()}>
            {uploading ? 'Uploading…' : 'Upload a log file'}
          </button>
        )}
      </div>
      {uploadLine && <div className="x1-card x1-note" role="status" data-testid="logs-upload-report">{uploadLine}</div>}
      {uploadError && <div className="x1-card x1-error" role="alert">{uploadError}</div>}
      <div className="x1-logs">
        <aside className="x1-card">
          <h3>Saved searches</h3>
          <div className="x1-saved">
            {allSaved.map((s) => {
              const mine = saved.includes(s)
              return (
                <div key={`${s.label}-${s.q}`} className="x1-row" style={{ flexWrap: 'nowrap', gap: 2 }}>
                  <button type="button" style={{ flex: 1, minWidth: 0, overflowWrap: 'anywhere' }} className={applied === s.q ? 'on' : undefined} onClick={() => submit(s.q)}>
                    {s.label}
                  </button>
                  {mine && <button type="button" aria-label={`Forget ${s.label}`} title="Forget this search" onClick={() => remember(saved.filter((x) => x !== s))}>×</button>}
                </div>
              )
            })}
          </div>
          {applied && !allSaved.some((s) => s.q === applied) && (
            <button type="button" className="x1-link" style={{ marginTop: 8, fontSize: 12.5 }} onClick={() => remember([...saved, { label: applied, q: applied }])}>
              Save this search
            </button>
          )}
          <h3 style={{ marginTop: 16 }}>Sources</h3>
          <div className="x1-saved">
            {sources.length === 0 && <span className="x1-muted" style={{ fontSize: 12.5 }}>None yet.</span>}
            {sources.map((info) => {
              const last = Date.parse(info.last)
              return (
                <button key={info.source} type="button" className="x1-srcrow" onClick={() => only(info.source)} title={`Show only ${info.label}`}>
                  <SourceChip source={info.source} label={info.label} />
                  <span className="x1-srcmeta">
                    {info.events.toLocaleString()} {info.events === 1 ? 'event' : 'events'}<br /><span className={`x1-dot${now - last < 15 * MIN ? '' : ' off'}`} />last {ago(last, now)}
                  </span>
                </button>
              )
            })}
          </div>
        </aside>
        <div className="x1" style={{ gap: 12 }}>
          <form className="x1-query" onSubmit={(e) => { e.preventDefault(); submit(q) }}>
            <input
              value={q}
              onChange={(e) => setQ(e.target.value)}
              onKeyDown={(e) => { if (e.key === 'Escape' && q) { e.preventDefault(); setQ(applied) } }}
              placeholder='Search: words, "a phrase", host:wks-12 user:jdoe ip:192.0.2.5 port:445 -source:entra loglm>0.7'
              aria-label="Search events"
              spellCheck={false}
            />
            <select className="x1-range" aria-label="Time range" value={range.key} onChange={(e) => {
              const key = e.target.value as Range['key']
              if (key === 'custom') pickRange({ key, start: ws, end: we })
              else pickRange({ key })
            }}>
              {RANGES.map((r) => <option key={r.key} value={r.key}>{r.label}</option>)}
            </select>
            <button type="submit" className="btn primary">Search</button>
            <button type="button" className={`btn ghost x1-live${live && relative ? ' on' : ''}`} aria-pressed={live && relative} disabled={!relative} title={relative ? 'Keep the newest events coming in' : 'Live works with a "Last …" range'} onClick={() => setLive(!live)}>
              <span className={`x1-dot${live && relative ? ' pulse' : ' off'}`} />Live
            </button>
            <button type="button" className="btn ghost" aria-expanded={help} onClick={() => setHelp(!help)}>Search help</button>
          </form>
          {range.key === 'custom' && (
            <div className="x1-row x1-custom">
              <label>From (UTC) <input type="datetime-local" value={toInput(range.start ?? ws)} onChange={(e) => { const t = fromInput(e.target.value); if (t) pickRange({ ...range, start: t }) }} /></label>
              <label>To (UTC) <input type="datetime-local" value={toInput(range.end ?? we)} onChange={(e) => { const t = fromInput(e.target.value); if (t) pickRange({ ...range, end: t }) }} /></label>
              {prevRange && <button type="button" className="btn ghost" onClick={() => pickRange(prevRange)}>Back to {RANGES.find((r) => r.key === prevRange.key)?.label.toLowerCase()}</button>}
            </div>
          )}
          {help && (
            <div className="x1-card x1-help" role="note">
              <dl>
                {HELP.map(([k, v]) => (
                  <Fragment key={k}><dt><button type="button" className="x1-link x1-mono" onClick={() => submit(k.split('  ')[0])}>{k}</button></dt><dd>{v}</dd></Fragment>
                ))}
              </dl>
              <p className="x1-muted">Everything you type has to match. Click a value in an event to add it, or <b>−</b> to leave it out.</p>
            </div>
          )}
          {terms.length > 0 && (
            <div className="x1-row x1-terms" aria-label="Search filters">
              {terms.map((t, i) => (
                <span key={`${i}-${t.key}-${t.value}`} className={`x1-term${t.negate ? ' not' : ''}`}>
                  {termLabel(t)}
                  <button type="button" aria-label={`Remove ${termLabel(t)}`} onClick={() => dropTerm(i)}>×</button>
                </span>
              ))}
              {terms.length > 1 && <button type="button" className="x1-link" onClick={() => submit('')}>Clear all</button>}
            </div>
          )}
          {error && <div className="x1-card x1-error" role="alert" data-testid="logs-error">{error}</div>}
          {metaError && !error && <div className="x1-card x1-error" role="alert">{metaError}</div>}
          {status && <LoglmNote status={status} onSettings={() => goSettings('integrations')} />}
          {sourceKeys.length > 0 && (
            <div className="x1-row" aria-label="Sources">
              {sourceKeys.map((s) => (
                <button key={s} type="button" className="x1-chipbtn" aria-pressed={!off.has(s)} onClick={() => toggle(s)} onDoubleClick={() => only(s)} title="Click to hide or show; double-click to show only this source">
                  <SourceChip source={s} label={labelOf(s)} />
                  <span className="n">{(counts[s] ?? 0).toLocaleString()}</span>
                </button>
              ))}
              {off.size > 0 && <button type="button" className="x1-link" onClick={() => setOff(new Set())}>Show all sources</button>}
            </div>
          )}
          {(!error || result) && (
            <div className="x1-card" style={{ padding: '10px 12px' }} aria-busy={loading}>
              <div className="x1-row" style={{ justifyContent: 'space-between', marginBottom: 4 }}>
                <span className="x1-muted" style={{ fontSize: 12 }} aria-live="polite" data-testid="logs-total">
                  {loading && !result ? 'Searching…' : `${total.toLocaleString()} events`}, {spanLabel(ws, we, now)} UTC
                  {live && relative && <> · {paused ? 'live paused while you read' : `live, newest ${ago(lastIn, now)}`}</>}
                </span>
                <span className="x1-row" style={{ gap: 12 }}>
                  {range.key === 'custom' && prevRange && <button type="button" className="x1-link" onClick={() => pickRange(prevRange)}>Zoom out</button>}
                  <span className="x1-legend"><span><i style={{ background: 'var(--poor)', borderRadius: 2 }} />In a case</span><span><i style={{ background: 'var(--ac)', opacity: 0.35, borderRadius: 2 }} />Other</span></span>
                </span>
              </div>
              {result && <Histogram result={result} onZoom={zoom} />}
            </div>
          )}
          <div className="x1-row" style={{ justifyContent: 'space-between' }}>
            <span className="x1-muted" style={{ fontSize: 12 }}>
              {rows.length ? `Newest first · showing ${rows.length.toLocaleString()} of ${total.toLocaleString()}` : ''}
            </span>
            {rows.length > 0 && <button type="button" className="x1-link" onClick={exportCsv}>Export {rows.length.toLocaleString()} rows as CSV</button>}
          </div>
          {rows.length > 0 && (
            <div className={`x1-table-wrap${loading && result ? ' x1-dim' : ''}`}>
              <table className="x1-table x1-logtable">
                {/* fixed columns; Event takes the rest and wraps, so the page never scrolls sideways */}
                <colgroup>
                  <col className="c-time" style={{ width: long ? 132 : 100 }} />
                  <col className="c-src" /><col className="c-class" /><col className="c-host" /><col className="c-host" /><col className="c-user" /><col /><col className="c-score" style={{ width: 112 }} />
                </colgroup>
                <thead>
                  <tr>
                    <th>Time (UTC)</th><th>Source</th><th className="c-class">Class</th><th>From</th><th>To</th><th>User</th><th>Event</th><th title="Score from LogLM"><span className="x1-h-wide">Unusual</span><span className="x1-h-narrow">Score</span></th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((r) => (
                    <Fragment key={r.id}>
                      <tr className={`click${r.caseId ? ' hit' : ''}${open === r.id ? ' open' : ''}${fresh.has(r.id) ? ' x1-new' : ''}`} onClick={() => setOpen(open === r.id ? null : r.id)} aria-expanded={open === r.id}>
                        <td className="x1-ts">{when(r)}</td>
                        <td><SourceChip source={r.source} label={labelOf(r.source)} /></td>
                        <td className="c-class" style={{ whiteSpace: 'nowrap' }}><SevDot level={r.severity} /> {r.class}</td>
                        <td>{hostBtn(r.srcIp, r.srcHost)}</td>
                        <td>{hostBtn(r.dstIp, r.dstHost)}{r.dstPort ? <span className="x1-muted">:{r.dstPort}</span> : null}</td>
                        <td>{r.user ?? <span className="x1-muted">—</span>}</td>
                        <td className="x1-ev">
                          {r.summary}
                          {r.tags.map((t) => <span key={t} style={{ marginLeft: 6 }}><Tag tone="fair">{t}</Tag></span>)}
                        </td>
                        <td data-testid="logs-unusual">{r.loglm === null ? <span className="x1-muted" title="LogLM did not score this event">—</span> : <LoglmMeter value={r.loglm} />}</td>
                      </tr>
                      {open === r.id && (
                        <tr className="open">
                          <td colSpan={8}>
                            <div className="x1-grid2">
                              <div>
                                <h3 className="x1-muted" style={{ fontSize: 11, textTransform: 'uppercase', letterSpacing: '.6px', margin: '4px 0 8px' }}>Vigil schema</h3>
                                <dl className="x1-kv">
                                  <dt>event.id</dt><dd className="x1-mono">{r.id}</dd>
                                  <dt>event.time</dt><dd className="x1-mono">{r.time}</dd>
                                  <dt>event.class</dt><dd>{r.class || '—'}{r.class && <Pivot term={`class:${r.class.split(' ')[0]}`} onAdd={addTerm} />}</dd>
                                  <dt>source</dt><dd>{labelOf(r.source)} <Pivot term={`source:${r.source}`} onAdd={addTerm} /></dd>
                                  <dt>src.ip / host</dt><dd>{r.srcIp ?? '—'} {r.srcHost && r.srcHost !== r.srcIp ? `(${r.srcHost})` : ''}{r.srcIp && <Pivot term={`ip:${r.srcIp}`} onAdd={addTerm} />}</dd>
                                  <dt>dst.ip / host</dt><dd>{r.dstIp ?? '—'} {r.dstHost && r.dstHost !== r.dstIp ? `(${r.dstHost})` : ''}{r.dstPort ? ` port ${r.dstPort}` : ''}{r.dstIp && <Pivot term={`ip:${r.dstIp}`} onAdd={addTerm} />}</dd>
                                  <dt>actor.user</dt><dd>{r.user ?? '—'}{r.user && <Pivot term={formatQuery([{ key: 'user', value: r.user, negate: false }])} onAdd={addTerm} />}</dd>
                                  <dt>activity</dt><dd>{r.action ?? '—'}{r.action && <Pivot term={formatQuery([{ key: 'action', value: r.action, negate: false }])} onAdd={addTerm} />}</dd>
                                  <dt>severity</dt><dd>{r.severity} <Pivot term={`sev:${r.severity}`} onAdd={addTerm} /></dd>
                                  <dt>attack.technique</dt><dd>{r.mitre ?? '—'}{r.mitre && <Pivot term={`mitre:${r.mitre}`} onAdd={addTerm} />}</dd>
                                  <dt>loglm.anomaly</dt><dd>{r.loglm ?? '—'}</dd>
                                  <dt>case</dt><dd>{r.caseId ?? '—'}{r.caseId && <Pivot term={`case:${r.caseId}`} onAdd={addTerm} />}</dd>
                                </dl>
                                <div className="x1-row" style={{ marginTop: 10 }}>
                                  {r.caseId && <button type="button" className="btn primary" onClick={() => go('incident', { search: `?case=${encodeURIComponent(r.caseId as string)}` })}>Open the incident view</button>}
                                  <button type="button" className="btn ghost" onClick={() => around(r)}>Events 5 min either side{r.srcHost || r.dstHost ? ` on ${r.srcHost ?? r.dstHost}` : ''}</button>
                                  {r.user && <button type="button" className="btn ghost" onClick={() => submit(formatQuery([{ key: 'user', value: r.user as string, negate: false }]))}>All events for {r.user}</button>}
                                  {r.srcIp && INTERNAL.test(r.srcIp) && <button type="button" className="btn ghost" onClick={() => go('graph', { search: `?host=${encodeURIComponent(r.srcIp as string)}` })}>Show {r.srcHost ?? r.srcIp} on the graph</button>}
                                </div>
                              </div>
                              <div>
                                <h3 className="x1-muted" style={{ fontSize: 11, textTransform: 'uppercase', letterSpacing: '.6px', margin: '4px 0 8px' }}>Original record</h3>
                                <pre className="x1-pre">{JSON.stringify(r.raw, null, 2)}</pre>
                              </div>
                            </div>
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {rows.length > 0 && rows.length < total && (
            <button type="button" className="btn ghost" style={{ justifySelf: 'start' }} disabled={loading} onClick={more}>
              Show {Math.min(PAGE, total - rows.length).toLocaleString()} more of {(total - rows.length).toLocaleString()}
            </button>
          )}
          {!loading && !error && rows.length === 0 && (
            isEmptyStore && status ? (
              <SendLogs status={status} canSend={canSend} uploading={uploading} onPick={() => fileInput.current?.click()} />
            ) : (status || metaError) && (
              <p className="x1-muted" data-testid="logs-no-match">
                No events match{off.size ? ' with some sources hidden' : ''}, {spanLabel(ws, we, now)} UTC.
                {range.key !== 'fit' && <> <button type="button" className="x1-link" onClick={() => pickRange({ key: 'fit' })}>Find where it matches</button></>}
              </p>
            )
          )}
        </div>
      </div>
    </div>
  )
}
