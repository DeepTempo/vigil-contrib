// What the Logs screen keeps in its URL and browser: the query language as a person
// reads it, time ranges, saved searches, and the CSV of the loaded rows.
import type { IngestReport, LogRow } from '../../services/logsApi'

export interface Term { key: string | null; value: string; negate: boolean; op?: string }

export const KEYS = ['source', 'host', 'ip', 'user', 'port', 'case', 'mitre', 'sev', 'class', 'action', 'id']

/** Read a search the way the server does: "quoted phrases", key:value, -exclude, key:a,b, loglm>0.7. */
export function parseQuery(q: string): Term[] {
  const out: Term[] = []
  const re = /(-?)(?:([a-z]+):)?(?:"([^"]*)"|(\S+))/gi
  for (const m of q.matchAll(re)) {
    const negate = m[1] === '-'
    const raw = m[3] ?? m[4] ?? ''
    const key = m[2]?.toLowerCase() ?? null
    if (!key) {
      const score = raw.match(/^loglm([<>]=?)([\d.]+)$/i)
      if (score) { out.push({ key: 'loglm', value: score[2], negate, op: score[1] }); continue }
    }
    if (!raw) continue
    if (key && !KEYS.includes(key)) out.push({ key: null, value: `${key}:${raw}`, negate })
    else out.push({ key, value: raw, negate })
  }
  return out
}

/** Write terms back as a search, so one filter can be taken out. */
export function formatQuery(terms: Term[]): string {
  return terms
    .map((t) => {
      if (t.key === 'loglm') return `${t.negate ? '-' : ''}loglm${t.op ?? '>='}${t.value}`
      const v = /\s/.test(t.value) ? `"${t.value}"` : t.value
      return `${t.negate ? '-' : ''}${t.key ? `${t.key}:` : ''}${v}`
    })
    .join(' ')
}

const KEY_WORD: Record<string, string> = { source: 'source', host: 'host', ip: 'IP', user: 'user', port: 'port', case: 'case', mitre: 'technique', sev: 'severity', class: 'class', action: 'action', id: 'event' }
const OP_WORD: Record<string, string> = { '>': '>', '<': '<', '<=': '≤', '>=': '≥' }

/** "host is wks-1", "not entra", "unusual ≥ 0.9": a term as a person reads it. */
export function termLabel(t: Term): string {
  if (t.key === 'loglm') return `${t.negate ? 'not ' : ''}unusual ${OP_WORD[t.op ?? '>=']} ${t.value}`
  if (!t.key) {
    const v = t.value.includes(',') && !/\s/.test(t.value) ? t.value.split(',').filter(Boolean).map((x) => `“${x}”`).join(' or ') : `“${t.value}”`
    return t.negate ? `without ${v}` : v
  }
  return `${KEY_WORD[t.key]} ${t.negate ? 'is not' : 'is'} ${t.value.split(',').join(' or ')}`
}

// ── Time ranges ──────────────────────────────────────────────────────────────

export type RangeKey = '15m' | '1h' | '4h' | '24h' | '7d' | 'fit' | 'custom'
export interface Range { key: RangeKey; start?: number; end?: number }

const MIN = 60_000
export const DAY = 1440 * MIN
export const RANGES: { key: RangeKey; label: string; ms?: number }[] = [
  { key: '15m', label: 'Last 15 minutes', ms: 15 * MIN },
  { key: '1h', label: 'Last hour', ms: 60 * MIN },
  { key: '4h', label: 'Last 4 hours', ms: 240 * MIN },
  { key: '24h', label: 'Last 24 hours', ms: DAY },
  { key: '7d', label: 'Last 7 days', ms: 7 * DAY },
  { key: 'fit', label: 'Wherever it matches' },
  { key: 'custom', label: 'Custom' },
]

export const isRelative = (r: Range) => r.key !== 'fit' && r.key !== 'custom'

/** The range as start and end times, now. A fitted range's times come from the server. */
export function windowOf(r: Range, now = Date.now()): [number, number] {
  if (r.key === 'custom') return [r.start ?? now - DAY, r.end ?? now]
  const ms = RANGES.find((x) => x.key === r.key)?.ms ?? DAY
  return [now - ms, now]
}

// ── The URL ──────────────────────────────────────────────────────────────────

/** A link naming a search and no range means "wherever it matches", so it never lands on an empty day. */
const defaultRange = (q: string) => (q ? 'fit' : '24h')

/** The search a URL asks for. /logs?case=<id> is the search case:<id>. */
export function queryFromParams(params: URLSearchParams): string {
  const q = params.get('q') ?? ''
  const caseId = params.get('case')
  if (!caseId) return q
  const term = formatQuery([{ key: 'case', value: caseId, negate: false }])
  return q ? `${term} ${q}` : term
}

export function rangeFromParams(params: URLSearchParams, q: string): Range {
  const v = params.get('range') ?? defaultRange(q)
  const custom = v.match(/^(\d+)-(\d+)$/)
  if (custom) return { key: 'custom', start: Number(custom[1]), end: Number(custom[2]) }
  return RANGES.some((r) => r.key === v && v !== 'custom') ? { key: v as RangeKey } : { key: '24h' }
}

export function paramsFor(q: string, r: Range): Record<string, string> {
  const range = r.key === 'custom' ? `${r.start}-${r.end}` : r.key
  return { ...(q ? { q } : {}), ...(range === defaultRange(q) ? {} : { range }) }
}

// ── Saved searches ───────────────────────────────────────────────────────────

export interface SavedSearch { label: string; q: string }

/** Ready-made, reading only the vocabulary the normalizer writes. */
export const STARTER_SEARCHES: SavedSearch[] = [
  { label: 'All events', q: '' },
  { label: 'Unusual per LogLM (≥ 0.7)', q: 'loglm>=0.7' },
  { label: 'High and critical', q: 'sev:high,critical' },
  { label: 'Failed logons and sign-ins', q: 'action:logon_failed,signin_failed' },
  { label: 'Process starts', q: 'action:process_start' },
  { label: 'Firewall denies', q: 'source:paloalto action:deny,drop,reset-both' },
  { label: 'DNS queries', q: 'source:dns' },
]

const savedKey = (userId: string) => `vigil.logs.saved.${userId}`

export function loadSaved(userId: string): SavedSearch[] {
  try {
    const parsed: unknown = JSON.parse(localStorage.getItem(savedKey(userId)) ?? '[]')
    if (!Array.isArray(parsed)) return []
    return parsed.filter((s): s is SavedSearch => typeof s?.label === 'string' && typeof s?.q === 'string')
  } catch {
    return []
  }
}

export function storeSaved(userId: string, saved: SavedSearch[]): void {
  localStorage.setItem(savedKey(userId), JSON.stringify(saved))
}

// ── Words ────────────────────────────────────────────────────────────────────

const DROP_WORDS: Record<string, string> = {
  no_time: 'had no time Vigil could read',
  not_parseable: 'could not be read',
  not_object: 'were not an object',
  too_large: 'were too large',
  past_retention: 'were past retention',
  future_time: 'were dated in the future',
}
const NOTE_WORDS: Record<string, string> = {
  bad_score: 'had a LogLM score outside 0 to 1, so it was left out',
  unknown_case: 'named a case that does not exist, so they are not linked',
}

/** What an upload did, whole, including every row it left out. */
export function reportLine(name: string, r: IngestReport): string {
  const counted = (words: Record<string, string>, counts: Record<string, number>) =>
    Object.entries(counts).map(([k, n]) => `${n.toLocaleString()} ${words[k] ?? k}`)
  const done = [`${r.stored.toLocaleString()} stored`]
  if (r.updated) done.push(`${r.updated.toLocaleString()} updated`)
  if (r.unchanged) done.push(`${r.unchanged.toLocaleString()} already here`)
  const dropped = counted(DROP_WORDS, r.dropped)
  const notes = counted(NOTE_WORDS, r.notes)
  return [
    `${name}: ${r.rows.toLocaleString()} rows, ${done.join(', ')}.`,
    dropped.length ? `Dropped: ${dropped.join(', ')}.` : '',
    notes.length ? `Also: ${notes.join(', ')}.` : '',
  ].filter(Boolean).join(' ')
}

// ── CSV ──────────────────────────────────────────────────────────────────────

/** The loaded rows as CSV, for a spreadsheet or a ticket. */
export function toCsv(rows: LogRow[]): string {
  const cols: (keyof LogRow)[] = ['time', 'source', 'class', 'severity', 'srcIp', 'srcHost', 'dstIp', 'dstHost', 'dstPort', 'user', 'action', 'summary', 'loglm', 'mitre', 'caseId', 'id']
  const cell = (v: unknown) => {
    let s = v === null || v === undefined ? '' : String(v)
    // log text comes from the attacker's side: a cell starting =, +, - or @ would run as a formula in a spreadsheet
    if (typeof v === 'string' && /^[=+\-@\t\r]/.test(s)) s = `'${s}`
    return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s
  }
  return [cols.join(','), ...rows.map((r) => cols.map((c) => cell(r[c])).join(','))].join('\n')
}
