/* /api/log-events: the routes behind Logs (core/log_events/log_events_router.py). */
import api from './api'

export interface LogRow {
  id: string
  time: string
  ts: number
  source: string
  class: string
  severity: string
  srcIp: string | null
  srcHost: string | null
  dstIp: string | null
  dstHost: string | null
  dstPort: number | null
  user: string | null
  action: string | null
  summary: string
  loglm: number | null
  mitre: string | null
  caseId: string | null
  tags: string[]
  raw: Record<string, unknown>
}

export interface LogResult {
  total: number
  events: LogRow[]
  bySource: Record<string, number>
  histogram: { counts: number[]; inCase: number[] }
  start: number
  end: number
  newest: number | null
}

export interface SearchArgs {
  q: string
  /** Sets the window to wherever the matches are. Otherwise start and end do. */
  fit?: boolean
  start?: number
  end?: number
  hide: string[]
  offset: number
  limit: number
  buckets: number
}

const toIso = (t?: number) => (t === undefined ? undefined : new Date(t).toISOString())

export async function searchLogs(a: SearchArgs, signal?: AbortSignal): Promise<LogResult> {
  const { data } = await api.get('/log-events/search', {
    signal,
    params: {
      q: a.q,
      fit: a.fit || undefined,
      start: a.fit ? undefined : toIso(a.start),
      end: a.fit ? undefined : toIso(a.end),
      hide: a.hide.length ? a.hide.join(',') : undefined,
      offset: a.offset,
      limit: a.limit,
      buckets: a.buckets,
    },
  })
  return {
    total: data.total,
    events: data.events,
    bySource: data.by_source,
    histogram: { counts: data.histogram.counts, inCase: data.histogram.in_case },
    start: Date.parse(data.start),
    end: Date.parse(data.end),
    newest: data.newest ? Date.parse(data.newest) : null,
  }
}

export interface LogSourceInfo {
  source: string
  label: string
  events: number
  first: string
  last: string
}

export async function logSources(): Promise<LogSourceInfo[]> {
  const { data } = await api.get<{ sources: LogSourceInfo[] }>('/log-events/sources')
  return data.sources
}

export interface LogStatus {
  total: number
  scored: number
  retention_days: number
  loglm: { configured: boolean; connected: boolean }
  shapes: string[]
  formats: string[]
  max_upload_mb: number
}

export async function logStatus(): Promise<LogStatus> {
  const { data } = await api.get<LogStatus>('/log-events/status')
  return data
}

export interface IngestReport {
  rows: number
  stored: number
  updated: number
  unchanged: number
  swept: number
  dropped: Record<string, number>
  notes: Record<string, number>
  shapes: Record<string, number>
  retention_days: number
}

export async function ingestLogs(file: File): Promise<IngestReport> {
  const form = new FormData()
  form.append('file', file)
  const { data } = await api.post<IngestReport>('/log-events/ingest', form, {
    headers: { 'Content-Type': 'multipart/form-data' },
    timeout: 0,
  })
  return data
}
