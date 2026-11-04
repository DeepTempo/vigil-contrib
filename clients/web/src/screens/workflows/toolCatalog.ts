// The tools an agent or a workflow step may be given, from GET /agents/custom/_meta/tools.
import { useEffect, useState } from 'react'
import { agentsApi } from '../../services/api'
import type { ToolChange } from '../../data/appData'

export interface CatalogTool {
  name: string
  /** "vigil" for Vigil's own tools, else the integration that serves it */
  server: string
  /** what the picker files it under: Findings, Cases… for Vigil's, the integration otherwise */
  group: string
  description: string
  changes: ToolChange
}

export interface ToolCatalog {
  phase: 'loading' | 'ready' | 'error'
  tools: CatalogTool[]
  byName: Map<string, CatalogTool>
}

// Integration keys as servers name themselves, said the way people say them.
const SERVER_LABEL: Record<string, string> = {
  vigil: 'Vigil',
  splunk: 'Splunk',
  crowdstrike: 'CrowdStrike',
  cs: 'CrowdStrike',
  okta: 'Okta',
  entra: 'Microsoft Entra ID',
  'azure-ad': 'Microsoft Entra ID (Azure AD)',
  azuread: 'Microsoft Entra ID (Azure AD)',
  'microsoft-defender': 'Microsoft Defender',
  'palo-alto': 'Palo Alto NGFW',
  'splunk-selfhosted': 'Splunk',
  'splunk-cloud': 'Splunk Cloud',
  'security-detections': 'Security detections',
  gcp: 'GCP',
  m365: 'Microsoft 365',
  o365: 'Microsoft 365',
  'microsoft-365': 'Microsoft 365',
  zeek: 'Zeek',
  defender: 'Microsoft Defender',
  sentinel: 'Microsoft Sentinel',
  jira: 'Jira',
  slack: 'Slack',
  servicenow: 'ServiceNow',
  virustotal: 'VirusTotal',
  vt: 'VirusTotal',
  opencti: 'OpenCTI',
  cf: 'Cloudflare',
  cloudflare: 'Cloudflare',
  vstrike: 'vStrike',
  cape: 'CAPE sandbox',
  ha: 'Hybrid Analysis',
  anyrun: 'ANY.RUN',
  url: 'URL analysis',
  paloalto: 'Palo Alto NGFW',
  panos: 'Palo Alto NGFW',
  aws: 'AWS',
  elastic: 'Elastic',
  wazuh: 'Wazuh',
  github: 'GitHub',
  atomic: 'Atomic Red Team',
  loglm: 'DeepTempo LogLM',
  deeptempo: 'DeepTempo LogLM',
}

// Words a server key may hold that people write in capitals.
const ACRONYM = new Set(['ad', 'aws', 'gcp', 'm365', 'o365', 'ngfw', 'edr', 'xdr', 'siem', 'api', 'ip', 'dns', 'ids', 'mdm', 'sso', 'iam', 'ti'])

export function serverLabel(server: string): string {
  const key = server.toLowerCase()
  if (SERVER_LABEL[key]) return SERVER_LABEL[key]
  return key
    .split(/[-_]/)
    .map((w) => (ACRONYM.has(w) ? w.toUpperCase() : w.charAt(0).toUpperCase() + w.slice(1)))
    .join(' ')
}

/** A tool's name without its server prefix, for reading: "splunk_search" → "search". */
export function shortName(t: Pick<CatalogTool, 'name' | 'server'>): string {
  const prefix = `${t.server}_`
  return t.server !== 'vigil' && t.name.startsWith(prefix) ? t.name.slice(prefix.length) : t.name
}

interface ApiCatalogRow { name: string; server?: string; group?: string; description?: string; changes?: ToolChange }

export function catalogFrom(data: unknown): CatalogTool[] {
  const rows = (data as { catalog?: ApiCatalogRow[] } | null | undefined)?.catalog
  return (Array.isArray(rows) ? rows : [])
    .filter((r) => r && typeof r.name === 'string')
    .map((r) => ({
      name: r.name,
      server: r.server || 'vigil',
      // integrations name their group by their server key: say it the way people do
      group: r.group && r.group !== r.server ? r.group : serverLabel(r.server || 'vigil'),
      description: r.description || '',
      changes: r.changes ?? 'read_only',
    }))
}

const LOADING: ToolCatalog = { phase: 'loading', tools: [], byName: new Map() }
const FAILED: ToolCatalog = { phase: 'error', tools: [], byName: new Map() }

/** Read when an editor opens and each time the window regains focus, so an integration connected
 *  in Settings or another tab is offered without a reload. A failed re-read keeps the list held. */
export function useToolCatalog(): ToolCatalog {
  const [state, setState] = useState<ToolCatalog>(LOADING)
  useEffect(() => {
    let cancelled = false
    const read = () => {
      Promise.resolve()
        .then(() => agentsApi.getAvailableTools())
        .then((r) => {
          if (cancelled) return
          const tools = catalogFrom(r?.data)
          setState({ phase: 'ready', tools, byName: new Map(tools.map((t) => [t.name, t])) })
        })
        .catch(() => { if (!cancelled) setState((held) => (held.phase === 'ready' ? held : FAILED)) })
    }
    read()
    window.addEventListener('focus', read)
    return () => { cancelled = true; window.removeEventListener('focus', read) }
  }, [])
  return state
}
