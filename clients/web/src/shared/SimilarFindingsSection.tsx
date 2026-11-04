// Recent alerts that look like this one, under a finding's details.
import { useEffect, useState } from 'react'
import { findingsApi, type SimilarFinding } from '../services/api'

export default function SimilarFindingsSection({ findingId }: { findingId: string }) {
  const [similar, setSimilar] = useState<SimilarFinding[]>([])

  useEffect(() => {
    let cancelled = false
    setSimilar([])
    findingsApi.similar(findingId, 5)
      .then((r) => { if (!cancelled) setSimilar(r.data.similar) })
      .catch(() => {})
    return () => { cancelled = true }
  }, [findingId])

  if (similar.length === 0) return null
  return (
    <section className="fd-sec">
      <h4>Similar alerts</h4>
      <ul className="fd-sim">
        {similar.map((s) => (
          <li key={s.finding_id}>
            <span className="fd-sim-t" title={s.finding_id}>{s.title || s.finding_id}</span>
            <span className="fd-muted">{s.reasons.join(' · ')}</span>
          </li>
        ))}
      </ul>
    </section>
  )
}
