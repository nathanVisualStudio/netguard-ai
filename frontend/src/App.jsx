import { useEffect, useState } from 'react'
import { localNetwork, runScan, savePdf, waitForService } from './api'

const SEVERITIES = ['critical', 'high', 'medium', 'low']

function Tag({ level }) {
  return <span className={`tag ${level}`}>{level}</span>
}

function Section({ number, title, children }) {
  return (
    <section className="block">
      <h2>
        <span className="num">{number}</span>
        {title}
      </h2>
      {children}
    </section>
  )
}

function Host({ host, open }) {
  const { risk } = host
  const confidence = Math.round(risk.probabilities[risk.level] * 100)
  return (
    <details className="host" open={open}>
      <summary>
        <span className="ip">{host.ip}</span>
        <Tag level={risk.level} />
        <span className="score-small">{risk.score}/100</span>
        <span className="muted">{host.open_count} open</span>
      </summary>
      <div className="host-body">
        <table>
          <thead>
            <tr>
              <th>Port</th>
              <th>Service</th>
              <th>Banner</th>
            </tr>
          </thead>
          <tbody>
            {host.ports.map((p) => (
              <tr key={p.port}>
                <td className="mono">{p.port}/tcp</td>
                <td>{p.service}</td>
                <td className="mono dim">{(p.banner || '').split(/\r?\n/)[0].slice(0, 110)}</td>
              </tr>
            ))}
          </tbody>
        </table>
        <p className="factors">
          Model confidence for {risk.level}: {confidence}%.{' '}
          {risk.factors.map((f) => `${f.factor} (+${f.impact})`).join(', ')}.
        </p>
        {host.findings.map((f, i) => (
          <div className={`finding ${f.severity}`} key={i}>
            <h3>
              <Tag level={f.severity} /> {f.title}
              {f.cve && <span className="mono cve">{f.cve}</span>}
            </h3>
            <p>{f.description}</p>
            <ul>
              {f.remediation.map((step) => (
                <li key={step}>{step}</li>
              ))}
            </ul>
          </div>
        ))}
      </div>
    </details>
  )
}

function Report({ report }) {
  const [saving, setSaving] = useState(false)
  const counts = report.finding_counts

  async function save() {
    setSaving(true)
    try {
      await savePdf(report.id)
    } finally {
      setSaving(false)
    }
  }

  return (
    <>
      <Section number="01" title="Assessment">
        <div className="assessment">
          <div className={`bignum ${report.risk.level}`}>
            {report.risk.score}
            <small>/100</small>
          </div>
          <div>
            <div className={`level ${report.risk.level}`}>{report.risk.level}</div>
            <p className="narrative">{report.narrative}</p>
            <p className="counts">
              {SEVERITIES.map((s) => (
                <span key={s}>
                  <i className={`dot ${s}`} />
                  {counts[s]} {s}
                </span>
              ))}
            </p>
            <button className="primary" onClick={save} disabled={saving}>
              {saving ? 'Preparing…' : 'Save PDF report'}
            </button>
          </div>
        </div>
      </Section>

      {report.top_actions.length > 0 && (
        <Section number="02" title="What to fix first">
          <ol className="actions">
            {report.top_actions.map((a, i) => (
              <li key={i}>
                <Tag level={a.severity} />
                <span>{a.action}</span>
                <span className="mono dim">
                  {a.host}:{a.port}
                </span>
              </li>
            ))}
          </ol>
        </Section>
      )}

      {report.hosts.length > 0 && (
        <Section number="03" title="Hosts">
          {report.hosts.map((h, i) => (
            <Host host={h} open={i === 0} key={h.ip} />
          ))}
        </Section>
      )}
    </>
  )
}

export default function App() {
  const [phase, setPhase] = useState('booting')
  const [target, setTarget] = useState('127.0.0.1')
  const [ports, setPorts] = useState('top')
  const [report, setReport] = useState(null)
  const [error, setError] = useState('')

  useEffect(() => {
    waitForService()
      .then(() => setPhase('idle'))
      .catch(() => {
        setError('The scan service did not start. Check that Python 3.10+ and service/requirements.txt are installed.')
        setPhase('failed')
      })
  }, [])

  async function detect() {
    try {
      setTarget(await localNetwork())
    } catch (err) {
      setError(err.message)
    }
  }

  async function submit(event) {
    event.preventDefault()
    setError('')
    setPhase('scanning')
    try {
      setReport(await runScan(target, ports.trim() || 'top'))
    } catch (err) {
      setError(err.message)
    }
    setPhase('idle')
  }

  const busy = phase === 'booting' || phase === 'scanning' || phase === 'failed'

  return (
    <div className="shell">
      <aside className="side">
        <div className="mark">
          netguard<em>ai</em>
        </div>
        <p className="tagline">Port scan, risk score, and a plan to close the gaps.</p>
        <form onSubmit={submit}>
          <label htmlFor="target">Target</label>
          <input id="target" value={target} onChange={(e) => setTarget(e.target.value)} spellCheck="false" required />
          <button type="button" className="link" onClick={detect} disabled={busy}>
            use my network
          </button>
          <label htmlFor="ports">Ports</label>
          <input id="ports" value={ports} onChange={(e) => setPorts(e.target.value)} spellCheck="false" />
          <p className="hint">top, 22,80,443 or 1-1024</p>
          <button type="submit" className="primary wide" disabled={busy}>
            {phase === 'scanning' ? 'Scanning…' : 'Run scan'}
          </button>
        </form>
        <p className="warn">
          Only scan networks and machines you own or have written permission to test. Unauthorised scanning can be illegal.
        </p>
      </aside>
      <main className="main">
        {error && <div className="error">{error}</div>}
        {phase === 'booting' && <p className="empty">Starting the scan service…</p>}
        {phase === 'scanning' && <p className="empty">Scanning and scoring. Wide ranges can take a little while.</p>}
        {phase === 'idle' && !report && !error && (
          <p className="empty">Pick a target on the left and run a scan. Your report will show up here.</p>
        )}
        {report && phase !== 'booting' && <Report report={report} key={report.id} />}
      </main>
    </div>
  )
}
