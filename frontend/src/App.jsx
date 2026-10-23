import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  Activity, AlertCircle, ArrowDownToLine, ArrowRight, ArrowUpRight, BadgeCheck,
  BarChart3, Bell, ChevronDown, ChevronRight, CircleHelp, Clock3, Command,
  Download, ExternalLink, FileJson, FileSpreadsheet, FileText, Globe2, History,
  LayoutDashboard, LoaderCircle, LockKeyhole, Menu, Radar, RefreshCw, Search,
  Shield, ShieldAlert, ShieldCheck, ShieldEllipsis, ShieldHalf, SlidersHorizontal,
  Sparkles, Target, X, Zap
} from 'lucide-react'
import {
  Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis
} from 'recharts'

const API = import.meta.env.VITE_API_URL || ''
const fmtDate = (value) => {
  if (!value) return '—'
  const d = new Date(value)
  return Number.isNaN(d.getTime()) ? value : d.toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' })
}
const scoreColor = (score) => score >= 90 ? 'mint' : score >= 75 ? 'blue' : score >= 50 ? 'amber' : 'red'
const sevClass = (s = '') => s.toLowerCase() === 'high' ? 'high' : s.toLowerCase() === 'medium' ? 'medium' : s.toLowerCase() === 'low' ? 'low' : 'info'
const shortHost = (url = '') => {
  try { return new URL(url).hostname } catch { return url }
}

async function api(path, options = {}) {
  const response = await fetch(`${API}${path}`, {
    ...options,
    headers: { ...(options.body ? { 'Content-Type': 'application/json' } : {}), ...options.headers }
  })
  if (!response.ok) {
    let message = `Request failed (${response.status})`
    try { const data = await response.json(); message = data.detail || message } catch {}
    throw new Error(message)
  }
  return response
}
async function getJSON(path) {
  const r = await api(path)
  return r.json()
}
async function downloadFile(path, fallbackName) {
  const response = await api(path)
  const blob = await response.blob()
  const disposition = response.headers.get('Content-Disposition') || ''
  const match = disposition.match(/filename="?([^";]+)"?/i)
  const name = match?.[1] || fallbackName
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url; a.download = name; document.body.appendChild(a); a.click(); a.remove()
  URL.revokeObjectURL(url)
}

function ScoreRing({ score }) {
  const safe = Math.max(0, Math.min(100, Number(score ?? 0)))
  const circumference = 2 * Math.PI * 43
  const color = safe >= 90 ? '#42e0b5' : safe >= 75 ? '#61a8ff' : safe >= 50 ? '#ffbd66' : '#ff727d'
  return <div className="score-ring">
    <svg viewBox="0 0 108 108" role="img" aria-label={`Security score ${safe} out of 100`}>
      <circle cx="54" cy="54" r="43" className="ring-track" />
      <circle cx="54" cy="54" r="43" className="ring-progress"
        stroke={color} strokeDasharray={`${circumference * safe / 100} ${circumference}`}
        transform="rotate(-90 54 54)" />
    </svg>
    <div className="ring-label"><strong>{safe}</strong><span>out of 100</span></div>
  </div>
}

function SeverityPill({ value }) {
  return <span className={`severity-pill ${sevClass(value)}`}><i />{value || 'Informational'}</span>
}

function StatusPill({ value }) {
  const kind = value === 'Completed' || value === 'Present' || value === 'Passed' ? 'status-good'
    : value === 'Failed' || value === 'Rejected' || value === 'Missing' ? 'status-bad'
    : value === 'Review' ? 'status-warn' : 'status-neutral'
  return <span className={`status-pill ${kind}`}>{value || 'Unknown'}</span>
}

function Sidebar({ page, setPage, mobileOpen, setMobileOpen }) {
  const items = [
    { id: 'overview', label: 'Overview', icon: LayoutDashboard },
    { id: 'scan', label: 'New scan', icon: Radar },
    { id: 'history', label: 'Scan history', icon: History }
  ]
  return <>
    {mobileOpen && <button className="mobile-scrim" aria-label="Close menu" onClick={() => setMobileOpen(false)} />}
    <aside className={`sidebar ${mobileOpen ? 'sidebar-open' : ''}`}>
      <div className="brand">
        <div className="brand-mark"><Shield size={22} strokeWidth={2.2} /><span /></div>
        <div><div className="brand-name">secure<span>scope</span></div><div className="brand-sub">SECURITY COMMAND CENTER</div></div>
        <button className="icon-button sidebar-close" onClick={() => setMobileOpen(false)} aria-label="Close navigation"><X size={18}/></button>
      </div>
      <div className="workspace-switch">
        <div className="workspace-avatar"><LockKeyhole size={17}/></div>
        <div className="workspace-copy"><strong>Personal workspace</strong><span>Local environment</span></div>
        <ChevronDown size={15} className="muted"/>
      </div>
      <div className="nav-label">WORKSPACE</div>
      <nav className="main-nav">
        {items.map(({ id, label, icon: Icon }) => <button key={id} className={`nav-item ${page === id ? 'active' : ''}`}
          onClick={() => { setPage(id); setMobileOpen(false) }}>
          <Icon size={18}/><span>{label}</span>{id === 'scan' && <span className="nav-new">NEW</span>}
        </button>)}
      </nav>
      <div className="nav-label nav-label-tools">TOOLS</div>
      <div className="nav-item nav-static"><BarChart3 size={18}/><span>Security insights</span><span className="coming-soon">Soon</span></div>
      <div className="nav-item nav-static"><SlidersHorizontal size={18}/><span>Configuration</span></div>
      <div className="sidebar-spacer" />
      <div className="sidebar-note">
        <div className="note-icon"><ShieldCheck size={17}/></div>
        <strong>Scan responsibly</strong>
        <p>Only assess websites you own or are explicitly authorized to test.</p>
      </div>
      <div className="profile">
        <div className="profile-avatar">LG</div>
        <div className="profile-copy"><strong>Laksh Garg</strong><span>Project workspace</span></div>
        <button className="icon-button" aria-label="Workspace options"><ChevronDown size={16}/></button>
      </div>
    </aside>
  </>
}

function Header({ page, onMenu, onRefresh }) {
  const names = { overview: ['Overview', 'Monitor your website security posture.'], scan: ['New security scan', 'Run a lightweight configuration audit.'], history: ['Scan history', 'Review previous scans and export reports.'] }
  const [title, subtitle] = names[page] || names.overview
  return <header className="topbar">
    <div className="topbar-left">
      <button className="icon-button mobile-menu" onClick={onMenu} aria-label="Open navigation"><Menu size={20}/></button>
      <div className="breadcrumb"><span>Workspace</span><ChevronRight size={14}/><strong>{title}</strong></div>
    </div>
    <div className="topbar-right">
      <div className="system-status"><span className="live-dot"/><span>API status</span><strong>LOCAL</strong></div>
      <button className="icon-button" title="Refresh data" onClick={onRefresh}><RefreshCw size={17}/></button>
      <div className="topbar-avatar">LG</div>
    </div>
  </header>
}

function PageIntro({ eyebrow, title, subtitle, action }) {
  return <div className="page-intro">
    <div><div className="eyebrow">{eyebrow}</div><h1>{title}</h1><p>{subtitle}</p></div>
    {action && <div className="intro-action">{action}</div>}
  </div>
}

function StatCard({ icon: Icon, label, value, hint, tone = 'blue' }) {
  return <div className="stat-card">
    <div className={`stat-icon ${tone}`}><Icon size={19}/></div>
    <div className="stat-body"><span className="stat-label">{label}</span><strong className="stat-value">{value}</strong><span className="stat-hint">{hint}</span></div>
    <div className={`stat-accent ${tone}`}/>
  </div>
}

function EmptyState({ icon: Icon = Radar, title, text, button, onClick }) {
  return <div className="empty-state"><div className="empty-icon"><Icon size={25}/></div><h3>{title}</h3><p>{text}</p>{button && <button className="button button-primary" onClick={onClick}>{button}<ArrowRight size={16}/></button>}</div>
}

function FindingTable({ findings }) {
  if (!findings?.length) return <div className="empty-inline">No findings to display.</div>
  return <div className="table-wrap"><table className="findings-table">
    <thead><tr><th>CHECK</th><th>SEVERITY</th><th>STATUS</th><th>EVIDENCE</th><th>RECOMMENDATION</th></tr></thead>
    <tbody>{findings.map((f, i) => <tr key={`${f.check}-${i}`}>
      <td><div className="check-name"><span className={`check-dot ${sevClass(f.severity)}`}/><strong>{f.check}</strong></div></td>
      <td><SeverityPill value={f.severity}/></td><td><StatusPill value={f.status}/></td>
      <td className="evidence-cell">{f.evidence || '—'}</td><td className="recommendation-cell">{f.recommendation || '—'}</td>
    </tr>)}</tbody>
  </table></div>
}

function Overview({ scans, loading, error, onNewScan, onSelectScan, onRefresh }) {
  const completed = scans.filter(s => s.status === 'Completed' && s.score !== null)
  const latest = completed[0]
  const avg = completed.length ? Math.round(completed.reduce((sum, s) => sum + s.score, 0) / completed.length) : null
  const riskTotals = scans.reduce((acc, s) => {
    Object.entries(s.risk || {}).forEach(([k, v]) => { acc[k] = (acc[k] || 0) + Number(v || 0) })
    return acc
  }, { High: 0, Medium: 0, Low: 0, Informational: 0 })
  const trend = [...completed].reverse().map((s, i) => ({ scan: `#${s.id}`, score: s.score, label: shortHost(s.target), date: fmtDate(s.scanned_at) }))
  const recent = scans.slice(0, 5)
  return <div className="page-content">
    <PageIntro eyebrow="SECURITY OVERVIEW" title="Good morning, Laksh." subtitle="Here's the latest view of your website security posture."
      action={<button className="button button-primary" onClick={onNewScan}><Radar size={17}/> Run a new scan</button>}/>
    {error && <div className="alert alert-error"><AlertCircle size={18}/>{error}</div>}
    <div className="notice-bar"><div className="notice-symbol"><ShieldCheck size={18}/></div><div><strong>Authorized scanning only</strong><span>SecureScope checks selected public HTTP response signals. It is not a penetration-testing tool.</span></div><button className="notice-link" onClick={() => window.open('https://owasp.org/www-project-web-security-testing-guide/', '_blank', 'noopener,noreferrer')}>Learn more <ArrowUpRight size={14}/></button></div>
    <div className="stats-grid">
      <StatCard icon={Activity} label="Total scans" value={scans.length} hint="Saved in local history" tone="blue"/>
      <StatCard icon={ShieldCheck} label="Average score" value={avg === null ? '—' : `${avg}/100`} hint={avg === null ? 'Run a scan to calculate' : 'Across completed scans'} tone="mint"/>
      <StatCard icon={ShieldAlert} label="High severity" value={riskTotals.High} hint="Across recorded scan findings" tone="red"/>
      <StatCard icon={Globe2} label="Targets assessed" value={new Set(scans.map(s => s.target)).size} hint="Unique target URLs" tone="violet"/>
    </div>
    <div className="overview-grid">
      <section className="panel trend-panel">
        <div className="panel-heading"><div><h2>Security score trend</h2><p>Scores from completed scans, oldest to newest.</p></div><button className="icon-button" onClick={onRefresh} title="Refresh trend"><RefreshCw size={16}/></button></div>
        {trend.length > 1 ? <div className="chart-box"><ResponsiveContainer width="100%" height="100%"><AreaChart data={trend} margin={{ top: 10, right: 10, left: -18, bottom: 0 }}>
          <defs><linearGradient id="scoreFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#4b9cff" stopOpacity={0.26}/><stop offset="100%" stopColor="#4b9cff" stopOpacity={0}/></linearGradient></defs>
          <CartesianGrid stroke="#25334a" strokeDasharray="4 5" vertical={false}/>
          <XAxis dataKey="scan" tick={{ fill: '#8190a8', fontSize: 11 }} axisLine={false} tickLine={false}/>
          <YAxis domain={[0, 100]} tick={{ fill: '#8190a8', fontSize: 11 }} axisLine={false} tickLine={false}/>
          <Tooltip contentStyle={{ background: '#111c2e', border: '1px solid #2a3a53', borderRadius: 10, color: '#eaf0fa' }} formatter={(v) => [`${v}/100`, 'Score']} labelFormatter={(v) => `Scan ${v}`}/>
          <Area type="monotone" dataKey="score" stroke="#65aaff" strokeWidth={2.5} fill="url(#scoreFill)" activeDot={{ r: 5, fill: '#65aaff', stroke: '#0e1728', strokeWidth: 3 }}/>
        </AreaChart></ResponsiveContainer></div> : <div className="chart-empty"><div className="chart-empty-icon"><BarChart3 size={24}/></div><strong>{trend.length ? 'One scan recorded' : 'Your security trend starts here'}</strong><span>{trend.length ? 'Run another scan to compare scores over time.' : 'Run an authorized scan to start building your history.'}</span><button className="text-button" onClick={onNewScan}>Start a scan <ArrowRight size={15}/></button></div>}
        <div className="chart-foot"><span><i className="legend-line"/> Hardening score</span><span>Scale: 0–100</span></div>
      </section>
      <section className="panel latest-panel">
        <div className="panel-heading"><div><h2>Latest completed scan</h2><p>Most recent successful assessment.</p></div><span className="panel-icon"><Clock3 size={17}/></span></div>
        {latest ? <div className="latest-content">
          <div className="latest-target"><div className="target-icon"><Globe2 size={18}/></div><div><strong>{shortHost(latest.target)}</strong><span>{latest.target}</span></div><button className="icon-button" onClick={() => onSelectScan(latest.id)} title="Open scan"><ArrowUpRight size={17}/></button></div>
          <div className="score-block"><ScoreRing score={latest.score}/><div><span className="score-kicker">HARDENING SCORE</span><h3>{latest.scoreLabel || latest.score_label || (latest.score >= 75 ? 'Good configuration' : 'Improvements needed')}</h3><p>{fmtDate(latest.scanned_at)}</p></div></div>
          <div className="latest-risk-grid">{['High', 'Medium', 'Low', 'Informational'].map(s => <div key={s} className="mini-risk"><span className={`risk-mini-dot ${sevClass(s)}`}/><span>{s}</span><strong>{latest.risk?.[s] ?? 0}</strong></div>)}</div>
          <button className="button button-secondary full-width" onClick={() => onSelectScan(latest.id)}>View scan details <ArrowRight size={16}/></button>
        </div> : <EmptyState icon={ShieldHalf} title="No scan results yet" text="Run your first authorized scan to see a security score, findings, and remediation steps." button="Run first scan" onClick={onNewScan}/>}
      </section>
    </div>
    <section className="panel recent-panel">
      <div className="panel-heading"><div><h2>Recent activity</h2><p>Your latest scan records.</p></div><button className="text-button" onClick={() => onSelectScan('history')}>View all scans <ArrowRight size={15}/></button></div>
      {loading ? <div className="loading-line"><LoaderCircle className="spin" size={18}/> Loading scan history…</div> : recent.length ? <div className="table-wrap"><table className="recent-table">
        <thead><tr><th>TARGET</th><th>DATE</th><th>STATUS</th><th>SCORE</th><th>FINDINGS</th><th></th></tr></thead>
        <tbody>{recent.map(s => <tr key={s.id} onClick={() => onSelectScan(s.id)} className="clickable-row">
          <td><div className="recent-target"><div className="target-icon small"><Globe2 size={15}/></div><div><strong>{shortHost(s.target)}</strong><span>{s.target}</span></div></div></td>
          <td className="date-cell">{fmtDate(s.scanned_at)}</td><td><StatusPill value={s.status}/></td>
          <td>{s.score == null ? '—' : <span className={`table-score ${scoreColor(s.score)}`}>{s.score}<small>/100</small></span>}</td>
          <td><div className="finding-counts"><b className="high-text">{s.risk?.High || 0}</b><b className="medium-text">{s.risk?.Medium || 0}</b><b className="low-text">{s.risk?.Low || 0}</b></div></td>
          <td><ChevronRight size={16} className="muted"/></td>
        </tr>)}</tbody>
      </table></div> : <EmptyState icon={History} title="Nothing in your history" text="Completed and unsuccessful scan attempts are saved here for local review." button="Run a scan" onClick={onNewScan}/>}
    </section>
    <div className="disclaimer"><CircleHelp size={15}/><span>The hardening score is a heuristic indicator, not a probability of compromise. Missing headers do not automatically mean a site is vulnerable.</span></div>
  </div>
}

function ScanPage({ onScanSaved, onSelectScan }) {
  const [url, setUrl] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [result, setResult] = useState(null)
  const [activeTab, setActiveTab] = useState('findings')
  const runScan = async (e) => {
    e.preventDefault()
    setError(''); setResult(null)
    if (!url.trim()) { setError('Enter a URL to begin scanning.'); return }
    setBusy(true)
    try {
      const r = await api('/api/scans', { method: 'POST', body: JSON.stringify({ target_url: url.trim() }) })
      const data = await r.json()
      setResult(data)
      onScanSaved()
    } catch (err) { setError(err.message || 'Could not connect to the SecureScope API.') }
    finally { setBusy(false) }
  }
  const exportOne = async (format) => {
    if (!result) return
    try { await downloadFile(`/api/scans/${result.id}/export?format=${format}`, `securescope_${result.id}.${format}`) }
    catch (err) { setError(err.message) }
  }
  const risk = result?.risk_summary || {}
  const score = result?.security_score
  const plan = result?.remediation_plan || []
  return <div className="page-content">
    <PageIntro eyebrow="ASSESSMENT WORKSPACE" title="Run a security scan" subtitle="Inspect selected HTTP response signals on a website you are authorized to assess."/>
    <div className="scan-layout">
      <div className="scan-main">
        <section className="panel scan-form-panel">
          <div className="scan-form-title"><div className="big-panel-icon"><Radar size={22}/></div><div><h2>Target configuration</h2><p>Enter the full URL of the website to assess.</p></div><span className="safe-tag"><LockKeyhole size={13}/> TLS verification on</span></div>
          <form onSubmit={runScan}>
            <label className="field-label" htmlFor="target-url">TARGET URL</label>
            <div className={`url-input-wrap ${error ? 'input-error' : ''}`}><Globe2 size={18}/><input id="target-url" type="url" value={url} onChange={e => setUrl(e.target.value)} placeholder="https://example.com" autoComplete="url" disabled={busy}/><span className="input-shortcut">URL</span></div>
            {error && <div className="inline-error"><AlertCircle size={15}/>{error}</div>}
            <div className="input-hint"><ShieldCheck size={14}/> Public HTTP and HTTPS targets only. Local/private addresses are rejected by validation.</div>
            <button className="button button-primary scan-submit" type="submit" disabled={busy}>{busy ? <><LoaderCircle size={17} className="spin"/> Checking response headers…</> : <><Radar size={17}/> Start security scan <ArrowRight size={16}/></>}</button>
          </form>
          {busy && <div className="scan-progress"><div className="progress-shimmer"/><div><strong>Analyzing target response</strong><span>Validating destination, requesting headers, and preparing findings.</span></div></div>}
        </section>
        {result && <section className="results-section">
          <div className="results-title-row"><div><div className="eyebrow">SCAN #{result.id}</div><h2>Assessment results</h2><p>{result.target} · {fmtDate(result.scanned_at)}</p></div><StatusPill value={result.status}/></div>
          {result.error && <div className="alert alert-error"><AlertCircle size={18}/>{result.error}</div>}
          {result.status === 'Completed' && <>
            <div className="result-hero panel">
              <div className="result-score"><ScoreRing score={score}/><div><span className="score-kicker">SECURITY HARDENING SCORE</span><h2>{result.score_label}</h2><p>Based on configured deductions from 100. This is a heuristic, not a probability of compromise.</p></div></div>
              <div className="result-stat-grid">{['High', 'Medium', 'Low', 'Informational'].map(s => <div key={s} className={`result-stat ${sevClass(s)}`}><span>{s}</span><strong>{risk[s] || 0}</strong></div>)}</div>
            </div>
            <div className="panel result-details">
              <div className="tabs"><button className={activeTab === 'findings' ? 'selected' : ''} onClick={() => setActiveTab('findings')}>All findings <span>{result.findings.length}</span></button><button className={activeTab === 'remediation' ? 'selected' : ''} onClick={() => setActiveTab('remediation')}>Remediation plan <span>{plan.length}</span></button></div>
              {activeTab === 'findings' ? <FindingTable findings={result.findings}/> : plan.length ? <div className="remediation-list">{plan.map((item, i) => <div className="remediation-item" key={`${item.check}-${i}`}><div className="remediation-number">{String(i + 1).padStart(2, '0')}</div><div className="remediation-copy"><div className="remediation-heading"><strong>{item.check}</strong><SeverityPill value={item.severity}/></div><p className="remediation-evidence">{item.evidence}</p><p>{item.recommendation}</p></div></div>)}</div> : <div className="empty-inline">No missing-header or HTTP-only findings were selected for the remediation list.</div>}
            </div>
            <div className="export-panel panel"><div><h3><Download size={17}/> Export this assessment</h3><p>Download the findings for your project report or local records.</p></div><div className="export-actions">
              <button className="button button-secondary" onClick={() => exportOne('json')}><FileJson size={16}/> JSON</button>
              <button className="button button-secondary" onClick={() => exportOne('csv')}><FileSpreadsheet size={16}/> CSV</button>
              <button className="button button-primary" onClick={() => exportOne('pdf')}><FileText size={16}/> PDF report</button>
            </div></div>
          </>}
        </section>}
      </div>
      <aside className="scan-aside">
        <section className="panel side-info"><div className="side-info-icon"><ShieldCheck size={20}/></div><h3>What gets checked?</h3><p>SecureScope reviews a focused set of response signals to help you spot configuration gaps.</p>
          <div className="check-list"><div><span className="check-check"><LockKeyhole size={14}/></span><span><strong>HTTPS & TLS</strong><small>HTTPS usage and certificate validation</small></span></div><div><span className="check-check"><ShieldHalf size={14}/></span><span><strong>Security headers</strong><small>CSP, HSTS, framing, referrer and browser policies</small></span></div><div><span className="check-check"><Globe2 size={14}/></span><span><strong>CORS indicators</strong><small>Preliminary review of response headers</small></span></div><div><span className="check-check"><Zap size={14}/></span><span><strong>Remediation guidance</strong><small>Prioritized actions for selected findings</small></span></div></div>
        </section>
        <section className="panel side-warning"><div className="warning-heading"><ShieldAlert size={18}/><strong>Before you scan</strong></div><ul><li>Only scan websites you own or have permission to assess.</li><li>Redirects are not followed automatically.</li><li>Header presence does not prove a secure configuration.</li><li>Do not expose this scanner publicly without stronger network egress controls.</li></ul><a href="https://owasp.org/www-project-web-security-testing-guide/" target="_blank" rel="noreferrer">Read OWASP testing guidance <ExternalLink size={13}/></a></section>
        <div className="help-card"><div className="help-icon"><CircleHelp size={18}/></div><div><strong>Need a starting point?</strong><p>Use a site or test environment where you have explicit permission.</p></div></div>
      </aside>
    </div>
  </div>
}

function HistoryPage({ scans, loading, error, onRefresh, onSelectScan }) {
  const [query, setQuery] = useState('')
  const [filter, setFilter] = useState('all')
  const filtered = useMemo(() => scans.filter(s => {
    const matchesQuery = `${s.target} ${s.status} ${s.id}`.toLowerCase().includes(query.toLowerCase())
    return matchesQuery && (filter === 'all' || s.status.toLowerCase() === filter)
  }), [scans, query, filter])
  const exportHistory = () => downloadFile('/api/scans/export/history.csv', 'securescope_scan_history.csv').catch(() => {})
  return <div className="page-content">
    <PageIntro eyebrow="LOCAL RECORDS" title="Scan history" subtitle="Every scan attempt is recorded locally so you can revisit results and export reports."
      action={<button className="button button-secondary" onClick={exportHistory}><ArrowDownToLine size={16}/> Export history CSV</button>}/>
    {error && <div className="alert alert-error"><AlertCircle size={18}/>{error}</div>}
    <div className="history-summary stats-grid">
      <StatCard icon={History} label="Total records" value={scans.length} hint="Stored locally" tone="blue"/>
      <StatCard icon={BadgeCheck} label="Completed" value={scans.filter(s => s.status === 'Completed').length} hint="Successful HTTP responses" tone="mint"/>
      <StatCard icon={AlertCircle} label="Failed / rejected" value={scans.filter(s => ['Failed', 'Rejected'].includes(s.status)).length} hint="Review target or network" tone="amber"/>
      <StatCard icon={Target} label="Unique targets" value={new Set(scans.map(s => s.target)).size} hint="Distinct target URLs" tone="violet"/>
    </div>
    <section className="panel history-panel">
      <div className="history-toolbar"><div className="search-box"><Search size={17}/><input placeholder="Search target, status, or scan ID…" value={query} onChange={e => setQuery(e.target.value)}/>{query && <button onClick={() => setQuery('')} aria-label="Clear search"><X size={14}/></button>}</div><div className="filter-control"><SlidersHorizontal size={15}/><select value={filter} onChange={e => setFilter(e.target.value)} aria-label="Filter scan status"><option value="all">All statuses</option><option value="completed">Completed</option><option value="failed">Failed</option><option value="rejected">Rejected</option></select></div><button className="icon-button" onClick={onRefresh} title="Refresh"><RefreshCw size={16}/></button></div>
      {loading ? <div className="loading-line"><LoaderCircle className="spin" size={18}/> Loading scan history…</div> : filtered.length ? <div className="table-wrap"><table className="history-table">
        <thead><tr><th>SCAN</th><th>TARGET</th><th>DATE & TIME</th><th>STATUS</th><th>SCORE</th><th>FINDINGS</th><th></th></tr></thead>
        <tbody>{filtered.map(s => <tr key={s.id} className="clickable-row" onClick={() => onSelectScan(s.id)}>
          <td><span className="scan-id">#{String(s.id).padStart(4, '0')}</span></td><td><div className="recent-target"><div className="target-icon small"><Globe2 size={14}/></div><div><strong>{shortHost(s.target)}</strong><span>{s.target}</span></div></div></td>
          <td className="date-cell">{fmtDate(s.scanned_at)}</td><td><StatusPill value={s.status}/></td><td>{s.score == null ? '—' : <span className={`table-score ${scoreColor(s.score)}`}>{s.score}<small>/100</small></span>}</td>
          <td><div className="finding-counts"><b className="high-text">{s.risk?.High || 0}</b><b className="medium-text">{s.risk?.Medium || 0}</b><b className="low-text">{s.risk?.Low || 0}</b></div></td><td><ChevronRight size={16} className="muted"/></td>
        </tr>)}</tbody>
      </table></div> : <EmptyState icon={Search} title="No matching scan records" text="Try another search or clear the status filter."/>}
      <div className="table-footer"><span>Showing <strong>{filtered.length}</strong> of <strong>{scans.length}</strong> records</span><span>Local SQLite database</span></div>
    </section>
    <div className="disclaimer"><CircleHelp size={15}/><span>Scan history is stored on the backend machine. Do not commit the database file or share sensitive target information.</span></div>
  </div>
}

function ScanDetailModal({ scanId, onClose }) {
  const [record, setRecord] = useState(null)
  const [error, setError] = useState('')
  useEffect(() => {
    if (!scanId || scanId === 'history') return
    getJSON(`/api/scans/${scanId}`).then(setRecord).catch(e => setError(e.message))
  }, [scanId])
  if (!scanId || scanId === 'history') return null
  return <div className="modal-backdrop" onMouseDown={onClose}><div className="detail-modal" onMouseDown={e => e.stopPropagation()}>
    <div className="modal-header"><div><div className="eyebrow">SCAN RECORD</div><h2>Scan details</h2></div><button className="icon-button" onClick={onClose}><X size={18}/></button></div>
    {!record && !error ? <div className="loading-line"><LoaderCircle size={18} className="spin"/> Loading scan…</div> : error ? <div className="alert alert-error">{error}</div> : <>
      <div className="modal-target"><Globe2 size={18}/><div><strong>{record.target}</strong><span>{fmtDate(record.scanned_at)}</span></div><StatusPill value={record.status}/></div>
      {record.security_score != null && <div className="modal-score"><ScoreRing score={record.security_score}/><div><span className="score-kicker">HARDENING SCORE</span><h3>{record.score_label}</h3><p>HTTP status: {record.http_status ?? '—'}</p></div></div>}
      {record.error && <div className="alert alert-error">{record.error}</div>}
      <h3 className="modal-section-title">Findings</h3><FindingTable findings={record.findings}/>
      <div className="modal-export"><button className="button button-secondary" onClick={() => downloadFile(`/api/scans/${record.id}/export?format=json`, `securescope_${record.id}.json`)}><FileJson size={15}/> JSON</button><button className="button button-secondary" onClick={() => downloadFile(`/api/scans/${record.id}/export?format=csv`, `securescope_${record.id}.csv`)}><FileSpreadsheet size={15}/> CSV</button><button className="button button-primary" onClick={() => downloadFile(`/api/scans/${record.id}/export?format=pdf`, `securescope_${record.id}.pdf`)}><FileText size={15}/> PDF</button></div>
    </>}
  </div></div>
}

export default function App() {
  const [page, setPage] = useState('overview')
  const [mobileOpen, setMobileOpen] = useState(false)
  const [scans, setScans] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [selectedScan, setSelectedScan] = useState(null)
  const [apiOnline, setApiOnline] = useState(null)

  const refresh = useCallback(async () => {
    setLoading(true); setError('')
    try {
      const [rows] = await Promise.all([getJSON('/api/scans?limit=100'), getJSON('/api/health').then(() => setApiOnline(true))])
      setScans(rows)
    } catch (err) {
      setApiOnline(false)
      setError(`${err.message}. Make sure the FastAPI backend is running on port 8000.`)
    } finally { setLoading(false) }
  }, [])
  useEffect(() => { refresh() }, [refresh])

  const selectScan = (id) => {
    if (id === 'history') { setPage('history'); return }
    setSelectedScan(id)
  }

  return <div className="app-shell">
    <Sidebar page={page} setPage={setPage} mobileOpen={mobileOpen} setMobileOpen={setMobileOpen}/>
    <main className="main-area">
      <Header page={page} onMenu={() => setMobileOpen(true)} onRefresh={refresh}/>
      <div className="api-banner-wrap">{apiOnline === false && <div className="api-offline"><AlertCircle size={15}/><span>API disconnected — start the backend to load scan data.</span></div>}</div>
      {page === 'overview' && <Overview scans={scans} loading={loading} error={error} onNewScan={() => setPage('scan')} onSelectScan={selectScan} onRefresh={refresh}/>}
      {page === 'scan' && <ScanPage onScanSaved={refresh} onSelectScan={selectScan}/>}
      {page === 'history' && <HistoryPage scans={scans} loading={loading} error={error} onRefresh={refresh} onSelectScan={selectScan}/>}
      <footer className="app-footer"><div><span className="footer-brand"><Shield size={14}/> SecureScope</span><span>Security configuration insights, made clearer.</span></div><span>For authorized assessments only · v2.0.0</span></footer>
    </main>
    <ScanDetailModal scanId={selectedScan} onClose={() => setSelectedScan(null)}/>
  </div>
}
