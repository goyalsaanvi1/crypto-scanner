import { useEffect, useRef, useState } from 'react'
import ScanForm from './ScanForm'
import ResultsPanel from './ResultsPanel'
import RuleConfigPanel from './RuleConfigPanel'
import RecentScans from './RecentScans'
import './App.css'

const API_BASE = 'http://localhost:8000'
const THEME_STORAGE_KEY = 'crypto-scanner-theme'

function getInitialTheme() {
  const stored = localStorage.getItem(THEME_STORAGE_KEY)
  return stored === 'light' || stored === 'dark' ? stored : 'dark'
}

function defaultRuleConfig(rules) {
  const config = {}
  for (const rule of rules) {
    config[rule.rule_id] = { enabled: true, severityOverride: '' }
  }
  return config
}

function App() {
  const [code, setCode] = useState('')
  const [samples, setSamples] = useState([])
  const [selectedSample, setSelectedSample] = useState('')
  const [files, setFiles] = useState([])
  const [rules, setRules] = useState([])
  const [ruleConfig, setRuleConfig] = useState({})
  const [status, setStatus] = useState('idle')
  const [resultMode, setResultMode] = useState('single')
  const [findings, setFindings] = useState([])
  const [fileResults, setFileResults] = useState([])
  const [summary, setSummary] = useState({ HIGH: 0, MEDIUM: 0, LOW: 0 })
  const [error, setError] = useState(null)
  const [history, setHistory] = useState([])
  const [selectedHistoryId, setSelectedHistoryId] = useState(null)
  const [theme, setTheme] = useState(getInitialTheme)
  const [configImportError, setConfigImportError] = useState(null)

  const sweepResolveRef = useRef(null)
  const scanFormRef = useRef(null)

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme)
    localStorage.setItem(THEME_STORAGE_KEY, theme)
  }, [theme])

  function handleToggleTheme() {
    setTheme((prev) => (prev === 'dark' ? 'light' : 'dark'))
  }

  useEffect(() => {
    fetch(`${API_BASE}/api/samples`)
      .then((res) => res.json())
      .then(setSamples)
      .catch(() => {
        // Sample list is a convenience, not required — fail silently.
      })

    fetch(`${API_BASE}/api/rules`)
      .then((res) => res.json())
      .then((data) => {
        setRules(data)
        setRuleConfig(defaultRuleConfig(data))
      })
      .catch(() => {
        // Rule config is a convenience, not required — fail silently.
      })

    fetchHistory()
  }, [])

  function fetchHistory() {
    fetch(`${API_BASE}/api/history`)
      .then((res) => res.json())
      .then(setHistory)
      .catch(() => {
        // Scan history is a convenience, not required — fail silently.
      })
  }

  async function handleSelectHistory(id) {
    const res = await fetch(`${API_BASE}/api/history/${id}`)
    if (!res.ok) return
    const data = await res.json()

    setResultMode('history')
    setFindings(data.findings_json)
    setSummary(data.summary_json)
    setError(null)
    setStatus('done')
    setSelectedHistoryId(id)
  }

  async function handleDeleteHistory(id) {
    const res = await fetch(`${API_BASE}/api/history/${id}`, { method: 'DELETE' })
    if (!res.ok) return

    setHistory((prev) => prev.filter((item) => item.id !== id))
    if (selectedHistoryId === id) {
      setSelectedHistoryId(null)
      setStatus('idle')
      setFindings([])
    }
  }

  async function handleClearAllHistory() {
    const res = await fetch(`${API_BASE}/api/history`, { method: 'DELETE' })
    if (!res.ok) return

    setHistory([])
    if (resultMode === 'history') {
      setSelectedHistoryId(null)
      setStatus('idle')
      setFindings([])
    }
  }

  function handleSelectSample(path) {
    if (!path) return
    const sample = samples.find((s) => s.path === path)
    if (!sample) return

    if (files.length === 0 && !code) {
      // Nothing loaded yet — quick single-file load, same as before.
      setSelectedSample(path)
      setCode(sample.code)
      return
    }

    if (files.length === 0) {
      // A single snippet is already loaded — picking another sample
      // converts to batch mode, keeping what was there as the first file.
      const firstName = selectedSample || 'snippet.java'
      setFiles([{ name: firstName, code }, { name: sample.path, code: sample.code }])
      setCode('')
      setSelectedSample('')
      return
    }

    // Already in batch mode — picking another sample just adds it.
    setFiles((prev) => [...prev, { name: sample.path, code: sample.code }])
  }

  async function handleFilesSelected(fileList) {
    const read = await Promise.all(
      fileList.map(async (file) => ({ name: file.name, code: await file.text() })),
    )
    setFiles((prev) => [...prev, ...read])
  }

  function handleRemoveFile(index) {
    setFiles((prev) => prev.filter((_, i) => i !== index))
  }

  function handleClearFiles() {
    setFiles([])
  }

  function handleToggleRuleEnabled(ruleId, enabled) {
    setRuleConfig((prev) => ({
      ...prev,
      [ruleId]: { ...prev[ruleId], enabled },
    }))
  }

  function handleChangeRuleSeverity(ruleId, severityOverride) {
    setRuleConfig((prev) => ({
      ...prev,
      [ruleId]: { ...prev[ruleId], severityOverride },
    }))
  }

  function handleExportConfig() {
    const lines = ['rules:']
    let hasEntries = false

    for (const rule of rules) {
      const cfg = ruleConfig[rule.rule_id] ?? { enabled: true, severityOverride: '' }
      if (cfg.enabled && !cfg.severityOverride) continue

      hasEntries = true
      lines.push(`  ${rule.rule_id}:`)
      lines.push(`    enabled: ${cfg.enabled}`)
      if (cfg.severityOverride) {
        lines.push(`    severity_override: ${cfg.severityOverride}`)
      }
    }

    const yamlText = hasEntries ? `${lines.join('\n')}\n` : 'rules: {}\n'

    const blob = new Blob([yamlText], { type: 'text/yaml' })
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = '.cryptoscanner.yml'
    link.click()
    URL.revokeObjectURL(url)
  }

  async function handleImportConfig(file) {
    setConfigImportError(null)
    const yamlText = await file.text()

    const res = await fetch(`${API_BASE}/api/config/parse`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ yaml_text: yamlText }),
    })
    const data = await res.json()

    if (!res.ok) {
      setConfigImportError(data.detail || 'Could not parse that config file.')
      return
    }

    setRuleConfig((prev) => {
      const next = { ...prev }
      for (const ruleId of Object.keys(next)) {
        const imported = data.rules[ruleId]
        next[ruleId] = imported
          ? { enabled: imported.enabled, severityOverride: imported.severity_override || '' }
          : { enabled: true, severityOverride: '' }
      }
      return next
    })
  }

  function handleSweepComplete() {
    sweepResolveRef.current?.()
  }

  function handleFindingClick(lineNumber) {
    if (resultMode !== 'single') return
    scanFormRef.current?.jumpToLine(lineNumber)
  }

  function buildRulesPayload() {
    return Object.fromEntries(
      Object.entries(ruleConfig).map(([ruleId, cfg]) => [
        ruleId,
        {
          enabled: cfg.enabled,
          severity_override: cfg.severityOverride || null,
        },
      ]),
    )
  }

  function buildScanBody() {
    return files.length > 0
      ? { files: files.map((f) => ({ name: f.name, code: f.code })), rules: buildRulesPayload() }
      : { code, rules: buildRulesPayload() }
  }

  async function handleExport(format) {
    const res = await fetch(`${API_BASE}/api/scan/export?format=${format}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(buildScanBody()),
    })
    if (!res.ok) return

    const blob = await res.blob()
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = format === 'sarif' ? 'crypto-scanner-results.sarif' : 'crypto-scanner-results.json'
    link.click()
    URL.revokeObjectURL(url)
  }

  async function handleRunScan() {
    if (status === 'scanning') return

    setStatus('scanning')
    setError(null)

    const sweepDone = new Promise((resolve) => {
      sweepResolveRef.current = resolve
    })

    const batchMode = files.length > 0

    const scanDone = fetch(`${API_BASE}/api/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(buildScanBody()),
    }).then(async (res) => {
      const data = await res.json()
      if (!res.ok) throw new Error(data.detail || `Scan failed (${res.status})`)
      return data
    })

    try {
      const [, data] = await Promise.all([sweepDone, scanDone])
      setSelectedHistoryId(null)
      if (batchMode) {
        setResultMode('batch')
        setFileResults(data.files)
      } else {
        setResultMode('single')
        setFindings(data.findings)
      }
      setSummary(data.summary)
      setStatus('done')
      fetchHistory()
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : 'Could not reach the scanner backend. Is it running on port 8000?',
      )
      setStatus('error')
    }
  }

  return (
    <div className="app">
      <header className="app-header">
        <div className="app-header-row">
          <div className="app-name">crypto-scanner</div>
          <button
            type="button"
            className="theme-toggle"
            onClick={handleToggleTheme}
            aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`}
            title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`}
          >
            {theme === 'dark' ? 'Light mode' : 'Dark mode'}
          </button>
        </div>
        <p className="app-tagline">
          Static analysis for Java cryptographic misuse — paste source or pick a sample.
        </p>
      </header>

      <main className="layout">
        <ScanForm
          ref={scanFormRef}
          code={code}
          onCodeChange={setCode}
          samples={samples}
          selectedSample={selectedSample}
          onSelectSample={handleSelectSample}
          onRunScan={handleRunScan}
          scanning={status === 'scanning'}
          onSweepComplete={handleSweepComplete}
          files={files}
          onFilesSelected={handleFilesSelected}
          onRemoveFile={handleRemoveFile}
          onClearFiles={handleClearFiles}
          theme={theme}
        />
        <ResultsPanel
          status={status}
          resultMode={resultMode}
          findings={findings}
          fileResults={fileResults}
          summary={summary}
          error={error}
          onFindingClick={handleFindingClick}
          onExport={handleExport}
        />
      </main>

      <RuleConfigPanel
        rules={rules}
        ruleConfig={ruleConfig}
        onToggleEnabled={handleToggleRuleEnabled}
        onChangeSeverity={handleChangeRuleSeverity}
        onExportConfig={handleExportConfig}
        onImportConfig={handleImportConfig}
        importError={configImportError}
      />

      <RecentScans
        history={history}
        onSelect={handleSelectHistory}
        selectedId={selectedHistoryId}
        onDelete={handleDeleteHistory}
        onClearAll={handleClearAllHistory}
      />
    </div>
  )
}

export default App
