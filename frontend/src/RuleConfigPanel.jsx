import { useRef } from 'react'

export default function RuleConfigPanel({
  rules,
  ruleConfig,
  onToggleEnabled,
  onChangeSeverity,
  onExportConfig,
  onImportConfig,
  importError,
}) {
  const fileInputRef = useRef(null)

  if (rules.length === 0) return null

  function handleImportFileChange(event) {
    const file = event.target.files?.[0]
    if (file) onImportConfig(file)
    event.target.value = ''
  }

  return (
    <section className="panel rules-panel" aria-label="Rule configuration">
      <div className="rules-panel-heading">
        <div>
          <h2 className="panel-heading">Rules</h2>
          <p className="field-label rules-hint">
            Enable/disable rules or force a severity, same as .cryptoscanner.yml.
          </p>
        </div>
        <div className="config-io-buttons">
          <button type="button" className="clear-files-button" onClick={onExportConfig}>
            Export .yml
          </button>
          <button type="button" className="clear-files-button" onClick={() => fileInputRef.current?.click()}>
            Import .yml
          </button>
          <input
            ref={fileInputRef}
            type="file"
            accept=".yml,.yaml"
            hidden
            onChange={handleImportFileChange}
          />
        </div>
      </div>

      {importError && <p className="empty-state error-state config-import-error">{importError}</p>}

      <ul className="rules-list">
        {rules.map((rule) => {
          const cfg = ruleConfig[rule.rule_id] ?? { enabled: true, severityOverride: '' }
          return (
            <li key={rule.rule_id} className="rule-row">
              <label className="rule-toggle">
                <input
                  type="checkbox"
                  checked={cfg.enabled}
                  onChange={(event) => onToggleEnabled(rule.rule_id, event.target.checked)}
                />
                <span className="rule-badge">{rule.rule_id}</span>
              </label>

              <select
                className="severity-select"
                value={cfg.severityOverride}
                onChange={(event) => onChangeSeverity(rule.rule_id, event.target.value)}
                disabled={!cfg.enabled}
                aria-label={`Severity override for ${rule.rule_id}`}
              >
                <option value="">Default</option>
                <option value="HIGH">HIGH</option>
                <option value="MEDIUM">MEDIUM</option>
                <option value="LOW">LOW</option>
              </select>

              <span className="rule-description">{rule.description}</span>
            </li>
          )
        })}
      </ul>
    </section>
  )
}
