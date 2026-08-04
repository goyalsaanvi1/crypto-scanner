const SEVERITY_ORDER = ['HIGH', 'MEDIUM', 'LOW']
const SEVERITY_LABEL = { HIGH: 'High', MEDIUM: 'Medium', LOW: 'Low' }

function FindingRow({ finding, clickable, onClick }) {
  return (
    <button
      type="button"
      className={`finding-row${clickable ? '' : ' finding-row-static'}`}
      onClick={clickable ? onClick : undefined}
      title={clickable ? `Jump to line ${finding.line_number}` : undefined}
    >
      <span
        className={`severity-swatch severity-${finding.severity.toLowerCase()}`}
        aria-hidden="true"
      />
      <span className="rule-badge">{finding.rule_id}</span>
      <span className="finding-line">line {finding.line_number}</span>
      <span className="finding-message">{finding.message}</span>
    </button>
  )
}

export default function ResultsPanel({
  status,
  resultMode,
  findings,
  fileResults,
  summary,
  error,
  onFindingClick,
  onExport,
}) {
  const totalFindings =
    resultMode === 'batch'
      ? fileResults.reduce((sum, file) => sum + file.findings.length, 0)
      : findings.length

  const isHistoryView = resultMode === 'history'

  return (
    <section className="panel results-panel" aria-label="Scan results" aria-live="polite">
      {status === 'error' && <p className="empty-state error-state">{error}</p>}

      {status === 'idle' && (
        <p className="empty-state">Paste Java source, pick a sample, or upload files, then run a scan.</p>
      )}

      {status === 'scanning' && <p className="empty-state">Scanning…</p>}

      {status === 'done' && totalFindings === 0 && <p className="empty-state">No findings.</p>}

      {status === 'done' && totalFindings > 0 && (
        <>
          <div className="summary-strip">
            {SEVERITY_ORDER.map((severity) => (
              <div key={severity} className={`summary-pill summary-${severity.toLowerCase()}`}>
                <span className="summary-count">{summary[severity] ?? 0}</span>
                <span className="summary-label">{SEVERITY_LABEL[severity]}</span>
              </div>
            ))}
            {!isHistoryView && (
              <div className="export-buttons">
                <button type="button" className="export-button" onClick={() => onExport?.('json')}>
                  Export JSON
                </button>
                <button type="button" className="export-button" onClick={() => onExport?.('sarif')}>
                  Export SARIF
                </button>
              </div>
            )}
          </div>

          {resultMode === 'batch' ? (
            <div className="batch-results">
              {fileResults
                .filter((file) => file.findings.length > 0)
                .map((file) => (
                  <div key={file.name} className="file-result-group">
                    <div className="file-result-heading">
                      <span className="file-result-name">{file.name}</span>
                      <span className="file-result-count">
                        {file.findings.length} finding{file.findings.length === 1 ? '' : 's'}
                      </span>
                    </div>
                    <ul className="findings-list">
                      {file.findings.map((finding, index) => (
                        <li key={index}>
                          <FindingRow finding={finding} clickable={false} />
                        </li>
                      ))}
                    </ul>
                  </div>
                ))}
            </div>
          ) : (
            <ul className="findings-list">
              {findings.map((finding, index) => (
                <li key={index}>
                  <FindingRow
                    finding={finding}
                    clickable={!isHistoryView}
                    onClick={() => onFindingClick?.(finding.line_number)}
                  />
                </li>
              ))}
            </ul>
          )}
        </>
      )}
    </section>
  )
}
