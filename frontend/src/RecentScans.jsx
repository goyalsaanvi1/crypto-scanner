const SEVERITY_ORDER = ['HIGH', 'MEDIUM', 'LOW']

function formatTimestamp(isoString) {
  if (!isoString) return ''
  const hasTimezone = /[zZ]|[+-]\d{2}:\d{2}$/.test(isoString)
  const date = new Date(hasTimezone ? isoString : `${isoString}Z`)
  if (Number.isNaN(date.getTime())) return isoString
  return date.toLocaleString(undefined, {
    month: 'short',
    day: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
  })
}

function firstLine(snippet) {
  const line = snippet.split('\n').find((l) => l.trim().length > 0) ?? snippet
  return line.trim()
}

export default function RecentScans({ history, onSelect, selectedId, onDelete, onClearAll }) {
  return (
    <section className="panel history-panel" aria-label="Recent scans">
      <div className="history-panel-heading">
        <h2 className="panel-heading">Recent Scans</h2>
        {history.length > 0 && (
          <button type="button" className="clear-files-button" onClick={onClearAll}>
            Clear all
          </button>
        )}
      </div>

      {history.length === 0 ? (
        <p className="empty-state">No scans yet — run one to see it here.</p>
      ) : (
        <ul className="history-list">
          {history.map((item) => (
            <li key={item.id} className="history-item">
              <button
                type="button"
                className={`history-row${item.id === selectedId ? ' history-row-active' : ''}`}
                onClick={() => onSelect(item.id)}
              >
                <span className="history-time">{formatTimestamp(item.created_at)}</span>
                <span className="history-snippet">{firstLine(item.source_snippet)}</span>
                <span className="history-dots">
                  {SEVERITY_ORDER.filter((severity) => item.summary[severity] > 0).map((severity) => (
                    <span key={severity} className="history-dot-group">
                      <span
                        className={`severity-swatch severity-${severity.toLowerCase()}`}
                        aria-hidden="true"
                      />
                      <span className="history-dot-count">{item.summary[severity]}</span>
                    </span>
                  ))}
                </span>
              </button>
              <button
                type="button"
                className="history-delete"
                onClick={() => onDelete(item.id)}
                aria-label={`Delete scan from ${formatTimestamp(item.created_at)}`}
                title="Delete this scan"
              >
                ×
              </button>
            </li>
          ))}
        </ul>
      )}
    </section>
  )
}
