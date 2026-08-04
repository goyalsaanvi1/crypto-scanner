import { forwardRef, useImperativeHandle, useRef } from 'react'
import ScanLineOverlay from './ScanLineOverlay'

const ScanForm = forwardRef(function ScanForm(
  {
    code,
    onCodeChange,
    samples,
    selectedSample,
    onSelectSample,
    onRunScan,
    scanning,
    onSweepComplete,
    files,
    onFilesSelected,
    onRemoveFile,
    onClearFiles,
  },
  ref,
) {
  const textareaRef = useRef(null)
  const fileInputRef = useRef(null)
  const batchMode = files.length > 0

  function handleFileInputChange(event) {
    const selected = Array.from(event.target.files || [])
    if (selected.length > 0) onFilesSelected(selected)
    event.target.value = ''
  }

  useImperativeHandle(ref, () => ({
    jumpToLine(lineNumber) {
      const textarea = textareaRef.current
      if (!textarea) return

      const lines = textarea.value.split('\n')
      const targetIndex = Math.min(Math.max(lineNumber - 1, 0), lines.length - 1)
      const start = lines.slice(0, targetIndex).reduce((sum, line) => sum + line.length + 1, 0)
      const end = start + lines[targetIndex].length

      textarea.focus()
      textarea.setSelectionRange(start, end)

      const approxLineHeight = textarea.scrollHeight / lines.length
      textarea.scrollTop = Math.max(
        0,
        approxLineHeight * targetIndex - textarea.clientHeight / 2,
      )
    },
  }))

  return (
    <section className="panel scan-form" aria-label="Scan input">
      <div className="scan-form-controls">
        <label className="field-label" htmlFor="sample-select">
          Load a sample {batchMode || code ? '(pick another to add it to the batch)' : ''}
        </label>
        <select
          id="sample-select"
          value={selectedSample}
          onChange={(event) => onSelectSample(event.target.value)}
        >
          <option value="">— choose a sample file —</option>
          {samples.map((sample) => (
            <option key={sample.path} value={sample.path}>
              {sample.name}
            </option>
          ))}
        </select>
      </div>

      <div className="file-upload-row">
        <button type="button" className="upload-button" onClick={() => fileInputRef.current?.click()}>
          Upload .java files…
        </button>
        <input
          ref={fileInputRef}
          type="file"
          accept=".java"
          multiple
          hidden
          onChange={handleFileInputChange}
        />
        {batchMode && (
          <button type="button" className="clear-files-button" onClick={onClearFiles}>
            Clear files
          </button>
        )}
      </div>

      <div className="code-panel">
        {batchMode ? (
          <ul className="file-chip-list" aria-label="Files to scan">
            {files.map((file, index) => (
              <li key={`${file.name}-${index}`} className="file-chip">
                <span className="file-chip-name">{file.name}</span>
                <button
                  type="button"
                  className="file-chip-remove"
                  onClick={() => onRemoveFile(index)}
                  aria-label={`Remove ${file.name}`}
                >
                  ×
                </button>
              </li>
            ))}
          </ul>
        ) : (
          <textarea
            ref={textareaRef}
            className="code-textarea"
            value={code}
            onChange={(event) => onCodeChange(event.target.value)}
            placeholder="Paste Java source here..."
            spellCheck={false}
            aria-label="Java source code"
          />
        )}
        {scanning && <ScanLineOverlay onComplete={onSweepComplete} />}
      </div>

      <button
        type="button"
        className="run-scan-button"
        onClick={onRunScan}
        disabled={scanning || (batchMode ? files.length === 0 : !code.trim())}
      >
        {scanning ? 'Scanning…' : 'Run Scan'}
      </button>
    </section>
  )
})

export default ScanForm
