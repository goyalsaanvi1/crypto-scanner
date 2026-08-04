import { useState } from 'react'

export default function CopyButton({ getText, className, label = 'Copy', copiedLabel = 'Copied' }) {
  const [copied, setCopied] = useState(false)

  async function handleClick() {
    const text = getText()
    if (!text) return
    try {
      await navigator.clipboard.writeText(text)
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    } catch {
      // Clipboard access can fail (permissions, insecure context) — fail silently.
    }
  }

  return (
    <button type="button" className={className} onClick={handleClick}>
      {copied ? copiedLabel : label}
    </button>
  )
}
