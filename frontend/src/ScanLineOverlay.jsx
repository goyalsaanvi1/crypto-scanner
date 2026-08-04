export default function ScanLineOverlay({ onComplete }) {
  return (
    <div className="scan-line-overlay" aria-hidden="true">
      <div className="scan-line" onAnimationEnd={onComplete} />
    </div>
  )
}
