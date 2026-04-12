const styles = {
  CRITICAL: 'bg-red-100 text-red-700 border border-red-300',
  HIGH:     'bg-orange-100 text-orange-700 border border-orange-300',
  MEDIUM:   'bg-yellow-100 text-yellow-700 border border-yellow-300',
  LOW:      'bg-blue-100 text-blue-700 border border-blue-300',
}

export default function SeverityBadge({ severity }) {
  const s = (severity ?? 'MEDIUM').toUpperCase()
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-bold ${styles[s] ?? styles.MEDIUM}`}>
      {s}
    </span>
  )
}
