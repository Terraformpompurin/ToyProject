export default function Navbar({ onReset }) {
  return (
    <header className="bg-gray-900 text-white shadow-md">
      <div className="max-w-7xl mx-auto px-6 h-14 flex items-center justify-between">
        <button
          onClick={onReset}
          className="flex items-center gap-2 font-bold text-lg tracking-tight hover:text-blue-300 transition-colors"
        >
          <span className="text-2xl">🛡️</span>
          <span>Terraform Security Scanner</span>
        </button>
        <span className="text-xs text-gray-400 font-mono">ISMS-P 기반 · 21개 커스텀 체크</span>
      </div>
    </header>
  )
}
