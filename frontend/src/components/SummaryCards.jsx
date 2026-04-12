import { calcSecurityScore, scoreColor, scoreBgColor, scoreLabel } from '../utils/scoring.js'
import { getCheckMeta } from '../data/checkMetadata.js'

export default function SummaryCards({ violations, passed, filename }) {
  const score   = calcSecurityScore(violations)
  const total   = violations.length + passed
  const criticals = violations.filter(v => getCheckMeta(v.check_id).severity === 'CRITICAL').length
  const highs     = violations.filter(v => getCheckMeta(v.check_id).severity === 'HIGH').length

  const cards = [
    {
      label: '스캔 리소스',
      value: total,
      sub: '총 체크 수',
      icon: '📋',
      color: 'border-gray-200 bg-white',
      textColor: 'text-gray-800',
    },
    {
      label: '위반 항목',
      value: violations.length,
      sub: `통과 ${passed}개`,
      icon: '❌',
      color: violations.length > 0 ? 'border-red-200 bg-red-50' : 'border-green-200 bg-green-50',
      textColor: violations.length > 0 ? 'text-red-600' : 'text-green-600',
    },
    {
      label: 'CRITICAL',
      value: criticals,
      sub: `HIGH ${highs}개`,
      icon: '🚨',
      color: criticals > 0 ? 'border-red-300 bg-red-50' : 'border-gray-200 bg-white',
      textColor: criticals > 0 ? 'text-red-700' : 'text-gray-400',
    },
    {
      label: '보안 점수',
      value: `${score}점`,
      sub: scoreLabel(score),
      icon: '🎯',
      color: `border ${scoreBgColor(score)}`,
      textColor: scoreColor(score),
    },
  ]

  return (
    <div>
      {filename && (
        <p className="text-sm text-gray-500 mb-3">
          📁 스캔 파일: <span className="font-mono font-medium text-gray-700">{filename}</span>
        </p>
      )}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        {cards.map((card) => (
          <div
            key={card.label}
            className={`rounded-xl border p-4 shadow-sm ${card.color}`}
          >
            <div className="flex items-center justify-between mb-1">
              <span className="text-xs font-medium text-gray-500 uppercase tracking-wide">
                {card.label}
              </span>
              <span className="text-xl">{card.icon}</span>
            </div>
            <p className={`text-3xl font-bold ${card.textColor}`}>{card.value}</p>
            <p className="text-xs text-gray-400 mt-1">{card.sub}</p>
          </div>
        ))}
      </div>
    </div>
  )
}
