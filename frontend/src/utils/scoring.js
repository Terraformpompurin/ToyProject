import { getCheckMeta } from '../data/checkMetadata.js'

const SEVERITY_PENALTY = { CRITICAL: 20, HIGH: 10, MEDIUM: 5, LOW: 2 }

/**
 * 위반 목록을 받아 0~100 보안 점수를 계산한다.
 * @param {Array} violations - failed_checks 배열
 * @returns {number} 0~100 점수
 */
export function calcSecurityScore(violations) {
  if (!violations || violations.length === 0) return 100

  const penalty = violations.reduce((sum, v) => {
    const meta = getCheckMeta(v.check_id)
    return sum + (SEVERITY_PENALTY[meta.severity] ?? 5)
  }, 0)

  return Math.max(0, Math.round(100 - penalty))
}

/** 점수에 따른 색상 클래스를 반환한다. */
export function scoreColor(score) {
  if (score >= 80) return 'text-green-600'
  if (score >= 60) return 'text-yellow-500'
  if (score >= 40) return 'text-orange-500'
  return 'text-red-600'
}

export function scoreBgColor(score) {
  if (score >= 80) return 'bg-green-50 border-green-200'
  if (score >= 60) return 'bg-yellow-50 border-yellow-200'
  if (score >= 40) return 'bg-orange-50 border-orange-200'
  return 'bg-red-50 border-red-200'
}

export function scoreLabel(score) {
  if (score >= 80) return '양호'
  if (score >= 60) return '주의'
  if (score >= 40) return '위험'
  return '심각'
}
