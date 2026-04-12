import SeverityBadge from './SeverityBadge.jsx'

/** 코드 블록: before/after 비교 */
function CodeBlock({ label, code, variant }) {
  const bg      = variant === 'before' ? 'bg-red-950'   : 'bg-green-950'
  const border  = variant === 'before' ? 'border-red-700' : 'border-green-700'
  const badge   = variant === 'before'
    ? 'bg-red-800 text-red-200'
    : 'bg-green-800 text-green-200'

  return (
    <div className={`rounded-lg border ${border} overflow-hidden`}>
      <div className={`${bg} px-4 py-2 flex items-center justify-between`}>
        <span className={`text-xs font-bold px-2 py-0.5 rounded ${badge}`}>{label}</span>
        <button
          onClick={() => navigator.clipboard?.writeText(code)}
          className="text-xs text-gray-400 hover:text-white"
          title="복사"
        >
          복사
        </button>
      </div>
      <pre className={`${bg} text-gray-100 code-block p-4 overflow-x-auto text-xs`}>
        {code}
      </pre>
    </div>
  )
}

export default function ViolationDetail({ violation, onClose }) {
  if (!violation) return null
  const meta = violation._meta

  return (
    /* 오버레이 */
    <div
      className="fixed inset-0 z-50 flex justify-end"
      onClick={onClose}
    >
      {/* 배경 딤 */}
      <div className="absolute inset-0 bg-black/40" />

      {/* 슬라이드 패널 */}
      <div
        className="relative w-full max-w-2xl h-full bg-white shadow-2xl overflow-y-auto"
        onClick={e => e.stopPropagation()}
      >
        {/* 헤더 */}
        <div className="sticky top-0 bg-white border-b border-gray-200 px-6 py-4 flex items-start justify-between z-10">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <SeverityBadge severity={meta.severity} />
              <span className="text-xs font-mono text-purple-600 bg-purple-50 px-2 py-0.5 rounded">
                ISMS-P {meta.ismsP}
              </span>
            </div>
            <h2 className="text-lg font-bold text-gray-900 leading-tight">{meta.title}</h2>
            <p className="text-xs font-mono text-gray-400 mt-0.5">{violation.check_id}</p>
          </div>
          <button
            onClick={onClose}
            className="ml-4 text-gray-400 hover:text-gray-700 text-2xl leading-none"
          >
            ×
          </button>
        </div>

        <div className="px-6 py-5 space-y-6">
          {/* 위반 리소스 정보 */}
          <section>
            <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-2">
              위반 리소스
            </h3>
            <div className="bg-gray-50 rounded-lg px-4 py-3 space-y-1 text-sm">
              <div className="flex gap-2">
                <span className="text-gray-400 w-16 shrink-0">리소스</span>
                <span className="font-mono text-gray-800">{violation.resource}</span>
              </div>
              <div className="flex gap-2">
                <span className="text-gray-400 w-16 shrink-0">파일</span>
                <span className="font-mono text-gray-600 text-xs">{violation.file_path}</span>
              </div>
              {violation.file_line_range && (
                <div className="flex gap-2">
                  <span className="text-gray-400 w-16 shrink-0">라인</span>
                  <span className="font-mono text-gray-600">
                    {violation.file_line_range[0]} – {violation.file_line_range[1]}
                  </span>
                </div>
              )}
            </div>
          </section>

          {/* 왜 위험한지 */}
          <section>
            <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-2">
              🚨 왜 위험한가요?
            </h3>
            <p className="text-sm text-gray-700 leading-relaxed bg-orange-50 border border-orange-100 rounded-lg px-4 py-3">
              {meta.reason}
            </p>
          </section>

          {/* 코드 비교 (diff 뷰) */}
          {(meta.before || meta.after) && (
            <section>
              <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-2">
                🔧 수정 방법
              </h3>
              <div className="space-y-3">
                {meta.before && <CodeBlock label="❌  수정 전 (취약)" code={meta.before} variant="before" />}
                {meta.after  && <CodeBlock label="✅  수정 후 (권장)" code={meta.after}  variant="after"  />}
              </div>
            </section>
          )}

          {/* 실제 사고 사례 */}
          {meta.incident && (
            <section>
              <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-2">
                📰 실제 사고 사례
              </h3>
              <div className="bg-gray-900 text-gray-100 rounded-lg px-4 py-3 text-sm leading-relaxed">
                {meta.incident}
              </div>
            </section>
          )}

          {/* ISMS-P 조항 설명 */}
          <section>
            <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-2">
              📋 ISMS-P 통제 항목
            </h3>
            <div className="flex items-center gap-3 bg-purple-50 border border-purple-100 rounded-lg px-4 py-3">
              <span className="text-2xl font-bold text-purple-700 font-mono">{meta.ismsP}</span>
              <span className="text-sm text-purple-800">
                {ISMS_P_LABELS[meta.ismsP] ?? '네트워크 및 접근 통제'}
              </span>
            </div>
          </section>
        </div>
      </div>
    </div>
  )
}

const ISMS_P_LABELS = {
  '2.5.1':  '사용자 계정 관리',
  '2.5.2':  '사용자 인증',
  '2.6.1':  '네트워크 접근통제',
  '2.6.2':  '정보시스템 접근통제',
  '2.7.1':  '암호정책 적용',
  '2.9.1':  '백업 및 복구',
  '2.9.2':  '업무 연속성 관리',
  '2.11.2': '로그 관리',
}
