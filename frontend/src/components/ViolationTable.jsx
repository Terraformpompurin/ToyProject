import { useState, useMemo } from 'react'
import SeverityBadge from './SeverityBadge.jsx'
import { getCheckMeta, SEVERITY_ORDER } from '../data/checkMetadata.js'

const SERVICE_ICONS = {
  'Security Group': '🔒',
  'S3':             '🪣',
  'IAM':            '👤',
  'RDS':            '🗄️',
  'CloudTrail':     '📜',
}

export default function ViolationTable({ violations, onSelect }) {
  const [filter, setFilter]       = useState('ALL')
  const [searchQuery, setSearch]  = useState('')
  const [sortField, setSortField] = useState('severity')

  const severityOptions = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW']

  const enriched = useMemo(() =>
    violations.map(v => ({ ...v, _meta: getCheckMeta(v.check_id) })),
    [violations]
  )

  const filtered = useMemo(() => {
    let list = enriched
    if (filter !== 'ALL') list = list.filter(v => v._meta.severity === filter)
    if (searchQuery) {
      const q = searchQuery.toLowerCase()
      list = list.filter(v =>
        v.resource?.toLowerCase().includes(q) ||
        v.check_id?.toLowerCase().includes(q) ||
        v._meta.title?.toLowerCase().includes(q) ||
        v.file_path?.toLowerCase().includes(q)
      )
    }
    return [...list].sort(
      (a, b) => (SEVERITY_ORDER[a._meta.severity] ?? 9) - (SEVERITY_ORDER[b._meta.severity] ?? 9)
    )
  }, [enriched, filter, searchQuery, sortField])

  return (
    <div>
      <div className="flex flex-wrap items-center gap-3 mb-4">
        <h3 className="text-sm font-semibold text-gray-600 uppercase tracking-wide">
          위반 항목 목록
        </h3>

        {/* 심각도 필터 */}
        <div className="flex gap-1 ml-auto">
          {severityOptions.map(s => (
            <button
              key={s}
              onClick={() => setFilter(s)}
              className={`px-2 py-0.5 rounded text-xs font-medium transition-colors
                ${filter === s
                  ? 'bg-gray-800 text-white'
                  : 'bg-gray-100 text-gray-500 hover:bg-gray-200'
                }`}
            >
              {s}
            </button>
          ))}
        </div>

        {/* 검색 */}
        <input
          type="text"
          placeholder="리소스 / 체크 ID 검색..."
          value={searchQuery}
          onChange={e => setSearch(e.target.value)}
          className="border border-gray-200 rounded-lg px-3 py-1.5 text-sm w-52 focus:outline-none focus:ring-2 focus:ring-blue-300"
        />
      </div>

      {filtered.length === 0 ? (
        <div className="text-center py-12 text-gray-400">
          <p className="text-3xl mb-2">✅</p>
          <p className="text-sm">해당하는 위반 항목이 없습니다.</p>
        </div>
      ) : (
        <div className="overflow-x-auto rounded-xl border border-gray-200 shadow-sm">
          <table className="min-w-full text-sm">
            <thead className="bg-gray-50 text-xs text-gray-500 uppercase tracking-wide">
              <tr>
                <th className="px-4 py-3 text-left">심각도</th>
                <th className="px-4 py-3 text-left">서비스</th>
                <th className="px-4 py-3 text-left">체크 항목</th>
                <th className="px-4 py-3 text-left">리소스</th>
                <th className="px-4 py-3 text-left">파일</th>
                <th className="px-4 py-3 text-left">ISMS-P</th>
                <th className="px-4 py-3 text-center">상세</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100 bg-white">
              {filtered.map((v, idx) => (
                <tr
                  key={idx}
                  className="hover:bg-blue-50 transition-colors cursor-pointer"
                  onClick={() => onSelect(v)}
                >
                  <td className="px-4 py-3">
                    <SeverityBadge severity={v._meta.severity} />
                  </td>
                  <td className="px-4 py-3 text-gray-600">
                    {SERVICE_ICONS[v._meta.service] ?? '☁️'} {v._meta.service}
                  </td>
                  <td className="px-4 py-3">
                    <p className="font-medium text-gray-800 leading-tight">{v._meta.title}</p>
                    <p className="text-xs text-gray-400 font-mono mt-0.5">{v.check_id}</p>
                  </td>
                  <td className="px-4 py-3 font-mono text-xs text-gray-600 max-w-[180px] truncate" title={v.resource}>
                    {v.resource}
                  </td>
                  <td className="px-4 py-3 text-xs text-gray-400 max-w-[160px] truncate" title={v.file_path}>
                    {v.file_path?.split('/').pop()}
                    {v.file_line_range && (
                      <span className="ml-1 text-gray-300">:{v.file_line_range[0]}</span>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    <span className="text-xs font-mono text-purple-600 bg-purple-50 px-2 py-0.5 rounded">
                      {v._meta.ismsP}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-center">
                    <button
                      onClick={(e) => { e.stopPropagation(); onSelect(v) }}
                      className="text-blue-500 hover:text-blue-700 text-xs font-medium"
                    >
                      상세 →
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <div className="px-4 py-2 bg-gray-50 border-t border-gray-100 text-xs text-gray-400">
            {filtered.length}개 표시 / 전체 {violations.length}개
          </div>
        </div>
      )}
    </div>
  )
}
