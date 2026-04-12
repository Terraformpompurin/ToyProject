import { useState, useCallback } from 'react'
import { scanFile, extractFailedChecks, extractPassedChecks } from './api/scanner.js'
import Navbar          from './components/Navbar.jsx'
import FileUpload      from './components/FileUpload.jsx'
import SummaryCards    from './components/SummaryCards.jsx'
import ServicePieChart from './components/ServicePieChart.jsx'
import ViolationTable  from './components/ViolationTable.jsx'
import ViolationDetail from './components/ViolationDetail.jsx'

export default function App() {
  const [loading,    setLoading]    = useState(false)
  const [error,      setError]      = useState(null)
  const [scanResult, setScanResult] = useState(null)   // raw API response
  const [selected,   setSelected]   = useState(null)   // 상세보기 위반 항목

  const violations = scanResult ? scanResult.results : []
  const passed     = scanResult ? scanResult.summary.passed : 0 

  const handleScan = useCallback(async (file) => {
    setLoading(true)
    setError(null)
    setScanResult(null)
    try {
      const result = await scanFile(file)
      if (!result.success) {
        setError(result.error ?? '스캔에 실패했습니다.')
      } else {
        setScanResult(result)
      }
    } catch (e) {
      setError(e.message ?? '서버에 연결할 수 없습니다. 백엔드가 실행 중인지 확인하세요.')
    } finally {
      setLoading(false)
    }
  }, [])

  const handleReset = () => {
    setScanResult(null)
    setError(null)
    setSelected(null)
  }

  return (
    <div className="min-h-screen bg-gray-50 flex flex-col">
      <Navbar onReset={handleReset} />

      <main className="flex-1 max-w-7xl mx-auto w-full px-6 py-8">

        {/* ── 업로드 화면 ── */}
        {!scanResult && !loading && (
          <div className="mt-16">
            <div className="text-center mb-10">
              <h1 className="text-3xl font-bold text-gray-900">Terraform 보안 스캐너</h1>
              <p className="text-gray-500 mt-2">
                .tf 파일 또는 .zip 파일을 업로드하면 ISMS-P 기반 21개 커스텀 체크를 실행합니다.
              </p>
            </div>
            <FileUpload onScan={handleScan} loading={loading} />
          </div>
        )}

        {/* ── 로딩 ── */}
        {loading && (
          <div className="mt-32 flex flex-col items-center gap-4 text-gray-500">
            <div className="w-12 h-12 border-4 border-blue-200 border-t-blue-600 rounded-full animate-spin" />
            <p className="text-sm">Checkov 스캔 실행 중...</p>
          </div>
        )}

        {/* ── 에러 ── */}
        {error && (
          <div className="mt-8 bg-red-50 border border-red-200 rounded-xl px-6 py-5 max-w-2xl mx-auto">
            <p className="font-semibold text-red-700 mb-1">스캔 오류</p>
            <p className="text-sm text-red-600">{error}</p>
            <button
              onClick={handleReset}
              className="mt-4 text-sm text-blue-600 hover:underline"
            >
              ← 다시 시도
            </button>
          </div>
        )}

        {/* ── 결과 대시보드 ── */}
        {scanResult && !loading && (
          <div className="space-y-6">
            {/* 요약 카드 */}
            <SummaryCards
              violations={violations}
              passed={passed}
              filename={scanResult.filename}
            />

            {/* 차트 + 테이블 */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* 파이 차트 */}
              <div className="bg-white rounded-xl border border-gray-200 shadow-sm p-5">
                <ServicePieChart violations={violations} />
              </div>

              {/* 위반 목록 테이블 */}
              <div className="lg:col-span-2 bg-white rounded-xl border border-gray-200 shadow-sm p-5">
                <ViolationTable violations={violations} onSelect={setSelected} />
              </div>
            </div>

            {/* 다시 스캔 버튼 */}
            <div className="text-center">
              <button
                onClick={handleReset}
                className="text-sm text-gray-500 hover:text-blue-600 underline"
              >
                ← 다른 파일 스캔하기
              </button>
            </div>
          </div>
        )}
      </main>

      {/* ── 상세 슬라이드 패널 ── */}
      <ViolationDetail violation={selected} onClose={() => setSelected(null)} />
    </div>
  )
}
