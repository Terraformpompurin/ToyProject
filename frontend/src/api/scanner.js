const API_BASE =
  (import.meta.env?.VITE_API_URL && String(import.meta.env.VITE_API_URL).trim()) ||
  '/scan'

function buildScanUrl() {
  // VITE_API_URL can be:
  // - "/scan" (default): same-origin, nginx will proxy to backend in k8s
  // - "http://host:8000": direct backend (local dev)
  return API_BASE.endsWith('/scan') ? API_BASE : `${API_BASE.replace(/\/$/, '')}/scan`
}

/**
 * .tf 또는 .zip 파일을 업로드하고 Checkov 스캔 결과를 반환한다.
 * @param {File} file
 * @returns {Promise<object>}
 */
export async function scanFile(file) {
  const formData = new FormData()
  formData.append('file', file)

  const res = await fetch(buildScanUrl(), {
    method: 'POST',
    body: formData,
  })

  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }))
    throw new Error(err.detail || '스캔 요청 실패')
  }

  const data = await res.json()

  // 개발 중 디버깅: 백엔드 _debug 정보 콘솔 출력
  if (data._debug) {
    console.group('[Scanner Debug]')
    console.log('scan_dir :', data._debug.scan_dir)
    console.log('tf_count :', data._debug.tf_count)
    console.log('returncode:', data._debug.returncode)
    if (data._debug.stderr_snippet) {
      console.warn('stderr:', data._debug.stderr_snippet)
    }
    console.groupEnd()
  }

  return data
}

/**
 * Checkov 결과에서 failed_checks 배열을 안전하게 추출한다.
 * Checkov는 단일 객체 또는 배열로 결과를 반환할 수 있다.
 */
export function extractFailedChecks(data) {
  if (!data) return []

  // 배열 형태: [{check_type: 'terraform', results: {...}}, ...]
  if (Array.isArray(data)) {
    return data.flatMap(item =>
      item?.results?.failed_checks ?? []
    )
  }

  // 단일 객체 형태: {results: {failed_checks: [...]}}
  return data?.results?.failed_checks ?? []
}

export function extractPassedChecks(data) {
  if (!data) return []
  if (Array.isArray(data)) {
    return data.flatMap(item => item?.results?.passed_checks ?? [])
  }
  return data?.results?.passed_checks ?? []
}
