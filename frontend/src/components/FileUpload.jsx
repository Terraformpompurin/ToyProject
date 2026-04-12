import { useState, useCallback } from 'react'

export default function FileUpload({ onScan, loading }) {
  const [dragging, setDragging] = useState(false)
  const [selectedFile, setSelectedFile] = useState(null)

  const handleFile = useCallback((file) => {
    if (!file) return
    const ext = file.name.split('.').pop().toLowerCase()
    if (!['tf', 'zip'].includes(ext)) {
      alert('.tf 또는 .zip 파일만 업로드할 수 있습니다.')
      return
    }
    setSelectedFile(file)
  }, [])

  const onDrop = useCallback((e) => {
    e.preventDefault()
    setDragging(false)
    handleFile(e.dataTransfer.files[0])
  }, [handleFile])

  const onInputChange = (e) => handleFile(e.target.files[0])

  const handleScan = () => {
    if (selectedFile) onScan(selectedFile)
  }

  return (
    <div className="max-w-2xl mx-auto">
      {/* 드래그 앤 드롭 영역 */}
      <div
        onDragOver={(e) => { e.preventDefault(); setDragging(true) }}
        onDragLeave={() => setDragging(false)}
        onDrop={onDrop}
        className={`border-2 border-dashed rounded-xl p-12 text-center transition-colors cursor-pointer
          ${dragging
            ? 'border-blue-500 bg-blue-50'
            : 'border-gray-300 bg-gray-50 hover:border-blue-400 hover:bg-blue-50'
          }`}
        onClick={() => document.getElementById('file-input').click()}
      >
        <div className="text-5xl mb-4">📂</div>
        <p className="text-gray-600 font-medium">
          Terraform 파일을 드래그하거나 클릭해서 선택하세요
        </p>
        <p className="text-sm text-gray-400 mt-1">.tf 파일 또는 .zip 압축 파일 지원</p>
        <input
          id="file-input"
          type="file"
          accept=".tf,.zip"
          className="hidden"
          onChange={onInputChange}
          onClick={(e) => e.stopPropagation()}
        />
      </div>

      {/* 선택된 파일 표시 */}
      {selectedFile && (
        <div className="mt-4 flex items-center justify-between bg-white border border-gray-200 rounded-lg px-4 py-3 shadow-sm">
          <div className="flex items-center gap-3">
            <span className="text-2xl">{selectedFile.name.endsWith('.zip') ? '🗜️' : '📄'}</span>
            <div>
              <p className="text-sm font-medium text-gray-800">{selectedFile.name}</p>
              <p className="text-xs text-gray-400">{(selectedFile.size / 1024).toFixed(1)} KB</p>
            </div>
          </div>
          <button
            onClick={() => setSelectedFile(null)}
            className="text-gray-400 hover:text-red-500 text-lg leading-none"
            title="파일 제거"
          >
            ✕
          </button>
        </div>
      )}

      {/* 스캔 버튼 */}
      <button
        onClick={handleScan}
        disabled={!selectedFile || loading}
        className={`mt-4 w-full py-3 rounded-lg font-semibold text-white transition-colors
          ${!selectedFile || loading
            ? 'bg-gray-300 cursor-not-allowed'
            : 'bg-blue-600 hover:bg-blue-700 active:bg-blue-800'
          }`}
      >
        {loading
          ? '🔍 스캔 중...'
          : '🔍 보안 스캔 시작'
        }
      </button>
    </div>
  )
}
