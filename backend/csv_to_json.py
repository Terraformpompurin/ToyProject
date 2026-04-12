import pandas as pd
import json

# 1. 파일 읽기 (인코딩 에러 방지)
file_path = 'isms_p_items.csv'
try:
    # 헤더가 없는 상태로 읽어서 직접 인덱스로 접근 (skiprows는 상단 제목 제거)
    df = pd.read_csv(file_path, encoding='cp949', header=None, skiprows=2)
except Exception as e:
    df = pd.read_csv(file_path, encoding='utf-8', header=None, skiprows=2)

isms_dict = {}

# 2. 데이터 가공 (보내준 텍스트 기반 인덱스 설정)
for _, row in df.iterrows():
    # 컬럼 인덱스 설명:
    # row[3] -> 항목 번호 (예: 2.1.1, 2.6.1)
    # row[4] -> 항목명 (예: 정책의 유지관리)
    # row[5] -> 상세내용
    
    item_no = str(row[3]).strip()
    
    # '2.'으로 시작하는 유효한 번호인 경우만 저장
    if item_no.startswith('2.'):
        isms_dict[item_no] = {
            "title": str(row[4]).strip(),
            "content": str(row[5]).strip(),
            "category": str(row[2]).strip() if pd.notna(row[2]) else ""
        }

# 3. JSON 저장
with open('isms_p_data.json', 'w', encoding='utf-8') as f:
    json.dump(isms_dict, f, ensure_ascii=False, indent=4)

print(f"✅ 변환 완료! 총 {len(isms_dict)}개 항목이 추출되었습니다.")