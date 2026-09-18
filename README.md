# CloudTARA

CloudTARA는 클라우드 네이티브 환경을 대상으로 TARA 평가 절차를 작성하고 검토하기 위한 웹 기반 연구용 도구입니다. 평가 범위 설정부터 DFD 구성, 공격 벡터 검토, 위험 평가와 대응책 검토까지 하나의 작업 흐름으로 관리합니다.

## 주요 기능

- 평가 이름, 대상 시스템, 생명주기 단계와 범위 관리
- DFD 구성요소·데이터 흐름·신뢰 경계 편집
- Kubernetes Manifest를 이용한 DFD 초안 생성
- Attack Case 기반 후보 공격 벡터 식별
- 공격 벡터 쇼핑 카트 구성 및 타당성 검토
- 위험 계산기 선택, 공격 벡터별 점수 입력 및 위험 민감도 매트릭스 확인
- 대응 공격 벡터, 대응책 후보, 비용·효과와 최종 조합 검토
- Gemini, Groq, OpenAI, Anthropic API를 이용한 선택적 LLM 보조 기능

## 실행 환경

- Python 3.11 이상 권장
- PyYAML 6.0.3
- 최신 Chromium, Firefox 또는 Edge 브라우저

## Windows에서 실행

```powershell
git clone https://github.com/0xsuyeon/cn-tara.git
cd cn-tara
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -B app.py
```

브라우저에서 `http://127.0.0.1:8080`을 엽니다.

## macOS 또는 Linux에서 실행

```bash
git clone https://github.com/0xsuyeon/cn-tara.git
cd cn-tara
python3 -m venv .venv
./.venv/bin/pip install -r requirements.txt
./.venv/bin/python -B app.py
```

## 데이터와 API 키

- 평가 데이터는 최초 실행 시 `data/cntara.db`에 생성됩니다.
- `data/`와 데이터베이스 파일은 Git에서 제외됩니다.
- LLM API 키는 도구의 API 키 설정 화면에서 입력합니다.
- API 키는 데이터베이스나 브라우저 저장소에 저장하지 않고 현재 서버 세션 메모리에서만 사용합니다.
- 기본 서버 주소는 `127.0.0.1:8080`이며 외부에 공개하도록 구성되어 있지 않습니다.

## 프로젝트 구성

```text
app.py                  HTTP 서버와 API
cntara_db.py            SQLite 데이터 모델과 업무 로직
dfd_catalog.py          DFD 구성요소 카탈로그
manifest_collector.py   Kubernetes Manifest 분석
static/                 화면, 스타일과 브라우저 로직
requirements.txt        Python 의존성
```

## 참고

이 저장소는 연구 및 기능 검증을 위한 프로토타입입니다. 별도의 오픈소스 라이선스는 포함하지 않습니다.
