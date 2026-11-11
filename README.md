# 🛡️ Simple Safe: LLM 생성 웹사이트 맞춤형 AI 보안 진단 서비스

> **바이브 코딩(Vibe Coding) 시대의 안전장치**  
> AI가 빠르게 생성한 웹사이트의 보안 취약점을 문맥 기반으로 분석하고, 자동 패치(PR)까지 제안하는 AI 보안 에이전트 서비스입니다.

---

## 👥 팀원 소개 (Team)

| 한재현 (팀장) | 김민서 (팀원) |
| :---: | :---: |
| 20231626 | 20231520 |

---

## 📌 1. 프로젝트 개요 및 문제 상황

### 배경
최근 자연어 프롬프트만으로 코드와 웹사이트를 완성하는 **바이브 코딩(Vibe Coding)**이 확산되면서, 비개발자나 스타트업도 손쉽게 완성도 높은 웹 서비스를 구축할 수 있게 되었습니다.

### 문제점
LLM은 코드 생성 시 '보안 안전성'보다 **'기능의 동작 여부'**를 우선시하는 경향이 있습니다. 프롬프트에서 매우 엄격한 보안 규칙을 명시하지 않으면 다음과 같은 치명적인 보안 결함이 빈번히 발생합니다.
- 🔑 **API 키 및 시크릿 하드코딩**
- 🛡️ **DOM 기반 XSS (크로스 사이트 스크립팅) 필터링 누락**
- ⚠️ **입력값 데이터 검증 부실로 인한 동적 렌더링 보안 문제**

보안 지식이 부족한 일반 사용자나 초보 개발자는 이러한 위험을 인지하지 못한 채 서비스를 배포하여 데이터 유출 등의 보안 사고에 노출됩니다.

### 해결책: Simple Safe
`Simple Safe`는 소스 코드 압축 파일이나 GitHub 저장소 링크만으로 전체 코드의 문맥과 데이터 흐름(Data Flow)을 추적하여, 오탐률을 줄인 정확한 분석 리포트와 **원클릭 자동 패치(PR)**를 제공합니다.

---

## 🚀 2. 주요 기능 (Key Features)

- 🔍 **원클릭 심층 보안 진단:** GitHub 저장소 URL 또는 ZIP 업로드로 소스 코드 전수 스캔.
- 🧠 **문맥 기반(Context-Aware) 리포트:** 단순 정규식(Regex)의 한계인 오탐을 극복하고, 데이터 오염 및 브라우저 렌더링 흐름을 논리적으로 설명.
- 🛠️ **자동 시큐어 코딩 패치 (Auto-Remediation):** 취약점이 발견된 코드를 안전한 방어 코드로 즉시 교체 제안하고, 클릭 한 번으로 GitHub Pull Request(PR) 전송.

---

## 🏗️ 3. 개발 및 고도화 과정 (Development Journey)

Simple Safe는 빠른 애자일 프로토타입 검증 후 글로벌 오픈소스 기술을 적극 수용하며 진화했습니다.

### 1단계: 초기 프로토타입 구축 (Agile Prototyping)
- **Cursor**와 **GPT**를 활용해 기획 아이디어를 빠르게 실체화.
- 소스 코드 분석 및 취약점 1차 식별 파이프라인의 실현 가능성 검증.

### 2단계: 글로벌 오픈소스 연동 및 엔진 고도화 (Strategic Integration)
- 개발 진행 중 GitHub에 공개된 Cloudflare의 **[`security-audit-skill`](https://github.com/cloudflare/security-audit-skill)** 발견.
- 팀의 문제 정의가 글로벌 트렌드와 일치함을 확인하고, 기존 자체 엔진에서 `security-audit-skill` 기반 보안 검사 모듈로 전격 교체.
- 엣지(Edge) 환경에서의 빠른 스캔 속도와 글로벌 스탠다드 보안 검증 정확도 확보.

---

## ⚖️ 4. 기술적 차별점 (vs SonarQube)

| 비교 항목 | SonarQube (전통적 SAST) | Simple Safe (LLM 기반 AI 에이전트) |
| :--- | :--- | :--- |
| **분석 방식** | 정해진 패턴(Regex) 및 AST 매칭 | 코드 의도 및 데이터 흐름(Data Flow) 추론 |
| **오탐률** | 높음 (문맥 파악 불가로 개발자 피로도 증가) | **낮음 (위험 데이터 흐름만 필터링)** |
| **해결책** | 수동 수정 (가이드 문서만 제공) | **자동 패치 생성 및 GitHub PR 즉시 전송** |
| **연동성** | 서버 구축 및 복잡한 Rule-set 설정 필요 | Zero-Config (GitHub 링크로 즉시 스캔) |
| **타겟** | 엔터프라이즈 레거시 코드 | **LLM 생성 웹사이트 (Vibe Coding 결과물)** |

---

## 🛠️ 5. 기술 스택 (Tech Stack)

- **Frontend / Agent UI:** HTML, CSS, JavaScript (Tailwind / Custom Dashboard UI)
- **Backend / Engine:** Python (FastAPI), BeautifulSoup / AST Parsing
- **AI & Security Core:** GPT-4o / Claude 3.5 Sonnet, LangChain (RAG), Cloudflare `security-audit-skill`
- **Integration:** GitHub API (Automated PR Generation)
