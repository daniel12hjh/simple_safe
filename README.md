# Simple Safe 2.1.1

GitHub 저장소의 소스 파일을 선택해 보안 검사를 실행하고, 검토한 변경을 Draft Pull Request로 올리는 로컬 웹 앱입니다.

## 실행

Python 3.10 이상을 사용합니다. Node.js가 설치돼 있으면 일반 JavaScript 파일의 수정안에 문법 검사를 적용합니다.

```bash
cd 'Simple Safe'
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
uvicorn main:app --host 127.0.0.1 --port 8000
```

브라우저에서 [Simple Safe](http://127.0.0.1:8000)를 엽니다. 샘플 Python 코드는 키 없이 검사할 수 있습니다.

- GitHub 연동은 `.env`의 `GITHUB_TOKEN`을 사용합니다. 대상 저장소 파일 조회에는 **Contents: Read**, 같은 저장소에서 Draft PR을 만들려면 **Contents: Read and write**와 **Pull requests: Read and write** 권한이 필요합니다. Fork를 쓰는 경우 토큰이 원본과 Fork 양쪽의 필요한 작업을 허용해야 합니다.
- Gemini 분석과 수정 제안은 `.env`의 `GEMINI_API_KEY`를 사용합니다. 필요하면 `GEMINI_MODEL`을 지정할 수 있습니다. 화면에서 Gemini 분석을 켜면 선택한 소스가 Gemini에 전송됩니다. 토큰과 API 키는 서버 환경 변수에서 읽습니다.

## GitHub에서 검사하고 PR 만들기

1. **GitHub 저장소에서 가져오기**를 열고 `owner/repo` 또는 GitHub 저장소 URL을 입력합니다. 브랜치를 비워두면 저장소 기본 브랜치를 사용합니다.
2. 파일 목록에서 검사할 파일을 검색하고 선택합니다. 한 번에 최대 12개, 파일당 80KB, 합계 250KB입니다. 큰 저장소에서 목록이 잘리면 화면에 표시합니다.
3. **분석 시작**을 누릅니다. Python 정적 검사에서는 셸 사용, pickle 역직렬화, TLS 검증 비활성화 패턴을 찾습니다. Gemini 분석을 켜면 지원 소스에 대해 근거가 있는 검토 후보와 수정안도 제안합니다. 결과의 **파일별 검사 범위**에서 수행된 검사를 확인할 수 있습니다.
4. **검토 후 Draft PR 생성**을 눌러 적용할 파일을 고르고 변경 줄을 확인한 뒤 승인합니다. 로컬 입력으로 검사한 경우에는 PR 대상 저장소와 브랜치를 이 화면에서 지정합니다.
5. GitHub에서 열린 Draft PR을 확인합니다. 원본이 일치하는 파일만 처리하며 GitHub에서 가져온 파일은 분석한 커밋을 기준으로 검사합니다. 브랜치가 이동해 409가 표시되면 파일을 새로 불러오고 다시 분석합니다.

선택 파일을 한 커밋으로 만든 뒤 수정 브랜치를 게시합니다. 동일한 기준 커밋과 패치로 재시도하면 기존 브랜치를 검증하고 열린 PR을 재사용합니다. 쓰기 권한이 없는 원본에서는 호환되는 사용자 Fork를 사용하거나 만들고, Fork 동기화가 진행 중이면 같은 요청을 다시 시도할 수 있습니다.

## 검사 범위와 상태

[Cloudflare security-audit-skill](https://github.com/cloudflare/security-audit-skill)의 검사 범위 기록과 근거 대조 방식을 참고했습니다. 정적 패턴은 코드에 나타난 구문을 의미합니다. AI 후보는 파일·줄·원문 근거를 대조한 뒤 **추가 검토 필요**로 표시합니다. Gemini가 제안한 수정은 원본에서 변경할 위치를 찾은 뒤 파일 전체 수정안으로 조립합니다. 수정안은 원본 일치 여부, 지원 언어의 문법, 새 Python 위험 패턴 추가 여부를 검사합니다. 앱은 대상 코드의 테스트나 실행 파일을 실행하지 않습니다. 문법 자동 검사가 지원되지 않는 파일은 패치 선택 화면에 표시합니다.

GitHub API는 루프백에서 접근할 수 있습니다. 이 앱은 로컬 사용을 전제로 합니다. 브랜치 보호 규칙, 조직의 Fork 정책, GitHub 토큰 권한에 따라 GitHub가 변경을 거절할 수 있습니다.

## API 및 테스트

- `GET /health`에서 GitHub 및 Gemini 설정 여부를 확인합니다.
- `POST /api/github/repository`에 `repo`, 선택적인 `branch`를 전달해 파일 목록과 커밋 SHA를 조회합니다.
- `POST /api/github/files`에 `repo`, `branch`, `sha`, `paths`를 전달해 해당 커밋의 파일을 읽습니다.
- `POST /analyze`에 `files` 배열을 전달합니다. 파일 요소는 `path`, `code`이고, 로컬 검사만 실행하려면 `use_ai: false`를 지정합니다.
- `POST /api/github/pull-request`는 `repo`, `base_branch`, 선택적인 `base_sha`, `approved: true`, `patches`를 받습니다. 패치 요소는 `file`, `original_code`, `patched_code`입니다.

```bash
python -m unittest -v
node --check js/app.js
```

테스트에서는 GitHub 응답을 모의로 재현합니다. 실제 GitHub PR 생성과 Gemini 응답은 각 서비스의 자격 증명을 설정한 환경에서 확인할 수 있습니다.
