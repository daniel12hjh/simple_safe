"""Read immutable GitHub snapshots and publish reviewed changes as one commit."""
import base64
import hashlib
import json
import re
from contextlib import contextmanager

from fastapi import HTTPException
from github import Auth, Github, GithubException, InputGitTreeElement
from requests.exceptions import RequestException

REGULAR_MODES = {'100644', '100755'}


@contextmanager
def github_repository(token, repo):
    match = re.fullmatch(r'(?:https://github\.com/)?([A-Za-z0-9-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?/?', repo.strip())
    if not match or match[2] in ('.', '..'):
        raise HTTPException(400, '저장소는 owner/name 또는 GitHub 저장소 URL로 입력해 주세요.')
    try:
        with Github(auth=Auth.Token(token), timeout=15, retry=None) as github:
            yield github, github.get_repo(f'{match[1]}/{match[2]}')
    except GithubException as exc:
        status = exc.status if exc.status in (401, 403, 404, 409, 422, 429) else 502
        messages = {
            401: 'GitHub 토큰을 확인해 주세요.',
            403: 'GitHub 토큰 권한 또는 API 사용 한도를 확인해 주세요.',
            404: '저장소, 브랜치 또는 파일을 찾을 수 없습니다. 토큰의 접근 권한을 확인해 주세요.',
            422: 'GitHub에서 변경 요청을 거절했습니다. 브랜치 규칙과 권한을 확인해 주세요.',
            429: 'GitHub API 사용 한도에 도달했습니다. 잠시 후 재시도해 주세요.',
        }
        raise HTTPException(status, messages.get(status, 'GitHub 요청에 실패했습니다.')) from exc
    except (RequestException, TimeoutError) as exc:
        raise HTTPException(502, 'GitHub에 연결할 수 없습니다. 잠시 후 재시도해 주세요.') from exc


def resolve_branch(repo, branch):
    branch = branch or repo.default_branch
    if not re.fullmatch(r'[\w./-]+', branch) or '..' in branch or branch.startswith('/'):
        raise HTTPException(400, '브랜치 이름을 확인해 주세요.')
    return branch, repo.get_branch(branch).commit.sha


def file_entry(repo, tree_sha, path, trees):
    parts = path.split('/')
    for index, part in enumerate(parts):
        if tree_sha not in trees:
            tree = repo.get_git_tree(tree_sha)
            if tree.truncated:
                raise HTTPException(422, 'GitHub가 파일 목록 일부만 반환했습니다. 해당 경로를 확인할 수 없습니다.')
            trees[tree_sha] = {item.path: item for item in tree.tree}
        item = trees[tree_sha].get(part)
        if item is None or (index < len(parts) - 1 and item.type != 'tree'):
            item = None
            break
        tree_sha = item.sha
    if item is None or item.type != 'blob' or item.mode not in REGULAR_MODES:
        raise HTTPException(409, f'일반 파일을 찾을 수 없습니다. {path}')
    return item


def read_blob(repo, entry, path, max_bytes):
    if entry.size is None or entry.size > max_bytes:
        raise HTTPException(413, f'파일 크기 초과: {path}')
    blob = repo.get_git_blob(entry.sha)
    try:
        if blob.encoding != 'base64':
            raise ValueError('Unexpected blob encoding')
        code = base64.b64decode(blob.content).decode('utf-8')
    except (UnicodeError, ValueError) as exc:
        raise HTTPException(422, f'UTF-8 소스 파일을 읽을 수 없습니다. {path}') from exc
    if '\x00' in code or not code.strip():
        raise HTTPException(422, f'비어 있거나 바이너리인 파일입니다. {path}')
    return code


def create_security_pull_request(*, token, repo, base_branch, patches, expected_sha=None, max_file_bytes=80_000):
    with github_repository(token, repo) as (github, origin):
        base_branch, current_sha = resolve_branch(origin, base_branch)
        if expected_sha and current_sha != expected_sha:
            raise HTTPException(409, 'GitHub 브랜치가 분석 이후 변경됐습니다. 저장소를 다시 연결하고 분석해 주세요.')
        base_sha = current_sha
        base_commit = origin.get_git_commit(base_sha)
        entries = []
        trees = {}
        for patch in sorted(patches, key=lambda patch: patch['file']):
            path = patch['file']
            item = file_entry(origin, base_commit.tree.sha, path, trees)
            if read_blob(origin, item, path, max_file_bytes) != patch['original_code']:
                raise HTTPException(409, f'GitHub 원본이 다릅니다. {path} 최신 코드를 다시 분석해 주세요.')
            entries.append(InputGitTreeElement(path, item.mode, 'blob', content=patch['patched_code']))

        digest = hashlib.sha256(json.dumps(
            [origin.full_name, base_branch, base_sha, sorted(patches, key=lambda patch: patch['file'])],
            sort_keys=True, ensure_ascii=True,
        ).encode()).hexdigest()
        branch = f'simple-safe/fix-{digest[:24]}'
        ref_name = f'heads/{branch}'

        permissions = origin.permissions
        forked = not (permissions and permissions.push)
        owner = github.get_user().login if forked else origin.owner.login
        head = f'{owner}:{branch}'

        def existing_pull():
            return next(iter(origin.get_pulls(state='open', head=head, base=base_branch)), None)

        def result(pull):
            return {'pr_url': pull.html_url, 'number': pull.number, 'head_repo': pull.head.repo.full_name,
                    'head_branch': branch, 'base_branch': base_branch, 'base_sha': base_sha, 'forked': forked}

        head_repo = origin
        if forked:
            try:
                head_repo = github.get_repo(f'{owner}/{origin.name}')
            except GithubException as exc:
                if exc.status != 404:
                    raise
                head_repo = github.get_user().create_fork(origin)
            if not head_repo.fork or head_repo.source.full_name != (origin.source.full_name if origin.fork else origin.full_name):
                raise HTTPException(409, '같은 이름의 저장소가 있어 안전하게 Fork를 사용할 수 없습니다.')
            try:
                base_commit = head_repo.get_git_commit(base_sha)
            except GithubException as exc:
                if exc.status != 404:
                    raise
                raise HTTPException(409, 'Fork 동기화 중입니다. 잠시 후 다시 시도해 주세요.') from exc

        tree = head_repo.create_git_tree(entries, base_tree=base_commit.tree)
        try:
            head_sha = head_repo.get_git_ref(ref_name).object.sha
        except GithubException as exc:
            if exc.status != 404:
                raise
            commit = head_repo.create_git_commit('Simple Safe: proposed security fixes', tree, [base_commit])
            try:
                head_sha = head_repo.create_git_ref(f'refs/{ref_name}', commit.sha).object.sha
            except GithubException as conflict:
                if conflict.status != 422:
                    raise
                try:
                    head_sha = head_repo.get_git_ref(ref_name).object.sha
                except GithubException:
                    raise conflict
        head_commit = head_repo.get_git_commit(head_sha)
        if head_commit.tree.sha != tree.sha or [parent.sha for parent in head_commit.parents] != [base_sha]:
            raise HTTPException(409, '수정 브랜치가 변경되었습니다. GitHub에서 브랜치를 확인해 주세요.')
        pull = existing_pull()
        if pull:
            return result(pull)
        if resolve_branch(origin, base_branch)[1] != base_sha:
            raise HTTPException(409, 'PR 생성 중 기준 브랜치가 변경됐습니다. 최신 코드를 다시 분석해 주세요.')
        body = ('Simple Safe가 제안하고 사용자가 선택한 변경입니다. 병합 전에 리뷰와 테스트를 진행해 주세요.\n\n'
                f'기준 커밋 `{base_sha}`\n\n### 수정 파일\n' +
                '\n'.join(f"- `{patch['file']}`" for patch in patches))
        try:
            pull = origin.create_pull(title='Simple Safe: proposed security fixes', body=body,
                                      head=head if forked else branch, base=base_branch, draft=True)
        except GithubException as exc:
            if exc.status != 422 or not (pull := existing_pull()):
                raise
        return result(pull)
