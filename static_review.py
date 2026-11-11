"""Read-only Python checks. Source is parsed without importing or running it."""
import ast

RULES = {
    'pickle.loads': ('CWE-502', 'pickle 역직렬화', '신뢰할 수 없는 입력은 JSON 등 데이터 전용 형식으로 처리하세요.'),
    'pickle.load': ('CWE-502', 'pickle 역직렬화', '역직렬화 대상의 출처와 무결성을 확인하세요.'),
    'subprocess.run': ('CWE-78', '셸 실행 사용', '셸이 필요 없다면 인자 배열과 shell=False를 사용하세요.'),
    'subprocess.Popen': ('CWE-78', '셸 실행 사용', '셸이 필요 없다면 인자 배열과 shell=False를 사용하세요.'),
    'requests.get': ('CWE-295', 'TLS 인증서 검증 비활성화', '서버 인증서를 검증하고 필요한 경우 신뢰할 CA를 지정하세요.'),
    'requests.post': ('CWE-295', 'TLS 인증서 검증 비활성화', '서버 인증서를 검증하고 필요한 경우 신뢰할 CA를 지정하세요.'),
}


def scan_python(code):
    try:
        tree = ast.parse(code)
    except SyntaxError as exc:
        return [], f'Python 문법 오류 ({exc.lineno}행)'
    except RecursionError:
        return [], 'Python 구문 복잡도 초과 · 검사 미완료'

    # Resolve direct imports conservatively. Ignore aliases rebound anywhere in the file.
    imports = {}
    rebound = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for item in node.names:
                imports[item.asname or item.name.split('.')[0]] = item.name if item.asname else item.name.split('.')[0]
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            for item in node.names:
                imports[item.asname or item.name] = f'{node.module}.{item.name}'
        elif isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            rebound.add(node.id)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.arg)):
            rebound.add(node.arg if isinstance(node, ast.arg) else node.name)

    lines = code.encode('utf-8').splitlines(keepends=True)
    findings = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            alias, suffix = func.value.id, f'.{func.attr}'
        elif isinstance(func, ast.Name):
            alias, suffix = func.id, ''
        else:
            continue
        if alias not in imports or alias in rebound:
            continue
        name = imports[alias] + suffix
        if name not in RULES:
            continue
        flag = {'subprocess': ('shell', True), 'requests': ('verify', False)}.get(name.split('.')[0])
        if flag and not any(keyword.arg == flag[0] and isinstance(keyword.value, ast.Constant)
                            and keyword.value.value is flag[1] for keyword in node.keywords):
            continue
        cwe, title, description = RULES[name]
        if node.lineno == node.end_lineno:
            excerpt = lines[node.lineno - 1][node.col_offset:node.end_col_offset]
        else:
            excerpt = lines[node.lineno - 1][node.col_offset:]
        findings.append({
            'title': title, 'cwe': cwe, 'line': node.lineno, 'rule': name,
            'description': description, 'bad_code': excerpt[:1000].decode('utf-8', errors='ignore').rstrip(),
            'secure_code': '', 'severity': None, 'status': 'pattern',
        })
    status = 'Python AST 검사 완료'
    if len(findings) > 60:
        status += ' · 처음 60개 패턴 표시'
    return findings, status
