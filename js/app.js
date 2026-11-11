const $ = id => document.getElementById(id);
const sample = "import requests\n\nresponse = requests.get('https://example.com', verify=False)\n";
const state = {
  files: [{path: 'example.py', code: sample}],
  active: 0,
  version: 0,
  analyzedVersion: -1,
  findings: [],
  patches: [],
  source: null,
  repository: null,
  selection: new Map(),
  publishing: false,
};
const limits = {count: 12, file: 80000, total: 250000};
let toastTimer;

function element(tag, text, className) {
  const node = document.createElement(tag);
  node.textContent = text ?? '';
  if (className) node.className = className;
  return node;
}

function toast(message, link) {
  const node = $('toast');
  node.replaceChildren(document.createTextNode(message));
  if (link) {
    const anchor = element('a', ' PR 열기');
    anchor.href = link;
    anchor.target = '_blank';
    anchor.rel = 'noopener noreferrer';
    node.append(anchor);
  }
  node.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { node.hidden = true; }, 9000);
}

async function api(url, payload) {
  const response = await fetch(url, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(payload),
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const detail = Array.isArray(data.detail) ? data.detail.map(item => item.msg).join(' · ') : data.detail;
    throw new Error(detail || '요청에 실패했습니다.');
  }
  return data;
}

function invalidate(message = '입력 변경됨 · 재분석 필요') {
  state.version++;
  $('pr-btn').disabled = true;
  $('approve-patches').checked = false;
  $('result-state').hidden = true;
  $('empty-state').hidden = false;
  $('status-text').textContent = message;
}

function updateGutter() {
  $('gutter').textContent = $('code').value.split('\n').map((_, index) => index + 1).join('\n');
}

function showActiveFile() {
  const file = state.files[state.active];
  $('active-file').replaceChildren(...state.files.map((entry, index) => new Option(entry.path, index)));
  $('active-file').value = state.active;
  $('code').value = file.code;
  $('file-path').value = file.path;
  $('code').readOnly = $('file-path').readOnly = Boolean(state.source);
  $('edit-local').hidden = !state.source;
  updateGutter();
}

function setFiles(files, source = null) {
  state.files = files;
  state.source = source;
  state.active = 0;
  showActiveFile();
  $('file-name').textContent = source
    ? `${source.repo} · ${source.branch} · ${source.sha.slice(0, 12)} · ${files.length}개 파일`
    : `${files.length}개 파일`;
  invalidate();
}

function renderRepositoryFiles() {
  const query = $('github-filter').value.trim().toLowerCase();
  const rows = state.repository.files.filter(file => file.path.toLowerCase().includes(query)).map(file => {
    const label = element('label', '', 'patch-option');
    const checkbox = element('input');
    checkbox.type = 'checkbox';
    checkbox.checked = state.selection.has(file.path);
    checkbox.onchange = () => {
      if (checkbox.checked) state.selection.set(file.path, file.size);
      else state.selection.delete(file.path);
      renderRepositorySelection();
    };
    label.append(checkbox, document.createTextNode(` ${file.path} (${file.size.toLocaleString()} B)`));
    return label;
  });
  $('github-file-list').replaceChildren(...rows);
  renderRepositorySelection();
}

function renderRepositorySelection() {
  const bytes = [...state.selection.values()].reduce((sum, size) => sum + size, 0);
  const count = state.selection.size;
  $('github-selection').textContent = `${count}/12개 선택 · ${bytes.toLocaleString()}/250,000 B`;
  $('github-load').disabled = !count || count > limits.count || bytes > limits.total;
}

$('github-connect').onsubmit = async event => {
  event.preventDefault();
  const button = event.submitter;
  button.disabled = true;
  state.repository = null;
  $('github-files').hidden = true;
  $('github-message').textContent = 'GitHub에서 파일 목록을 불러오는 중…';
  try {
    state.repository = await api('/api/github/repository', {
      repo: $('github-repo').value.trim(),
      branch: $('github-branch').value.trim(),
    });
    const {repo, branch, sha, truncated, files} = state.repository;
    state.selection.clear();
    $('github-filter').value = '';
    $('github-message').textContent = `${repo} · ${branch} · ${sha.slice(0, 12)} · ${files.length}개 표시` +
      (truncated ? ' · 목록 일부만 표시됩니다.' : '');
    renderRepositoryFiles();
    $('github-files').hidden = false;
  } catch (error) {
    $('github-message').textContent = error.message;
  } finally {
    button.disabled = false;
  }
};
$('github-filter').oninput = renderRepositoryFiles;
$('github-load').onclick = async () => {
  const repository = state.repository;
  const version = state.version;
  const {repo, branch, sha} = repository;
  $('github-load').disabled = true;
  try {
    const data = await api('/api/github/files', {repo, branch, sha, paths: [...state.selection.keys()]});
    if (repository === state.repository && version === state.version) {
      setFiles(data.files, {repo: data.repo, branch: data.branch, sha: data.sha});
    }
  } catch (error) {
    toast(error.message);
  } finally {
    if (state.repository) renderRepositorySelection();
  }
};

function renderFindings(selected = 0) {
  const labels = {pattern: '정적 패턴', needs_validation: '추가 검토 필요'};
  $('vuln-list').replaceChildren(...state.findings.map((finding, index) => {
    const row = element('li');
    const button = element('button', '', `vuln ${index === selected ? 'active' : ''}`);
    button.type = 'button';
    const top = element('div', '', 'vuln-top');
    top.append(element('strong', `${finding.title} · ${finding.file}:${finding.line}`),
      element('span', labels[finding.status], 'badge'));
    button.append(top, element('p', finding.description));
    button.onclick = () => renderFindings(index);
    row.append(button);
    return row;
  }));
  const finding = state.findings[selected];
  if (!finding) $('vuln-list').append(element('li', '실행한 검사에서 표시할 항목이 없습니다.'));
  $('bad-code').textContent = finding?.bad_code || '—';
  const patch = finding && state.patches.find(item => item.file === finding.file);
  $('secure-code').textContent = patch?.diff || (finding ? '이 파일에 검사를 통과한 수정안이 없습니다.' : '—');
}

function renderPatches() {
  $('patch-list').replaceChildren(...state.patches.map(patch => {
    const label = element('label', '', 'patch-option');
    const checkbox = element('input');
    checkbox.type = 'checkbox';
    checkbox.checked = patch.selected;
    checkbox.onchange = () => {
      patch.selected = checkbox.checked;
      $('approve-patches').checked = false;
      renderPreview();
    };
    label.append(checkbox, document.createTextNode(` ${patch.file} · ${patch.check}`));
    return label;
  }));
  renderPreview();
}

function renderPreview() {
  const patches = state.patches.filter(patch => patch.selected);
  $('patch-preview').textContent = patches.map(patch => patch.diff).join('\n\n') || '수정할 파일을 선택하세요.';
  $('pr-submit').disabled = state.publishing || !patches.length;
}

$('analyze-btn').onclick = async () => {
  const version = state.version;
  const useAI = $('use-ai').checked;
  $('analyze-btn').disabled = true;
  $('loading-state').hidden = false;
  $('empty-state').hidden = true;
  $('result-state').hidden = true;
  $('pr-btn').disabled = true;
  $('status-text').textContent = '소스 검사 중';
  try {
    const result = await api('/analyze', {files: state.files, language: $('language').value, use_ai: useAI});
    if (version !== state.version) return;
    state.findings = result.vulnerabilities;
    state.patches = result.patches.map(patch => ({...patch, selected: false}));
    state.analyzedVersion = version;
    const statuses = {
      disabled: 'Gemini 분석 꺼짐',
      unconfigured: 'Gemini 키 미설정',
      failed: 'Gemini 분석 실패',
      reviewed: 'Gemini 분석 완료',
    };
    $('analysis-summary').textContent = [statuses[result.ai_status], result.summary, ...(result.notices || [])].filter(Boolean).join(' · ');
    $('coverage').replaceChildren(...result.coverage.map(item => element('li', `${item.file} · ${item.static}`)));
    $('stats').replaceChildren(...[['pattern', '정적 패턴'], ['needs_validation', '추가 검토 필요']].map(([type, label]) => {
      const box = element('div', '', 'stat');
      box.append(element('b', state.findings.filter(item => item.status === type).length), element('span', label));
      return box;
    }));
    renderFindings();
    $('pr-btn').disabled = !state.patches.length;
    $('result-state').hidden = false;
    $('status-text').textContent = '검사 완료';
  } catch (error) {
    if (version !== state.version) return;
    $('empty-state').hidden = false;
    $('status-text').textContent = '검사 실패';
    toast(error.message);
  } finally {
    $('analyze-btn').disabled = false;
    $('loading-state').hidden = true;
  }
};

async function addFiles(input) {
  const files = Array.from(input).filter(file => /\.(js|jsx|ts|tsx|py|java|php|go|rb|cs|c|cpp|html|css|sql)$/i.test(file.name));
  if (!files.length || files.length > limits.count || files.some(file => file.size > limits.file)
      || files.reduce((sum, file) => sum + file.size, 0) > limits.total) {
    toast('지원되는 파일을 최대 12개, 파일당 80KB, 합계 250KB까지 선택하세요.');
    return;
  }
  try {
    const version = state.version;
    const entries = await Promise.all(files.map(async file => ({
      path: file.webkitRelativePath?.split('/').slice(1).join('/') || file.name,
      code: new TextDecoder('utf-8', {fatal: true, ignoreBOM: true}).decode(await file.arrayBuffer()),
    })));
    if (version === state.version) setFiles(entries);
  } catch {
    toast('선택한 파일을 UTF-8 소스로 읽을 수 없습니다.');
  }
}

$('active-file').onchange = () => {
  state.active = Number($('active-file').value);
  showActiveFile();
};
$('edit-local').onclick = () => setFiles(state.files);
$('code').oninput = () => {
  state.files[state.active].code = $('code').value;
  updateGutter();
  invalidate();
};
$('file-path').oninput = () => {
  state.files[state.active].path = $('file-path').value.trim();
  $('active-file').selectedOptions[0].textContent = state.files[state.active].path;
  invalidate();
};
$('code').onscroll = () => { $('gutter').scrollTop = $('code').scrollTop; };
$('language').onchange = $('use-ai').onchange = () => invalidate();
$('file-input').onchange = event => addFiles(event.target.files);
$('folder-input').onchange = event => addFiles(event.target.files);
for (const type of ['dragenter', 'dragover', 'dragleave', 'drop']) {
  $('dropzone').addEventListener(type, event => {
    event.preventDefault();
    $('dropzone').classList.toggle('dragover', type === 'dragenter' || type === 'dragover');
    if (type === 'drop') addFiles(event.dataTransfer.files);
  });
}

$('pr-btn').onclick = () => {
  const source = state.source;
  $('repo').readOnly = $('base-branch').readOnly = Boolean(source);
  $('repo').value = source?.repo || '';
  $('base-branch').value = source?.branch || '';
  $('pr-base').textContent = source ? `분석한 기준 커밋 ${source.sha.slice(0, 12)}` : '선택한 원본 파일을 GitHub 브랜치와 대조합니다.';
  $('pr-error').hidden = true;
  $('approve-patches').checked = false;
  renderPatches();
  $('pr-modal').hidden = false;
};

function closePR() {
  if (!state.publishing) $('pr-modal').hidden = true;
}

$('pr-cancel').onclick = closePR;
$('pr-modal').onclick = event => { if (event.target === $('pr-modal')) closePR(); };
$('repo').oninput = $('base-branch').oninput = () => { $('approve-patches').checked = false; };
$('pr-submit').onclick = async () => {
  const error = $('pr-error');
  const repo = $('repo').value.trim();
  const patches = state.patches.filter(patch => patch.selected);
  if (!$('approve-patches').checked || !repo || !patches.length || state.analyzedVersion !== state.version) {
    error.textContent = '저장소와 최신 패치를 선택한 뒤 변경 사항을 검토하고 승인해 주세요.';
    error.hidden = false;
    return;
  }
  state.publishing = true;
  error.hidden = true;
  renderPreview();
  try {
    const data = await api('/api/github/pull-request', {
      repo, base_branch: $('base-branch').value.trim(),
      base_sha: state.source?.sha,
      patches: patches.map(({file, original_code, patched_code}) => ({file, original_code, patched_code})),
      approved: true,
    });
    $('pr-modal').hidden = true;
    toast(`Draft PR #${data.number}`, data.pr_url);
    $('status-text').textContent = 'Draft PR 준비 완료';
  } catch (failure) {
    error.textContent = failure.message;
    error.hidden = false;
  } finally {
    state.publishing = false;
    renderPreview();
  }
};

showActiveFile();
