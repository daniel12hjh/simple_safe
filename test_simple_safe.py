"""Run with python -m unittest -v."""
import base64
import json
from contextlib import contextmanager
from types import SimpleNamespace as Object
import unittest
from unittest.mock import MagicMock, Mock, PropertyMock, patch

from fastapi import HTTPException
from fastapi.testclient import TestClient
from github import GithubException

from github_pr import create_security_pull_request
from main import SourceFile, app, check_path, sanitize_result, validate_sources, validate_syntax


class SecurityTests(unittest.TestCase):
    def test_traversal_rejected(self):
        for path in ('../evil.py', '/etc/passwd.py', '.env', 'foo\\bar.py', 'src/.env.py', 'src//app.py'):
            with self.subTest(path=path), self.assertRaises(HTTPException):
                check_path(path)

    def test_duplicate_rejected(self):
        with self.assertRaises(HTTPException):
            validate_sources([SourceFile(path='a.py', code='a=1'), SourceFile(path='a.py', code='a=2')])

    def test_review_recovers_unique_evidence_and_requires_matching_original(self):
        files = [SourceFile(path='src/a.py', code='x=1\n')]
        finding = {'file': 'src/a.py', 'line': 1, 'evidence': 'x=1', 'severity': 'high'}
        change = {'file': 'src/a.py', 'original_code': 'x=1\n', 'patched_code': 'x=3\n'}
        review = sanitize_result({'vulnerabilities': [finding], 'patches': [change]}, files)
        self.assertEqual(review['vulnerabilities'][0]['status'], 'needs_validation')
        self.assertIsNone(review['vulnerabilities'][0]['severity'])
        self.assertIn('+x=3', review['patches'][0]['diff'])
        wrong_line = dict(finding, line=2)
        recovered = sanitize_result({'vulnerabilities': [wrong_line], 'patches': [change]}, files)
        self.assertEqual(recovered['vulnerabilities'][0]['line'], 1)
        self.assertEqual(len(recovered['patches']), 1)
        missing = dict(finding, evidence='x=9')
        wrong_original = dict(change, original_code='x=2\n')
        new_risk = dict(change, patched_code='import pickle\nx = pickle.loads(data)\n')
        for candidate, proposed in [(missing, change), (finding, wrong_original), (finding, new_risk)]:
            with self.subTest(candidate=candidate, proposed=proposed):
                self.assertEqual(sanitize_result({'vulnerabilities': [candidate], 'patches': [proposed]}, files)['patches'], [])

    def test_java_review_recovers_excerpt_and_prepares_exact_edits(self):
        original = 'class Main {\r\n  int n = Integer.parseInt(input);\r\n}\r\n'
        files = [SourceFile(path='src/Main.java', code=original)]
        finding = {'file': 'src/Main.java', 'line': 50, 'evidence': 'Integer.parseInt(input)'}
        change = {'file': 'src/Main.java', 'edits': [
            {'before': 'Integer.parseInt(input)', 'after': 'Integer.parseInt(input.trim())'},
        ]}
        review = sanitize_result({'summary': '입력 처리', 'vulnerabilities': [finding], 'patches': [change]}, files)
        self.assertEqual(review['vulnerabilities'][0]['line'], 2)
        self.assertEqual(review['patches'][0]['original_code'], original)
        self.assertEqual(review['patches'][0]['patched_code'], original.replace('parseInt(input)', 'parseInt(input.trim())'))
        change['edits'].append({'before': 'parseInt(input)', 'after': 'parseInt(value)'})
        self.assertEqual(sanitize_result({'vulnerabilities': [finding], 'patches': [change]}, files)['patches'], [])

    def test_unanchored_summary_explains_missing_results(self):
        review = sanitize_result({'summary': 'Possible issue', 'vulnerabilities': []}, [
            SourceFile(path='a.py', code='pass'),
        ])
        self.assertEqual(review['summary'], '')
        self.assertTrue(review['notices'])
        self.assertEqual(review['patches'], [])

    def test_python_syntax_rejects_invalid_code(self):
        for source in ('def broken(:', 'return 1'):
            with self.subTest(source=source), self.assertRaises(HTTPException):
                validate_syntax('a.py', source)

    def test_local_static_scan_and_coverage(self):
        client = TestClient(app, base_url='http://127.0.0.1')
        result = client.post('/analyze', json={'use_ai': False, 'files': [
            {'path': 'a.py', 'code': 'import requests as r\nr.get(url, verify=False)'},
            {'path': 'b.js', 'code': 'let x = 1;'},
        ]})
        self.assertEqual(result.status_code, 200)
        data = result.json()
        self.assertEqual(data['ai_status'], 'disabled')
        self.assertEqual(data['vulnerabilities'][0]['cwe'], 'CWE-295')
        self.assertEqual(data['coverage'][1]['static'], '정적 규칙 미지원')
        self.assertEqual(client.get('/health', headers={'Host': 'untrusted.example'}).status_code, 400)
        self.assertEqual(client.post('/analyze', headers={'Origin': 'http://untrusted.example'}, json={}).status_code, 403)


    def test_ai_candidate_and_patch_through_api(self):
        client = TestClient(app, base_url='http://127.0.0.1')
        original = 'import requests\nr = requests.get(url, verify=False)\n'
        revised = 'import requests\nr = requests.get(url)\n'
        model = MagicMock()
        model.__enter__.return_value.models.generate_content.return_value.text = json.dumps({
            'vulnerabilities': [{'file': 'a.py', 'line': 2, 'evidence': 'verify=False'}],
            'patches': [{'file': 'a.py', 'original_code': original, 'patched_code': revised}],
        })
        with patch('main.genai.Client', return_value=model), patch('main.rate_limit'), patch.dict(
            'os.environ', {'GEMINI_API_KEY': 'test'},
        ):
            response = client.post('/analyze', json={'files': [{'path': 'a.py', 'code': original}], 'use_ai': True})
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data['ai_status'], 'reviewed')
        self.assertEqual([finding['status'] for finding in data['vulnerabilities']], ['pattern', 'needs_validation'])
        self.assertEqual(data['patches'][0]['patched_code'], revised)


class GitHubTests(unittest.TestCase):
    def setUp(self):
        self.sha = 'a' * 40
        self.repo = Mock(default_branch='main', full_name='team/project')
        self.repo.owner.login = 'team'
        self.repo.permissions.push = True
        self.repo.get_branch.return_value.commit.sha = self.sha
        base = Object(sha=self.sha, tree=Object(sha='tree-base'))
        tree = Object(sha='tree-new')
        updated = Object(sha='commit-new', tree=tree, parents=[base])
        self.repo.get_git_commit.side_effect = {self.sha: base, updated.sha: updated}.__getitem__
        self.repo.get_git_tree.return_value = Object(truncated=False, tree=[
            Object(path='a.py', sha='blob', size=4, mode='100644', type='blob'),
            Object(path='b.py', sha='blob', size=4, mode='100755', type='blob'),
            Object(path='link.py', sha='blob', size=4, mode='120000', type='blob'),
        ])
        self.repo.get_git_blob.return_value = Object(encoding='base64', content=base64.b64encode(b'x=1\n'))
        self.repo.create_git_tree.return_value = tree
        self.repo.create_git_commit.return_value = updated
        self.ref = Object(object=Object(sha=updated.sha))
        self.repo.create_git_ref.return_value = self.ref
        self.pull = Object(html_url='https://github.com/team/project/pull/1', number=1,
                           head=Object(repo=Object(full_name='team/project')))
        self.repo.create_pull.return_value = self.pull

    @contextmanager
    def repository(self, token, repo):
        yield None, self.repo

    def publish(self, files, sha=None):
        with patch('github_pr.github_repository', self.repository):
            return create_security_pull_request(token='test', repo='team/project', base_branch='',
                expected_sha=sha or self.sha,
                patches=[{'file': file, 'original_code': 'x=1\n', 'patched_code': 'x=2\n'} for file in files])

    def test_multi_file_commit_and_retry(self):
        # PyGithub loads the ref object lazily, so the missing-ref error occurs on .object.
        missing = Mock()
        type(missing).object = PropertyMock(side_effect=GithubException(404, {}, None))
        self.repo.get_git_ref.side_effect = [missing, self.ref]
        self.repo.get_pulls.side_effect = [[], [self.pull]]
        self.assertEqual(self.publish(['b.py', 'a.py']), self.publish(['a.py', 'b.py']))
        self.repo.create_git_ref.assert_called_once()
        self.repo.create_git_commit.assert_called_once()
        self.repo.create_pull.assert_called_once()
        self.assertTrue(self.repo.create_pull.call_args.kwargs['draft'])
        entries = self.repo.create_git_tree.call_args.args[0]
        self.assertEqual([(entry._identity['path'], entry._identity['mode']) for entry in entries],
                         [('a.py', '100644'), ('b.py', '100755')])

    def test_stale_branch_and_symlink_stop_before_writes(self):
        for files, sha in [(['a.py'], 'b' * 40), (['link.py'], self.sha)]:
            with self.assertRaises(HTTPException) as failure:
                self.publish(files, sha)
            self.assertEqual(failure.exception.status_code, 409)
        self.repo.create_git_tree.assert_not_called()
        self.repo.create_git_ref.assert_not_called()

    def test_repository_browse_and_load_snapshot(self):
        client = TestClient(app, base_url='http://127.0.0.1', client=('127.0.0.1', 5000))
        with patch('main.github_repository', self.repository), patch.dict('os.environ', {'GITHUB_TOKEN': 'test'}):
            response = client.post('/api/github/repository', json={'repo': 'team/project'})
            self.assertEqual(response.status_code, 200)
            self.assertEqual([file['path'] for file in response.json()['files']], ['a.py', 'b.py'])
            params = {'repo': 'team/project', 'sha': self.sha, 'paths': ['a.py']}
            response = client.post('/api/github/files', json=params)
            self.assertEqual(response.json()['files'], [{'path': 'a.py', 'code': 'x=1\n'}])
            self.assertEqual(client.post('/api/github/files', json=dict(params, sha='b' * 40)).status_code, 409)


    def test_pr_route_requires_approval_and_checks_patch(self):
        client = TestClient(app, base_url='http://127.0.0.1', client=('127.0.0.1', 5000))
        self.repo.get_git_ref.side_effect = GithubException(404, {}, None)
        self.repo.get_pulls.return_value = []
        change = {'file': 'a.py', 'original_code': 'x=1\n', 'patched_code': 'x=2\n'}
        payload = {'repo': 'team/project', 'base_sha': self.sha, 'patches': [change]}
        route = '/api/github/pull-request'
        with patch('github_pr.github_repository', self.repository), patch.dict('os.environ', {'GITHUB_TOKEN': 'test'}):
            self.assertEqual(client.post(route, json=payload).status_code, 422)
            unsafe = dict(change, patched_code='import pickle\nx=pickle.loads(data)\n')
            self.assertEqual(client.post(route, json=dict(payload, approved=True, patches=[unsafe])).status_code, 422)
            self.repo.create_git_ref.assert_not_called()
            response = client.post(route, json=dict(payload, approved=True))
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json()['pr_url'], self.pull.html_url)


if __name__ == '__main__':
    unittest.main()
