"""Process-level workflows; only synthetic identities and disposable vaults."""
import contextlib
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import tester

ROOT = Path(__file__).resolve().parents[1]


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'vault.json'
        self.env = dict(os.environ, TESTER_VAULT=str(self.path))
        self.password = 'synthetic-test-master'
        self.log = []
        self.addCleanup(self.evidence)

    def evidence(self):
        directory = os.environ.get('TESTER_EVIDENCE_DIR')
        if directory:
            Path(directory).mkdir(parents=True, exist_ok=True)
            Path(directory, self.id() + '.log').write_text('\n'.join(self.log))

    def run_cli(self, args, inputs=(), code=0, installed=False):
        executable = Path(sys.executable).parent / ('tester.exe' if os.name == 'nt' else 'tester')
        command = [str(executable)] if installed else [sys.executable, str(ROOT / 'tester.py')]
        result = subprocess.run(command + args, input='\n'.join(inputs) + ('\n' if inputs else ''),
                                text=True, capture_output=True, env=self.env, cwd=self.temp.name, timeout=20)
        output = result.stdout + result.stderr
        self.log.append(f'COMMAND: {command + args!r}\nINPUT: synthetic fixture (passwords omitted)\nEXIT: {result.returncode}\n{output}')
        self.assertEqual(result.returncode, code, output)
        self.assertNotIn('Traceback', output)
        self.assertNotIn(self.password, output)
        return output

    def test_cli_lifecycle_both_entrypoints(self):
        for installed in (False, True):
            with self.subTest(installed=installed):
                self.path = Path(self.temp.name) / f'vault-{installed}.json'
                self.env['TESTER_VAULT'] = str(self.path)
                run = lambda args, inputs=(), code=0: self.run_cli(args, inputs, code, installed)
                self.assertIn('Tester', run(['--version']))
                self.assertIn('generate', run(['--help']))
                for action in ('init', 'tui', 'generate', 'add', 'list', 'show', 'copy', 'copy-password', 'open', 'delete', 'backup', 'restore'):
                    self.assertIn('usage:', run([action, '--help']))
                run(['list'], code=1)
                run(['init'], [self.password, self.password])
                run(['init'], [self.password, self.password], code=1)
                self.assertIn('No accounts', run(['list'], [self.password]))
                run(['list'], ['incorrect'], code=1)
                fields = [self.password, 'Example', 'fixture@example.com', '', 'synthetic-login-secret',
                          'https://example.com/login', 'QA, qa, local', 'Synthetic fixture']
                self.assertIn('Saved', run(['add'], fields))
                run(['add'], fields, code=1)
                self.assertIn('fixture@example.com', run(['list'], [self.password]))
                shown = run(['show', 'fixture@example.com'], [self.password])
                self.assertIn('qa', shown)
                self.assertNotIn('synthetic-login-secret', shown)
                run(['show', 'missing'], [self.password], code=1)
                backup = str(Path(self.temp.name) / f'backup-{installed}.vault')
                run(['backup', backup], [self.password])
                run(['backup', backup], [self.password], code=1)
                run(['restore', backup], [self.password], code=1)
                run(['delete', 'fixture@example.com'], [self.password, 'n'])
                self.assertIn('fixture@example.com', run(['list'], [self.password]))
                run(['delete', 'fixture@example.com'], [self.password, 'y'])
                self.assertIn('No accounts', run(['list'], [self.password]))
                run(['restore', backup, '--force'], [self.password])
                self.assertIn('fixture@example.com', run(['list'], [self.password]))
                fresh = Path(self.temp.name) / f'restored-{installed}.json'
                run(['--vault', str(fresh), 'restore', backup], [self.password])
                self.assertEqual(tester.decrypt(fresh, self.password)['accounts'], tester.decrypt(self.path, self.password)['accounts'])
                if os.name != 'nt':
                    self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

    def test_generate_and_errors(self):
        for installed in (False, True):
            example = self.run_cli(['generate', '--base', 'chris', '--domain', 'example.com', '--count', '5'], installed=installed)
            self.assertEqual(sum('@example.com' in line for line in example.splitlines()), 5)
            for plus in (False, True):
                args = ['generate', '--base', 'chris', '--domain', 'example.com', '--count', '100'] + (['--plus'] if plus else [])
                output = self.run_cli(args, installed=installed)
                addresses = [line for line in output.splitlines() if '@example.com' in line]
                self.assertEqual(len(set(addresses)), 100)
                self.assertFalse(self.path.exists())
            for flags in (['--count', '0'], ['--count', '101'], ['--count', 'abc'], ['--domain', '-invalid.com'], ['--base', 'a+b', '--plus']):
                # A leading hyphen is argparse syntax unless passed with '='.
                args = ['generate', '--base', 'chris', '--domain', 'example.com'] + flags
                expected = 2 if flags in (['--count', 'abc'], ['--domain', '-invalid.com']) else 1
                self.run_cli(args, code=expected, installed=installed)
            self.run_cli(['generate'], code=2, installed=installed)

    def test_tui_full_menu_and_reopen(self):
        inputs = [self.password, self.password, '?', 'g', 'chris', 'example.com', '2', 'n',
                  'g', 'chris', 'example.com', '', 'y', 'g', 'chris', 'example.com', 'abc',
                  'a', 'Example', 'fixture@example.com', '', '', '', 'QA', 'Synthetic fixture',
                  's', 'fixture@example.com', 'p', 'fixture@example.com', 'o', 'fixture@example.com',
                  's', 'missing', 'd', 'fixture@example.com', 'n', 'q']
        output = self.run_cli(['tui'], inputs)
        for expected in ('Saved.', 'Candidates only', 'No password saved', 'No sign-in URL saved', 'No account found', 'Choose one', 'Error:', 'Vault locked'):
            self.assertIn(expected, output)
        output = self.run_cli(['tui'], [self.password, 'd', 'fixture@example.com', 'y', 'q'], installed=True)
        self.assertIn('Deleted.', output)
        self.assertEqual(tester.decrypt(self.path, self.password)['accounts'], [])

    def test_eof_invalid_records_and_lock(self):
        self.run_cli(['init'], code=130)
        self.run_cli(['init'], ['short', 'short'], code=1)
        self.run_cli(['init'], [self.password, 'different'], code=1)
        self.run_cli(['init'], [self.password, self.password])
        self.run_cli(['tui'], [self.password], code=130)
        for email, url in [('invalid', ''), ('fixture@example.com', 'http://example.com'), ('fixture@example.com', 'https://example.com:wrong')]:
            self.run_cli(['add'], [self.password, 'Example', email, '', '', url, '', ''], code=1)
        with tester.FileLock(str(self.path) + '.lock'):
            self.run_cli(['list'], code=2)
        self.path.write_text('{bad json')
        self.run_cli(['list'], [self.password], code=1)

    def test_missing_optional_fields_and_desktop_failures(self):
        tester.encrypt(self.path, self.password, {'schema': 1, 'accounts': [tester.make_account('Example', 'fixture@example.com', '', '', '', [], '')]})
        self.run_cli(['copy-password', 'fixture@example.com'], [self.password], code=1)
        self.run_cli(['open', 'fixture@example.com'], [self.password], code=1)
        self.env.update(DISPLAY='', WAYLAND_DISPLAY='', PATH=self.temp.name)
        output = self.run_cli(['copy', 'fixture@example.com'], [self.password], code=1)
        self.assertIn('Clipboard utility missing', output)

    def test_ambiguous_email_requires_id(self):
        accounts = [tester.make_account(service, 'fixture@example.com', '', '', '', [], '')
                    for service in ('First', 'Second')]
        tester.encrypt(self.path, self.password, {'schema': 1, 'accounts': accounts})
        self.assertIn('multiple records', self.run_cli(['show', 'fixture@example.com'], [self.password], code=1))
        self.assertIn('First', self.run_cli(['show', accounts[0]['id']], [self.password]))


class RegressionTests(unittest.TestCase):
    def test_collision_retry_and_exhaustion(self):
        with patch('tester.secrets.choice', side_effect=list('aaaaaa' * 2 + 'bbbbbb')):
            self.assertEqual(tester.generate('a', 'example.com', 2, False), ['a.aaaaaa@example.com', 'a.bbbbbb@example.com'])
        with patch('tester.secrets.choice', return_value='a'), self.assertRaises(tester.TesterError):
            tester.generate('a', 'example.com', 2, False)

    def test_plus_never_silently_changes_mailbox(self):
        for base in ('a+b', 'a b', '.abc', 'abc-', 'a@b'):
            with self.subTest(base=base), self.assertRaises(tester.TesterError):
                tester.generate(base, 'example.com', 1, True)

    def test_oversized_write_preserves_vault(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'vault'
            tester.encrypt(path, 'synthetic', {'schema': 1, 'accounts': []})
            original = path.read_bytes()
            with patch('tester.MAX_VAULT_BYTES', 1), self.assertRaises(tester.TesterError):
                tester.encrypt(path, 'synthetic', {'schema': 1, 'accounts': []})
            self.assertEqual(path.read_bytes(), original)

    def test_tui_save_failure_rolls_back(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'vault'
            tester.encrypt(path, 'synthetic', {'schema': 1, 'accounts': []})
            account = tester.make_account('Example', 'fixture@example.com', '', '', '', [], '')
            with patch('tester.unlock', return_value=({'schema': 1, 'accounts': []}, 'synthetic')), patch('tester.prompt_account', return_value=account), patch('tester.save', side_effect=OSError('disk full')), patch('builtins.input', side_effect=['a', 's', account['id'], 'q']), contextlib.redirect_stdout(io.StringIO()) as output:
                tester.tui(path)
            self.assertIn('disk full', output.getvalue())
            self.assertIn('No account found', output.getvalue())

    def test_desktop_dispatch_and_failure(self):
        account = tester.make_account('Example', 'fixture@example.com', '', 'synthetic-secret', 'https://example.com', [], '')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'vault'
            tester.encrypt(path, 'synthetic', {'schema': 1, 'accounts': [account]})
            for opened in (True, False):
                with patch('tester.unlock', return_value=(tester.decrypt(path, 'synthetic'), 'synthetic')), patch('builtins.input', side_effect=['c', account['id'], 'p', account['id'], 'o', account['id'], 'q']), patch('tester.copy') as clipboard, patch('tester.webbrowser.open', return_value=opened), contextlib.redirect_stdout(io.StringIO()) as output:
                    tester.tui(path)
                self.assertEqual([call.args[0] for call in clipboard.call_args_list], ['fixture@example.com', 'synthetic-secret'])
                self.assertIn('Opened sign-in' if opened else 'Could not open', output.getvalue())
            self.assertIsNotNone(tester.decrypt(path, 'synthetic')['accounts'][0]['last_used_at'])

    def test_untrusted_record_urls_and_corrupt_envelopes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'vault'
            for url in ('http://example.com', 'https://example.com:bad', 'https://exa mple.com', 'https://user:secret@example.com'):
                account = tester.make_account('Example', 'fixture@example.com', '', '', '', [], '')
                account['login_url'] = url
                tester.encrypt(path, 'synthetic', {'schema': 1, 'accounts': [account]})
                with self.subTest(url=url), self.assertRaises(tester.TesterError):
                    tester.decrypt(path, 'synthetic')
            for data in ({'schema': 1, 'accounts': [{}]}, {'schema': 2, 'accounts': []}, {'schema': 1, 'accounts': 'invalid'}):
                tester.encrypt(path, 'synthetic', data)
                with self.assertRaises(tester.TesterError):
                    tester.decrypt(path, 'synthetic')

    @unittest.skipUnless(os.name == 'posix', 'POSIX terminal integration')
    def test_actual_terminal_password_hidden_and_menu(self):
        import pty
        import select
        import time
        with tempfile.TemporaryDirectory() as directory:
            parent, child = pty.openpty()
            command = [sys.executable, str(ROOT / 'tester.py'), '--vault', str(Path(directory) / 'vault'), 'tui']
            process = subprocess.Popen(command, stdin=child, stdout=child, stderr=child, start_new_session=True)
            os.close(child)
            transcript = bytearray()
            cursor = 0
            def expect(needle):
                nonlocal cursor
                deadline = time.monotonic() + 10
                while needle not in transcript[cursor:]:
                    if time.monotonic() > deadline:
                        self.fail(f'Terminal did not show {needle!r}')
                    if select.select([parent], [], [], 0.1)[0]:
                        transcript.extend(os.read(parent, 65536))
                cursor = transcript.index(needle, cursor) + len(needle)
            try:
                for prompt, answer in [(b'Master password:', 'synthetic-terminal-master'), (b'Confirm master password:', 'synthetic-terminal-master'), (b'Select:', 'g'), (b'Base name:', 'terminal'), (b'Domain:', 'example.com'), (b'Count', '1'), (b'[y/N]', 'y'), (b'Select:', 'q')]:
                    expect(prompt)
                    os.write(parent, (answer + '\n').encode())
                expect(b'Vault locked. Goodbye.')
                self.assertEqual(process.wait(timeout=10), 0)
                self.assertNotIn(b'synthetic-terminal-master', transcript)
                self.assertIn(b'terminal+', transcript)
                output = os.environ.get('TESTER_EVIDENCE_DIR')
                if output:
                    Path(output, 'terminal.log').write_text('COMMAND: ' + repr(command) + '\nPASSWORD INPUT: omitted; verified absent from terminal echo\n' + transcript.decode())
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()
                os.close(parent)

    def test_platform_paths_and_environment_override(self):
        with patch.dict(os.environ, {'TESTER_VAULT': '~/fixture-vault'}, clear=True):
            self.assertEqual(tester.vault_path(), Path.home() / 'fixture-vault')
        with patch.dict(os.environ, {'XDG_DATA_HOME': '/tmp/fixture-data'}, clear=True), patch('tester.sys.platform', 'linux'):
            if os.name == 'posix':
                self.assertEqual(tester.vault_path(), Path('/tmp/fixture-data/tester/vault.json'))
        if os.name == 'posix':
            with patch.dict(os.environ, {}, clear=True), patch('tester.sys.platform', 'darwin'):
                self.assertEqual(tester.vault_path(), Path.home() / 'Library/Application Support/Tester/vault.json')

    def test_clipboard_owner_cannot_inherit_cli_output(self):
        with patch('tester.shutil.which', return_value='/usr/bin/xclip'), patch('tester.subprocess.run') as run:
            tester.copy('synthetic clipboard fixture')
        self.assertEqual(run.call_args.kwargs['stdout'], subprocess.DEVNULL)
        self.assertEqual(run.call_args.kwargs['stderr'], subprocess.DEVNULL)
