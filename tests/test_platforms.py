import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import tester
from tester_platforms import platform
from tester_sessions import SessionError, profile_directory, write_json


class PlatformTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'vault.json'
        self.master = 'synthetic-platform-master'
        self.data = {'schema': 1, 'accounts': []}
        tester.encrypt(self.path, self.master, self.data)

    def add(self, provider='google', email='controlled@example.com', signup=False):
        with contextlib.redirect_stdout(io.StringIO()):
            return tester.add_platform(self.path, self.master, self.data, provider, email, signup)

    def test_add_existing_is_not_authentication_and_profiles_unique(self):
        first = self.add()
        second = self.add('microsoft')
        self.assertNotEqual(first['browser_profile'], second['browser_profile'])
        self.assertEqual(first['status'], 'unverified')
        self.assertEqual(first['password'], '')
        self.assertIsNone(first['session']['verified_at'])
        self.assertEqual(len(tester.decrypt(self.path, self.master)['accounts']), 2)
        with self.assertRaises(tester.TesterError):
            self.add()

    def test_no_record_when_add_write_fails(self):
        with patch('tester.save', side_effect=OSError('disk full')), self.assertRaises(OSError):
            self.add()
        self.assertEqual(self.data['accounts'], [])
        self.assertEqual(tester.decrypt(self.path, self.master)['accounts'], [])

    def test_observation_and_fresh_verification_are_distinct(self):
        account = self.add()
        result = {'state': 'authenticated', 'identity_match': True, 'fresh_check': False, 'checkpoint': 'fixture only', 'timings': {}}
        with patch('tester.session_request', return_value=result), contextlib.redirect_stdout(io.StringIO()):
            tester.platform_action(self.path, self.master, self.data, account['id'], 'switch')
        self.assertIsNone(self.data['accounts'][0]['session']['verified_at'])
        result['fresh_check'] = True
        with patch('tester.session_request', return_value=result), contextlib.redirect_stdout(io.StringIO()):
            tester.platform_action(self.path, self.master, self.data, account['id'], 'verify')
        self.assertIsNotNone(self.data['accounts'][0]['session']['verified_at'])

    def test_browser_action_save_failure_does_not_claim_success(self):
        account = self.add()
        result = {'state': 'authenticated', 'fresh_check': True, 'checkpoint': 'fixture', 'timings': {}}
        with patch('tester.session_request', return_value=result), patch('tester.save', side_effect=OSError('disk full')), self.assertRaisesRegex(tester.TesterError, 'may have occurred'):
            tester.platform_action(self.path, self.master, self.data, account['id'], 'switch')
        self.assertEqual(self.data['accounts'][0]['session']['state'], 'never_checked')

    def test_signup_remains_pending_at_checkpoint(self):
        result = {'state': 'signup_pending', 'fresh_check': False, 'checkpoint': 'Complete provider verification yourself', 'timings': {}}
        with patch('tester.session_request', return_value=result):
            self.add(signup=True)
        record = tester.decrypt(self.path, self.master)['accounts'][0]
        self.assertEqual(record['status'], 'signup_pending')
        self.assertNotIn('signup_identity_confirmed_at', record)

    def test_remove_does_not_call_provider_signout(self):
        account = self.add()
        with patch('tester.forget_profile') as forget, patch('tester.session_request') as remote, contextlib.redirect_stdout(io.StringIO()):
            tester.platform_action(self.path, self.master, self.data, account['id'], 'remove')
        forget.assert_called_once()
        remote.assert_not_called()
        self.assertEqual(tester.decrypt(self.path, self.master)['accounts'], [])

    def test_corrupt_and_shared_profiles_rejected(self):
        first = self.add()
        second = self.add('microsoft')
        for value in ('../../escape', first['browser_profile']):
            self.data['accounts'][1]['browser_profile'] = value
            tester.encrypt(self.path, self.master, self.data)
            with self.assertRaises(tester.TesterError):
                tester.decrypt(self.path, self.master)

    @unittest.skipUnless(os.name == 'posix', 'POSIX profiles')
    def test_profile_permissions_paths_and_symlinks(self):
        first = self.add()
        path = profile_directory(self.path, first['browser_profile'])
        self.assertEqual(path.stat().st_mode & 0o777, 0o700)
        write_json(path / 'fixture.json', {'state': 'synthetic'})
        self.assertEqual((path / 'fixture.json').stat().st_mode & 0o777, 0o600)
        with self.assertRaises(SessionError):
            profile_directory(self.path, '../escape')
        link = Path(self.temp.name) / 'link'
        link.symlink_to(path)
        with self.assertRaises(SessionError):
            profile_directory(link / 'vault', first['browser_profile'])

    def test_cli_and_menu_platform_record_lifecycle(self):
        executable = Path(sys.executable).parent / ('tester.exe' if os.name == 'nt' else 'tester')
        for entry in ([sys.executable, str(Path(tester.__file__).resolve())], [str(executable)]):
            env = dict(os.environ, TESTER_VAULT=str(self.path))
            def run(args, inputs, expected=0):
                output = subprocess.run(entry + args, input='\n'.join(inputs)+'\n', capture_output=True, text=True, env=env, timeout=10)
                self.assertEqual(output.returncode, expected, output.stderr)
                self.assertNotIn(self.master, output.stdout+output.stderr)
                return output.stdout
            for name in ('accounts', 'add-existing', 'signup', 'signin', 'switch', 'resume', 'verify', 'signout', 'verify-signout', 'remove', 'close', 'close-sessions', 'set-identifier'):
                run([name, '--help'], [])
            email = ('direct' if len(entry) == 2 else 'installed') + '@example.com'
            self.assertIn('unverified', run(['add-existing', 'google', email], [self.master]))
            self.assertIn('cached', run(['accounts'], [self.master]))
            menu_path = Path(self.temp.name) / 'new.vault'
            if not menu_path.exists():
                self.assertIn('No accounts', run(['--vault', str(menu_path), 'tui'], [self.master, self.master, 'e', 'microsoft', email, 'q']))
            if os.name == 'posix':
                self.assertIn('not deleted', run(['remove', email], [self.master]))

    def test_provider_urls_separate_from_api_authorization(self):
        self.assertEqual(platform('google').mail_url, 'https://mail.google.com/mail/u/0/')
        self.assertEqual(platform('microsoft').signup_url, 'https://signup.live.com/')
        with self.assertRaises(ValueError):
            platform('resend')

    def test_correct_signup_identifier_keeps_profile_but_invalidates_status(self):
        account = self.add()
        profile = account['browser_profile']
        with contextlib.redirect_stdout(io.StringIO()):
            tester.set_identifier(self.path, self.master, self.data, account['id'], 'corrected@example.com')
        record = tester.decrypt(self.path, self.master)['accounts'][0]
        self.assertEqual(record['browser_profile'], profile)
        self.assertEqual(record['email'], 'corrected@example.com')
        self.assertEqual(record['status'], 'unverified')
        self.assertIsNone(record['session']['verified_at'])

    def test_locked_vault_never_starts_browser(self):
        self.add()
        with patch('tester.session_request') as browser, patch('tester.password_prompt', return_value='incorrect'), patch('sys.argv', ['tester', '--vault', str(self.path), 'switch', 'controlled@example.com']), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
            tester.main()
        self.assertEqual(error.exception.code, 1)
        browser.assert_not_called()

    def test_checkpoint_resume_does_not_navigate_away(self):
        from unittest.mock import Mock
        from tester_sessions import operate
        page = Mock()
        page.is_closed.return_value = False
        provider = Mock()
        provider.observe.return_value = {'state': 'authentication_required', 'identity_match': False, 'checkpoint': 'MFA fixture'}
        result, _ = operate(Mock(), page, provider, 'controlled@example.com', 'resume')
        self.assertEqual(result['state'], 'authentication_required')
        page.goto.assert_not_called()
        self.assertFalse(result['fresh_check'])

    def test_signout_wrong_identity_is_refused(self):
        from unittest.mock import Mock
        from tester_sessions import operate
        page = Mock()
        page.is_closed.return_value = False
        provider = Mock()
        provider.observe.return_value = {'state': 'identity_mismatch', 'identity_match': False, 'checkpoint': 'Wrong identity fixture'}
        result, _ = operate(Mock(), page, provider, 'controlled@example.com', 'signout')
        self.assertEqual(result['state'], 'identity_mismatch')
        provider.signout.assert_not_called()
        page.goto.assert_not_called()

    def test_auth_origin_without_form_is_not_signout_proof(self):
        from unittest.mock import Mock
        page = Mock()
        page.url = 'https://accounts.google.com/example'
        page.locator.return_value.count.return_value = 0
        result = platform('google').observe(page, 'controlled@example.com')
        self.assertEqual(result['state'], 'authentication_pending')
        self.assertFalse(result['identity_match'])

    def test_profile_request_failure_preserves_last_observation(self):
        account = self.add()
        with patch('tester.session_request', side_effect=SessionError('Browser unavailable')), self.assertRaises(SessionError):
            tester.platform_action(self.path, self.master, self.data, account['id'], 'switch')
        self.assertEqual(tester.decrypt(self.path, self.master)['accounts'][0]['session']['state'], 'never_checked')

    def test_windows_acl_failure_is_sanitized(self):
        from tester_sessions import windows_private_directory
        with patch('tester_sessions.subprocess.run', side_effect=subprocess.CalledProcessError(1, ['sensitive-placeholder'])), self.assertRaises(SessionError) as error:
            windows_private_directory(self.path.parent)
        self.assertNotIn('sensitive-placeholder', str(error.exception))

    def test_menu_number_selects_exact_platform_record(self):
        first = self.add('google', 'first@example.com')
        self.add('microsoft', 'second@example.com')
        with patch('tester.unlock', return_value=(self.data, self.master)), patch('builtins.input', side_effect=['1', 'q']), patch('tester.platform_action') as action, contextlib.redirect_stdout(io.StringIO()):
            tester.tui(self.path)
        self.assertEqual(action.call_args.args[3:], (first['id'], 'switch'))

    def test_tui_retains_saved_signup_intent_when_browser_fails(self):
        with patch('tester.unlock', return_value=(self.data, self.master)), patch('builtins.input', side_effect=['n', 'google', 'pending@example.com', 'q']), patch('tester.session_request', side_effect=SessionError('Browser unavailable')), contextlib.redirect_stdout(io.StringIO()) as output:
            tester.tui(self.path)
        self.assertIn('pending@example.com', output.getvalue())
        self.assertEqual(tester.decrypt(self.path, self.master)['accounts'][0]['email'], 'pending@example.com')

    def test_failed_remove_save_reports_partial_local_effect(self):
        account = self.add()
        with patch('tester.forget_profile'), patch('tester.save', side_effect=OSError('disk full')), self.assertRaisesRegex(tester.TesterError, 'record remains'):
            tester.platform_action(self.path, self.master, self.data, account['id'], 'remove')
        self.assertEqual(len(tester.decrypt(self.path, self.master)['accounts']), 1)

    @unittest.skipUnless(os.name == 'posix', 'POSIX worker startup')
    def test_actual_missing_browser_startup_is_sanitized(self):
        from tester_sessions import request, worker_running
        import time
        account = self.add()
        invalid_path = str(Path(self.temp.name) / 'nonexistent-sensitive-placeholder')
        with patch.dict(os.environ, {'TESTER_BROWSER': invalid_path}), self.assertRaises(SessionError) as error:
            request(self.path, account, 'open', timeout=10)
        self.assertIn('Browser unavailable', str(error.exception))
        self.assertNotIn('sensitive-placeholder', str(error.exception))
        directory = profile_directory(self.path, account['browser_profile'])
        deadline = time.monotonic()+2
        while worker_running(directory) and time.monotonic()<deadline:
            time.sleep(.05)
        self.assertFalse(worker_running(directory))
        self.assertFalse(list(directory.glob('*.request.json')))

    def test_signup_navigation_failure_returns_nonzero_but_keeps_intent(self):
        failure = {'state': 'browser_error', 'fresh_check': False, 'checkpoint': 'Synthetic network failure', 'timings': {}}
        with patch('tester.password_prompt', return_value=self.master), patch('tester.session_request', return_value=failure), patch('sys.argv', ['tester', '--vault', str(self.path), 'signup', 'google', 'pending@example.com']), contextlib.redirect_stdout(io.StringIO()), self.assertRaises(SystemExit) as error:
            tester.main()
        self.assertEqual(error.exception.code, 3)
        self.assertEqual(tester.decrypt(self.path, self.master)['accounts'][0]['session']['state'], 'browser_error')
