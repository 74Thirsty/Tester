"""Isolated persistent browser workers, controlled through owner-only local files.

No TCP debugging ports; Playwright uses a private browser pipe. Workers never
receive the vault password and never persist page contents or navigation URLs.
"""
from __future__ import annotations
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
import uuid
from filelock import FileLock, Timeout
from tester_platforms import platform


class SessionError(Exception):
    pass


def windows_private_directory(path: Path) -> None:
    # Construct the complete DACL in memory and apply it once. Never reset to a
    # broad inherited ACL while a profile contains session data.
    script = '''$ErrorActionPreference = 'Stop'
$sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
$acl = New-Object System.Security.AccessControl.DirectorySecurity
$acl.SetOwner($sid)
$acl.SetAccessRuleProtection($true, $false)
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
$acl.AddAccessRule($rule)
Set-Acl -LiteralPath $env:TESTER_PROFILE_ACL_PATH -AclObject $acl
'''
    try:
        subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', script],
                       env=dict(os.environ, TESTER_PROFILE_ACL_PATH=str(path)),
                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       check=True, timeout=15)
    except (OSError, subprocess.SubprocessError):
        raise SessionError('Could not restrict the profile directory ACL to the current Windows user. No browser was started.') from None


def private_directory(path: Path) -> Path:
    path = path.absolute()
    for ancestor in (path, *path.parents):
        if ancestor.is_symlink() or (os.name == 'nt' and ancestor.exists() and getattr(ancestor.lstat(), 'st_file_attributes', 0) & 0x400):
            raise SessionError('Profile storage cannot traverse symlinks.')
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name == 'nt':
        windows_private_directory(path)
        return path
    if path.stat().st_uid != os.getuid():
        raise SessionError('Profile storage must belong to the current OS user.')
    path.chmod(0o700)
    return path


def profile_directory(vault: Path, profile_id: str) -> Path:
    if not re.fullmatch(r'[a-f0-9]{32}', profile_id):
        raise SessionError('Invalid browser profile identifier.')
    root = private_directory(vault.absolute().with_name(vault.name + '.profiles'))
    return private_directory(root / profile_id)


def write_json(path: Path, value: dict) -> None:
    if path.is_symlink():
        raise SessionError('Refusing symlink session artifact.')
    temporary = path.with_name('.' + uuid.uuid4().hex + '.tmp')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(value, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def worker_running(directory: Path) -> bool:
    try:
        with FileLock(str(directory / 'worker.lock'), timeout=0, mode=0o600):
            return False
    except Timeout:
        return True


def request(vault: Path, account: dict, action: str, timeout: float = 50) -> dict:
    started = time.perf_counter()
    directory = profile_directory(vault, account['browser_profile'])
    with FileLock(str(directory / 'client.lock'), timeout=2, mode=0o600):
        cold = not worker_running(directory)
        if cold:
            (directory / 'startup-error.json').unlink(missing_ok=True)
            # A separate process keeps browser contexts alive when the CLI exits.
            env = dict(os.environ)
            env.pop('DEBUG', None)  # Playwright debug traces can contain auth URLs.
            env.pop('PWDEBUG', None)
            subprocess.Popen([sys.executable, str(Path(__file__).resolve()), '--worker', str(directory)],
                             stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             start_new_session=True, env=env)
        correlation = uuid.uuid4().hex
        req = directory / f'{correlation}.request.json'
        response = directory / f'{correlation}.response.json'
        write_json(req, {'platform': account['platform'], 'email': account['email'], 'action': action,
                         'signup_pending': bool(account.get('signup_started_at') and not account.get('signup_identity_confirmed_at')),
                         'deadline': time.time() + timeout})
        try:
            while time.perf_counter() - started < timeout:
                if response.exists():
                    result = json.loads(response.read_text())
                    result['timings']['client_total_ms'] = round((time.perf_counter() - started) * 1000, 2)
                    result['timings']['cold_worker'] = cold
                    result['timings']['startup_ipc_and_scheduling_ms'] = round(max(0, result['timings']['client_total_ms'] - result['timings'].get('activation_ms', 0) - result['timings'].get('navigation_and_observation_ms', 0)), 2)
                    return result
                error = directory / 'startup-error.json'
                if error.exists():
                    raise SessionError(json.loads(error.read_text())['error'])
                time.sleep(0.05)
            raise SessionError('Browser did not respond in time. It may be busy or unavailable; retry. No authentication result was recorded.')
        finally:
            req.unlink(missing_ok=True)
            response.unlink(missing_ok=True)


def close_profile(vault: Path, account: dict) -> None:
    directory = profile_directory(vault, account['browser_profile'])
    if worker_running(directory):
        request(vault, account, 'close')
        deadline = time.monotonic() + 8
        while worker_running(directory) and time.monotonic() < deadline:
            time.sleep(0.05)
        if worker_running(directory):
            raise SessionError('Browser has not closed; profile kept intact. Retry after closing its windows.')


def forget_profile(vault: Path, account: dict) -> None:
    directory = profile_directory(vault, account['browser_profile'])
    close_profile(vault, account)
    # Only the validated, dedicated UUID directory is eligible for deletion.
    shutil.rmtree(directory)


def operate(context, page, provider, expected: str, action: str) -> tuple[dict, object]:
    """Only browser observations can produce authenticated/signed_out states."""
    started = time.perf_counter()
    fresh = False
    navigation_ms = 0.0
    if page is None or page.is_closed():
        page = context.new_page()
    page.bring_to_front()
    activated = time.perf_counter()
    if action == 'close':
        return {'state': 'closed', 'identity_match': False, 'fresh_check': False,
                'checkpoint': 'Browser closed; this does not sign out of the provider.',
                'timings': {'activation_ms': 0, 'navigation_and_observation_ms': 0}}, page
    if action == 'signup':
        # Never restart a checkpoint already visible in this persistent session.
        if page.url == 'about:blank':
            nav = time.perf_counter()
            page.goto(provider.signup_url, wait_until='domcontentloaded', timeout=25000)
            navigation_ms = (time.perf_counter() - nav) * 1000
        checkpoint = provider.observe(page, expected)
        observation = {'state': 'signup_pending', 'identity_match': False,
                       'checkpoint_code': checkpoint.get('checkpoint_code', 'signup'),
                       'checkpoint': 'Signup pending; creation is not confirmed. Complete signup, terms and verification yourself, then resume. ' + checkpoint['checkpoint']}
    else:
        if action == 'signout':
            before_signout = provider.observe(page, expected)
            if before_signout['state'] == 'identity_mismatch':
                return {**before_signout, 'fresh_check': False, 'timings': {}}, page
            if before_signout['state'] != 'authentication_required' and (before_signout['state'] != 'authenticated' or not provider.signout(page)):
                return {'state': 'signout_pending', 'identity_match': False, 'fresh_check': False,
                        'checkpoint': 'Use the provider account menu to sign out in this window, then run verify-signout. Closing the window does not sign out.',
                        'timings': {'activation_ms': round((activated-started)*1000, 2), 'navigation_and_observation_ms': 0}}, page
            page.wait_for_timeout(1000)
        observation = provider.observe(page, expected)
        checkpoint_visible = observation['state'] in {'authentication_required', 'authentication_pending'} and action in {'open', 'signin', 'resume'}
        if not checkpoint_visible:
            nav = time.perf_counter()
            if action in {'signout', 'verify-signout'}:
                # A new navigation must demand authentication after provider logout.
                page = context.new_page()
                page.bring_to_front()
            page.goto(provider.mail_url, wait_until='domcontentloaded', timeout=25000)
            fresh = True
            navigation_ms = (time.perf_counter() - nav) * 1000
            deadline = time.monotonic() + 4
            while True:
                observation = provider.observe(page, expected)
                if observation['state'] in {'authenticated', 'authentication_required', 'identity_mismatch'} or time.monotonic() >= deadline:
                    break
                page.wait_for_timeout(200)
            if observation['state'] == 'unknown' and getattr(provider, 'signin_url', '') and action in {'open', 'signin', 'resume', 'verify'}:
                # Microsoft's documented sign-in entry point; only use it when
                # direct mail navigation did not reach a recognizable app/login.
                page.goto(provider.signin_url, wait_until='domcontentloaded', timeout=25000)
                page.wait_for_timeout(1000)
                observation = provider.observe(page, expected)
        if action in {'signout', 'verify-signout'}:
            if observation['state'] == 'authentication_required':
                observation = {'state': 'signed_out', 'identity_match': False,
                               'checkpoint': 'Fresh mail navigation requires authentication in this profile. Other profiles were not changed.'}
            else:
                observation['checkpoint'] = 'Sign-out is NOT confirmed (observed state: ' + observation['state'] + '). Complete provider sign-out in this window, then run verify-signout.'
                observation['state'] = 'signout_pending'
    elapsed = (time.perf_counter() - started) * 1000
    observation.update(fresh_check=fresh, timings={'activation_ms': round((activated-started)*1000, 2),
                       'navigation_ms': round(navigation_ms, 2), 'navigation_and_observation_ms': round(elapsed-(activated-started)*1000, 2),
                       'usable_page_ms': round(elapsed, 2) if observation['state'] == 'authenticated' else None})
    return observation, page


def worker(directory: Path) -> None:
    os.umask(0o077)
    private_directory(directory)
    try:
        lock = FileLock(str(directory / 'worker.lock'), timeout=0, mode=0o600)
        with lock:
            try:
                executable = os.environ.get('TESTER_BROWSER') or shutil.which('google-chrome') or shutil.which('chromium')
                if executable and (not Path(executable).is_file() or not os.access(executable, os.X_OK)):
                    raise SessionError('Configured browser executable is unavailable.')
                from playwright.sync_api import sync_playwright
                with sync_playwright() as driver:
                    # No stealth flags, credential automation, remote-debugging ports,
                    # traces, screenshots or browser console logging.
                    context = driver.chromium.launch_persistent_context(
                        str(private_directory(directory / 'browser')), executable_path=executable,
                        headless=False, chromium_sandbox=True, accept_downloads=False,
                        args=['--no-first-run', '--no-default-browser-check', '--restore-last-session'])
                    context.set_default_timeout(1500)
                    page = context.pages[-1] if context.pages else context.new_page()
                    try:
                        while context.pages:
                            for req in directory.glob('*.request.json'):
                                response = req.with_name(req.name.replace('.request.json', '.response.json'))
                                try:
                                    payload = json.loads(req.read_text())
                                    if payload['deadline'] < time.time():
                                        req.unlink(missing_ok=True)
                                        continue
                                    action = payload['action']
                                    if action not in {'open', 'signin', 'signup', 'resume', 'verify', 'signout', 'verify-signout', 'close'}:
                                        raise ValueError('Invalid operation')
                                    if action == 'resume' and payload.get('signup_pending') and page.url == 'about:blank':
                                        action = 'signup'
                                    adapter = platform(payload['platform'])
                                    if action == 'resume' and page in context.pages:
                                        # A provider may finish authentication in a new tab.
                                        # Never select an older stale tab over an active MFA page.
                                        newer = context.pages[context.pages.index(page)+1:]
                                        for candidate in reversed(newer):
                                            if adapter.observe(candidate, payload['email'])['state'] == 'authenticated':
                                                page = candidate
                                                break
                                    result, page = operate(context, page, adapter, payload['email'], action)
                                except Exception:
                                    # Browser exceptions may contain full authentication URLs.
                                    result = {'state': 'browser_error', 'identity_match': False, 'fresh_check': False,
                                              'checkpoint': 'Browser/navigation failed. Check connectivity and provider availability, complete any visible checkpoint, then retry. No authentication success was recorded.',
                                              'timings': {}}
                                    action = ''
                                if req.exists():
                                    write_json(response, result)
                                req.unlink(missing_ok=True)
                                if action == 'close':
                                    return
                            if page.is_closed() and context.pages:
                                page = context.pages[-1]
                            if not page.is_closed():
                                page.wait_for_timeout(50)
                    finally:
                        context.close()
            except Exception:
                write_json(directory / 'startup-error.json', {'error': 'Browser unavailable. Install Playwright and Chromium (python -m playwright install chromium), ensure a graphical session and browser sandbox support, or set TESTER_BROWSER to a supported executable. No raw browser exception was logged.'})
    except Timeout:
        return


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '--worker':
        worker(Path(sys.argv[2]))
