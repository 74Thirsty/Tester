"""Real Chromium fixture tests; explicitly NOT Google/Microsoft authentication proof.
Runs the production adapters and operations against a controlled local website.
"""
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import statistics
import tempfile
import threading
import time
from urllib.parse import urlsplit, parse_qs

from playwright.sync_api import sync_playwright
from tester_platforms import platform
from tester_sessions import operate, private_directory


def main():
    os.umask(0o077)
    revoked = set()
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            parsed = urlsplit(self.path)
            if parsed.path == '/frame':
                self.send_response(200)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                self.end_headers()
                self.wfile.write(b'<a id="O365_MainLink_Signout" href="/logout" target="_top">Sign out</a>')
                return
            params = parse_qs(parsed.query)
            identity = params.get('identity', [''])[0]
            if parsed.path == '/login' and identity:
                self.send_response(302)
                self.send_header('Set-Cookie', f'fixture={identity}; Path=/; Max-Age=3600; HttpOnly; SameSite=Lax')
                self.send_header('Location', '/mail')
                self.end_headers()
                return
            if parsed.path == '/logout':
                self.send_response(302)
                self.send_header('Set-Cookie', 'fixture=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax')
                self.send_header('Location', '/login')
                self.end_headers()
                return
            cookie = self.headers.get('Cookie', '')
            identity = next((x.strip().split('=', 1)[1] for x in cookie.split(';') if x.strip().startswith('fixture=')), '')
            if not identity or identity in revoked:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'<title>Fixture authentication</title><input type="password"><p>Sign in required</p>')
                return
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.end_headers()
            self.wfile.write((f'<a aria-label="Google Account: Fixture ({identity})">Profile</a>'
                             f'<button id="O365_MainLink_Me" aria-label="Account {identity}">Profile</button>'
                             f'<div id="mectrl_currentAccount_secondary">{identity}</div>'
                             '<main role="main">Synthetic mail fixture</main>'
                             '<iframe src="/frame"></iframe>').encode())
        def log_message(self, *args):
            pass
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    url = f'http://127.0.0.1:{server.server_port}'
    results = []
    try:
        with tempfile.TemporaryDirectory() as directory, sync_playwright() as driver:
            for key in ('google', 'microsoft'):
                provider = replace(platform(key), mail_url=url+'/mail', signup_url=url+'/signup', mail_hosts=('127.0.0.1',), auth_hosts=())
                # Fixture supplies an explicit login form. Production adapters use
                # provider-origin checks; this local subclass is not shipped as an adapter.
                class FixtureProvider:
                    mail_url = provider.mail_url
                    signup_url = provider.signup_url
                    def observe(self, page, expected):
                        if page.locator('input[type=password]').count():
                            return {'state': 'authentication_required', 'identity_match': False, 'checkpoint': 'Local fixture login required'}
                        return provider.observe(page, expected)
                    def signout(self, page):
                        return provider.signout(page)
                fixture = FixtureProvider()
                contexts = []
                paths = []
                try:
                    for i in range(2):
                        path = private_directory(Path(directory) / f'{key}-{i}')
                        paths.append(path)
                        started = time.perf_counter()
                        context = driver.chromium.launch_persistent_context(str(path), executable_path=shutil.which('chromium'), headless=False, chromium_sandbox=True)
                        context.set_default_timeout(1500)
                        contexts.append(context)
                        page = context.pages[0]
                        identity = f'{key}{i}@example.com'
                        page.goto(url+'/login?identity='+identity)
                        page.evaluate('(value) => {localStorage.setItem("identity", value); sessionStorage.setItem("identity", value)}', identity)
                        result, page = operate(context, page, fixture, identity, 'open')
                        assert result['state'] == 'authenticated'
                        results.append({'platform': key, 'sample': i, 'kind': 'initial_fixture_session', 'elapsed_ms': round((time.perf_counter()-started)*1000, 2), 'timings': result['timings']})
                    for sample in range(8):
                        i = sample % 2
                        context = contexts[i]
                        identity = f'{key}{i}@example.com'
                        before = time.perf_counter()
                        result, page = operate(context, context.pages[-1], fixture, identity, 'open')
                        assert result['state'] == 'authenticated'
                        assert page.evaluate('localStorage.getItem("identity")') == identity
                        assert page.evaluate('sessionStorage.getItem("identity")') == identity
                        results.append({'platform': key, 'sample': sample, 'kind': 'warm_fixture_switch', 'elapsed_ms': round((time.perf_counter()-before)*1000, 2), 'timings': result['timings']})
                    mismatch, _ = operate(contexts[0], contexts[0].pages[-1], fixture, f'{key}1@example.com', 'verify')
                    assert mismatch['state'] == 'identity_mismatch'
                    contexts[0].close()
                    contexts[0] = driver.chromium.launch_persistent_context(str(paths[0]), executable_path=shutil.which('chromium'), headless=False, chromium_sandbox=True)
                    restored, page = operate(contexts[0], contexts[0].pages[-1], fixture, f'{key}0@example.com', 'open')
                    assert restored['state'] == 'authenticated'
                    assert page.evaluate('localStorage.getItem("identity")') == f'{key}0@example.com'
                    revoked.add(f'{key}0@example.com')
                    expired, page = operate(contexts[0], page, fixture, f'{key}0@example.com', 'verify')
                    assert expired['state'] == 'authentication_required'
                    other, _ = operate(contexts[1], contexts[1].pages[-1], fixture, f'{key}1@example.com', 'verify')
                    assert other['state'] == 'authenticated'
                    revoked.clear()
                    page.goto(url+'/login?identity='+f'{key}0@example.com')
                    signed_out, page = operate(contexts[0], page, fixture, f'{key}0@example.com', 'signout')
                    assert signed_out['state'] == 'signed_out'
                    other, _ = operate(contexts[1], contexts[1].pages[-1], fixture, f'{key}1@example.com', 'verify')
                    assert other['state'] == 'authenticated'
                    print(f'PASS {key} adapter against LOCAL FIXTURE: identities, cookie/localStorage/sessionStorage isolation, restart, revocation, sign-out and unaffected peer')
                finally:
                    for context in contexts:
                        context.close()
        summary = {}
        for key in ('google', 'microsoft'):
            values = [r['elapsed_ms'] for r in results if r['platform'] == key and r['kind'] == 'warm_fixture_switch']
            summary[key] = {'n': len(values), 'median_ms': round(statistics.median(values), 2), 'slowest_ms': max(values)}
        Path('verification/session-performance.json').write_text(json.dumps({'conditions': 'Local HTTP fixture, real headful Chromium, persistent separate profiles, no real provider/network/manual authentication timings', 'samples': results, 'warm_summary': summary}, indent=2))
        print(json.dumps(summary))
        print('NOT live provider verification; no actual Google or Microsoft account was used.')
    finally:
        server.shutdown()
        server.server_close()


if __name__ == '__main__':
    main()
