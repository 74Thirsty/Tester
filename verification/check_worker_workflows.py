"""End-to-end CLI/menu + persistent workers using local synthetic provider pages.
The only substitution is the provider website. Never real-provider auth evidence.
"""
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import contextlib
import io
import json
import multiprocessing
import os
from pathlib import Path
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from urllib.parse import parse_qs, urlsplit

import tester
import tester_sessions
from tester_platforms import platform


def worker_fixture(directory, key, email, base):
    original = platform(key)
    provider = replace(original, mail_url=base+'/mail', signup_url=base+'/signup', mail_hosts=('127.0.0.1',), auth_hosts=())
    first = True
    def adapter(_):
        nonlocal first
        # Seed only the fixture's fake session on first navigation, never real credentials.
        seed = first and not (directory / 'seeded').exists()
        first = False
        (directory / 'seeded').touch(mode=0o600)
        selected = replace(provider, mail_url=base+'/login?identity='+email) if seed else provider
        class Fixture:
            mail_url = selected.mail_url
            signup_url = selected.signup_url
            def observe(self, page, expected):
                if page.locator('input[type=password]').count():
                    return {'state': 'authentication_required', 'identity_match': False, 'checkpoint': 'Synthetic authentication required'}
                return selected.observe(page, expected)
            def signout(self, page):
                return selected.signout(page)
        return Fixture()
    tester_sessions.platform = adapter
    tester_sessions.worker(directory)


def main():
    network_down = threading.Event()
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if network_down.is_set():
                self.close_connection = True
                return
            parsed = urlsplit(self.path)
            if parsed.path in ('/login', '/logout'):
                identity = parse_qs(parsed.query).get('identity', [''])[0]
                self.send_response(302)
                self.send_header('Set-Cookie', f'fixture={identity}; Path=/; Max-Age={3600 if identity else 0}; HttpOnly')
                self.send_header('Location', '/mail')
                self.end_headers()
                return
            identity = next((c.strip().split('=', 1)[1] for c in self.headers.get('Cookie', '').split(';') if c.strip().startswith('fixture=')), '')
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.end_headers()
            if identity:
                self.wfile.write((f'<a aria-label="Google Account: Fixture ({identity})">Account</a>'
                                 f'<button id="O365_MainLink_Me" aria-label="Account {identity}">Account</button>'
                                 '<main role="main">Local fixture</main><a id="O365_MainLink_Signout" href="/logout">Sign out</a>').encode())
            else:
                self.wfile.write(b'<input type=password><p>Local fixture requires authentication</p>')
        def log_message(self, *args):
            pass
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f'http://127.0.0.1:{server.server_port}'
    measurements = []
    processes = []
    try:
        with tempfile.TemporaryDirectory() as folder:
            vault = Path(folder)/'vault'
            master = 'synthetic-worker-master'
            data = {'schema': 1, 'accounts': []}
            tester.encrypt(vault, master, data)
            env = dict(os.environ, TESTER_VAULT=str(vault))
            installed = [str(Path(sys.executable).parent/'tester')]
            direct = [sys.executable, str(Path(tester.__file__).resolve())]
            def run(args, extra=(), expected=0, entry=installed):
                started = time.perf_counter()
                result = subprocess.run(entry+args, input='\n'.join([master, *extra, '']), text=True, capture_output=True, env=env, timeout=55)
                if result.returncode != expected:
                    safe = [line for line in result.stdout.splitlines() if line.startswith(('signout_pending:', 'browser_error:', 'identity_mismatch:', 'authentication_required:'))]
                    print('Unexpected fixture result:', safe, flush=True)
                # Never print raw exceptions/command output on unexpected failure.
                assert result.returncode == expected, f'Unexpected exit for {args[0]}: {result.returncode}'
                assert master not in result.stdout+result.stderr
                states = [line.split(':', 1)[0] for line in result.stdout.splitlines() if line.startswith(('authenticated:', 'signed_out:', 'authentication_required:', 'closed:'))]
                print(json.dumps({'command': entry+args, 'menu_inputs': list(extra), 'exit': result.returncode, 'observed_states': states, 'vault_password': 'omitted'}), flush=True)
                return result.stdout, round((time.perf_counter()-started)*1000, 2)
            for key in ('google', 'microsoft'):
                accounts = []
                for i in range(2):
                    email = f'{key}{i}@example.com'
                    run(['add-existing', key, email])
                    record = tester.find_account(tester.decrypt(vault, master), email)
                    accounts.append(record)
                    directory = tester_sessions.profile_directory(vault, record['browser_profile'])
                    process = multiprocessing.get_context('fork').Process(target=worker_fixture, args=(directory,key,email,base))
                    process.start()
                    processes.append(process)
                    deadline = time.monotonic()+10
                    while not tester_sessions.worker_running(directory) and time.monotonic()<deadline:
                        time.sleep(.05)
                    output, elapsed = run(['switch', record['id']])
                    assert 'authenticated:' in output
                    measurements.append({'platform': key, 'kind': 'initial_worker_cli', 'elapsed_ms': elapsed})
                for sample in range(8):
                    record = accounts[sample%2]
                    output, elapsed = run(['switch', record['id']], entry=direct if sample%2 else installed)
                    assert 'authenticated:' in output
                    timings = json.loads(next(line.split(': ', 1)[1] for line in output.splitlines() if line.startswith('Timings')))
                    measurements.append({'platform': key, 'kind': 'warm_worker_cli', 'elapsed_ms': elapsed, 'timings': timings})
                output, _ = run(['tui'], ['w', accounts[0]['id'], 'i', accounts[1]['id'], 'v', accounts[0]['id'], 'q'])
                assert output.count('authenticated:') == 3
                network_down.set()
                output, _ = run(['verify', accounts[0]['id']], expected=3)
                assert 'browser_error:' in output and 'Traceback' not in output
                network_down.clear()
                output, _ = run(['verify', accounts[0]['id']])
                assert 'authenticated:' in output
                print(f'PASS {key}: real fixture connection failure sanitized; subsequent navigation recovered', flush=True)
                output, _ = run(['signout', accounts[0]['id']])
                assert 'signed_out:' in output
                output, _ = run(['switch', accounts[0]['id']], expected=3)
                assert 'authentication_required:' in output
                output, _ = run(['switch', accounts[1]['id']])
                assert 'authenticated:' in output
                output, _ = run(['verify-signout', accounts[0]['id']])
                assert 'signed_out:' in output
                output, _ = run(['tui'], ['r', accounts[0]['id'], 'y', accounts[0]['id'], 'x', accounts[1]['id'], 'y', accounts[1]['id'], 'u', accounts[0]['id'], f'corrected-{key}@example.com', 'b', accounts[0]['id'], 'q'])
                assert 'Error:' not in output
                assert 'authentication_required:' in output and 'signed_out:' in output and 'closed:' in output
                output, _ = run(['remove', accounts[0]['id']])
                assert 'not deleted' in output
                assert not tester_sessions.profile_directory(vault, accounts[0]['browser_profile']).joinpath('browser').exists()
                print(f'PASS {key} LOCAL FIXTURE: installed/direct switch, menu W/I/V, exact identity, process reuse, persisted observations, sign-out verification, unaffected peer, local remove', flush=True)
            run(['close-sessions'])
            for record in tester.decrypt(vault, master)['accounts']:
                assert not tester_sessions.worker_running(tester_sessions.profile_directory(vault, record['browser_profile']))
            summaries = {}
            for key in ('google', 'microsoft'):
                samples = [r['elapsed_ms'] for r in measurements if r['platform']==key and r['kind']=='warm_worker_cli']
                summaries[key] = {'n': len(samples), 'median_ms': round(statistics.median(samples),2), 'slowest_ms': max(samples)}
            Path('verification/worker-performance.json').write_text(json.dumps({'conditions': 'Real CLI and browser workers; local synthetic provider only; includes Python startup, synthetic vault unlock/save and IPC; excludes human typing and real provider time', 'samples': measurements, 'summary': summaries}, indent=2))
            print(json.dumps(summaries), flush=True)
    finally:
        for process in processes:
            process.join(timeout=10)
            if process.is_alive():
                process.terminate()
                process.join(timeout=5)
        server.shutdown()
        server.server_close()


if __name__ == '__main__':
    main()
