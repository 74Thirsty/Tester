"""Real X11 clipboard round trip and Chromium HTTPS navigation (synthetic data only).
Run with the clean environment's Python from the repository root.
"""
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import os
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import tester


def main():
    browser = shutil.which('chromium')
    if not browser or not shutil.which('xclip'):
        raise SystemExit('BLOCKED: Chromium and xclip required')
    previous = subprocess.run(['xclip', '-selection', 'clipboard', '-o'], capture_output=True, timeout=5)
    with tempfile.TemporaryDirectory() as folder:
        directory = Path(folder)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                .serial_number(x509.random_serial_number()).not_valid_before(datetime.now(timezone.utc) - timedelta(minutes=1))
                .not_valid_after(datetime.now(timezone.utc) + timedelta(hours=1))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost')]), critical=False).sign(key, hashes.SHA256()))
        (directory / 'cert.pem').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        (directory / 'key.pem').write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        received = []
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                received.append(self.path)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'<title>Tester verification fixture</title>Controlled sign-in fixture')
            def log_message(self, *args):
                pass
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(directory / 'cert.pem', directory / 'key.pem')
        server.socket = context.wrap_socket(server.socket, server_side=True)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        path = directory / 'vault.json'
        master = 'synthetic-desktop-master'
        marker = '/verify-' + uuid.uuid4().hex
        url = f'https://localhost:{server.server_port}{marker}'
        account = tester.make_account('Desktop fixture', 'desktop@example.com', '', 'synthetic-desktop-secret', url, [], '')
        tester.encrypt(path, master, {'schema': 1, 'accounts': [account]})
        env = dict(os.environ, TESTER_VAULT=str(path), BROWSER=f'{browser} --headless --no-sandbox --disable-gpu --ignore-certificate-errors --user-data-dir={directory / "browser"} --dump-dom %s')
        entries = [[sys.executable, str(Path(tester.__file__).resolve())], [str(Path(sys.executable).parent / 'tester')]]
        try:
            for entry in entries:
                for command, value in [('copy', account['email']), ('copy-password', account['password']), ('open', None)]:
                    result = subprocess.run(entry + [command, account['id']], input=master + '\n', text=True, capture_output=True, env=env, timeout=40)
                    assert result.returncode == 0, result.stderr
                    if value is not None:
                        actual = subprocess.check_output(['xclip', '-selection', 'clipboard', '-o'], timeout=5).decode()
                        assert actual == value
                        print(f'PASS {entry} {command} <fixture-id>: actual X11 clipboard equals synthetic fixture; contents omitted')
                    else:
                        assert marker in received
                        assert tester.decrypt(path, master)['accounts'][0]['last_used_at']
                        print(f'PASS {entry} open <fixture-id>: Chromium fetched unique local HTTPS path; last_used_at persisted')
                        received.clear()
            for command, value in [('c', account['email']), ('p', account['password']), ('o', None)]:
                result = subprocess.run(entries[1] + ['tui'], input='\n'.join([master, command, account['id'], 'q', '']), text=True, capture_output=True, env=env, timeout=40)
                assert result.returncode == 0 and 'Error:' not in result.stdout, result.stderr
                if value is None:
                    assert marker in received
                else:
                    assert subprocess.check_output(['xclip', '-selection', 'clipboard', '-o'], timeout=5).decode() == value
                print(f'PASS installed tester tui: {command.upper()} -> fixture ID -> Q; real desktop boundary verified')
        finally:
            # Do not log or persist the user's previous clipboard contents.
            subprocess.run(['xclip', '-selection', 'clipboard'], input=previous.stdout if previous.returncode == 0 else b'', timeout=5, check=True)
            server.shutdown()
            server.server_close()
    print('PASS: clipboard restored; all fixtures and browser profile removed. HTTPS fixture uses a temporary self-signed certificate.')


if __name__ == '__main__':
    main()
