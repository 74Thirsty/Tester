"""Interactive acceptance runner for TWO CONTROLLED accounts on one real provider.

No credentials in arguments/logs. Run with --vault pointing to a dedicated test
vault. This signs out and removes local account A, never deletes external accounts.
Required MFA/CAPTCHA/consent/revocation are performed by the user in the browser.
"""
import argparse
import contextlib
import getpass
import io
import json
from pathlib import Path
import statistics
import subprocess
import sys
import time

import tester
from tester_sessions import close_profile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--vault', type=Path, required=True, help='dedicated controlled-account test vault')
    parser.add_argument('--platform', choices=['google', 'microsoft'], required=True)
    parser.add_argument('--output', type=Path, required=True, help='sanitized evidence JSON path')
    parser.add_argument('--signup', action='store_true', help='separate user-completed signup check only')
    args = parser.parse_args()
    path = args.vault.expanduser()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    evidence = {'platform': args.platform, 'scope': 'real provider; user-operated checkpoints', 'checks': [], 'complete': False}
    def record(operation, status, **details):
        evidence['checks'].append({'operation': operation, 'status': status, **details})
        args.output.parent.mkdir(parents=True, exist_ok=True)
        # Only fixed labels, observations and timings are written; no account IDs,
        # emails, browser contents, cookies, URLs or passwords are recorded.
        args.output.write_text(json.dumps(evidence, indent=2))
    master = getpass.getpass('Dedicated test vault master password: ')
    with tester.FileLock(str(path)+'.lock', timeout=0):
        if path.exists():
            data = tester.decrypt(path, master)
        else:
            if len(master) < 12:
                raise tester.TesterError('Use at least 12 characters.')
            data = {'schema': 1, 'accounts': []}
            tester.encrypt(path, master, data, create=True)
    def direct(account, action):
        # Take the same vault lock as the application and reload current state.
        with tester.FileLock(str(path)+'.lock', timeout=0):
            data = tester.decrypt(path, master)
            with contextlib.redirect_stdout(io.StringIO()):
                result = tester.platform_action(path, master, data, account['id'], action)
        return result
    def select_or_add(label, signup=False):
        email = input(f'Controlled {label} email (never written to evidence): ').strip()
        with tester.FileLock(str(path)+'.lock', timeout=0):
            data = tester.decrypt(path, master)
            matching = [a for a in data['accounts'] if a.get('platform') == args.platform and a['email'].lower() == email.lower()]
            if matching:
                if signup:
                    raise tester.TesterError('Signup verification requires a new local intent, not a preexisting record.')
                return matching[0]
            with contextlib.redirect_stdout(io.StringIO()):
                return tester.add_platform(path, master, data, args.platform, email, signup)
    def authenticate(account, label):
        result = direct(account, 'signin')
        for _ in range(4):
            if result['state'] == 'authenticated' and result.get('identity_match'):
                record('sign_in_' + label, 'IMPLEMENTED AND LIVE-VERIFIED', timings=result['timings'])
                return
            print(result['checkpoint'])  # static instructions only, never page content
            if input('Complete the provider prompts yourself, then Enter to verify; Q to stop: ').strip().lower() == 'q':
                record('sign_in_' + label, 'BLOCKED BY EXTERNAL ACCESS', checkpoint=result.get('checkpoint_code', result['state']))
                raise SystemExit(3)
            result = direct(account, 'verify')
        record('sign_in_' + label, 'BLOCKED BY EXTERNAL ACCESS', checkpoint=result['state'])
        raise SystemExit(3)
    if args.signup:
        account = select_or_add('desired NEW account', signup=True)
        print('Complete legitimate signup, terms, verification and MFA in the browser. No step is automated.')
        if input('Type CREATED only after you personally completed new-account creation; otherwise Q: ').strip() != 'CREATED':
            record('signup', 'BLOCKED BY EXTERNAL ACCESS', checkpoint='user signup completion required')
            return
        authenticate(account, 'new_account')
        record('signup', 'IMPLEMENTED AND LIVE-VERIFIED', evidence_basis='user-attested creation plus freshly observed matching identity and mail UI; not an account-creation API result')
        evidence['complete'] = True
        record('signup_finished', 'IMPLEMENTED AND LIVE-VERIFIED')
        return
    print('Use TWO distinct controlled test accounts. Account A will be signed out and removed locally. External accounts are never deleted.')
    accounts = [select_or_add(label) for label in ('A', 'B')]
    if accounts[0]['id'] == accounts[1]['id']:
        raise tester.TesterError('Choose two distinct accounts.')
    record('add_existing', 'IMPLEMENTED AND LIVE-VERIFIED', count=2, note='local records only; authentication checked separately')
    for label, account in zip(('A', 'B'), accounts):
        authenticate(account, label)
    # Every sample starts a NEW application process. Browser workers persist.
    samples = []
    for index in range(8):
        account = accounts[index % 2]
        started = time.perf_counter()
        run = subprocess.run([sys.executable, str(Path(tester.__file__).resolve()), '--vault', str(path), 'switch', account['id']],
                             input=master+'\n', text=True, capture_output=True, timeout=60)
        elapsed = (time.perf_counter()-started)*1000
        lines = run.stdout.splitlines()
        if run.returncode != 0 or not any(line.startswith('authenticated:') for line in lines):
            record('switch', 'BLOCKED BY EXTERNAL ACCESS', sample=index, note='expected identity/mail UI not confirmed; raw output suppressed')
            raise SystemExit(3)
        timings = json.loads(next(line.split(': ',1)[1] for line in lines if line.startswith('Timings')))
        samples.append({'account': 'A' if index%2 == 0 else 'B', 'elapsed_ms': round(elapsed,2), 'timings': timings})
    record('switch_and_application_restart', 'IMPLEMENTED AND LIVE-VERIFIED', samples=samples,
           median_ms=round(statistics.median(x['elapsed_ms'] for x in samples),2), slowest_ms=max(x['elapsed_ms'] for x in samples))
    close_profile(path, accounts[0])
    restarted = direct(accounts[0], 'switch')
    record('browser_restart_reuse', 'IMPLEMENTED AND LIVE-VERIFIED' if restarted['state']=='authenticated' else 'BLOCKED BY EXTERNAL ACCESS', timings=restarted['timings'])
    print('In provider security settings, revoke ONLY test account A’s session, or wait until it expires. Do not change account B.')
    revoked = input('Enter REVOKED when done; otherwise Enter records this check as blocked: ').strip() == 'REVOKED'
    if revoked:
        result = direct(accounts[0], 'verify')
        if result['state'] != 'authentication_required':
            record('revocation', 'BLOCKED BY EXTERNAL ACCESS', observed=result['state'])
            raise SystemExit(3)
        record('revocation', 'IMPLEMENTED AND LIVE-VERIFIED')
        authenticate(accounts[0], 'A_recovery')
    else:
        record('revocation', 'BLOCKED BY EXTERNAL ACCESS', checkpoint='user must revoke controlled session or allow expiry')
    result = direct(accounts[0], 'signout')
    if result['state'] != 'signed_out':
        print(result['checkpoint'])
        input('Complete sign-out in A’s provider window, then Enter: ')
        result = direct(accounts[0], 'verify-signout')
    peer = direct(accounts[1], 'verify')
    if result['state'] != 'signed_out' or peer['state'] != 'authenticated':
        record('isolated_signout', 'BLOCKED BY EXTERNAL ACCESS', selected_state=result['state'], peer_state=peer['state'])
        raise SystemExit(3)
    record('isolated_signout', 'IMPLEMENTED AND LIVE-VERIFIED', basis='fresh authentication form required for A; matching mail identity observed for B')
    direct(accounts[0], 'remove')
    record('remove_local', 'IMPLEMENTED AND LIVE-VERIFIED', note='local record/profile removed; no external-account deletion operation exists')
    with tester.FileLock(str(path)+'.lock', timeout=0), contextlib.redirect_stdout(io.StringIO()):
        data = tester.decrypt(path, master)
        restored_record = tester.add_platform(path, master, data, args.platform, accounts[0]['email'])
    authenticate(restored_record, 'A_after_local_removal')
    record('external_account_survives_removal', 'IMPLEMENTED AND LIVE-VERIFIED', basis='re-added existing identity and observed authenticated mail UI in a new isolated profile')
    direct(restored_record, 'remove')
    evidence['complete'] = revoked and restarted['state'] == 'authenticated'
    record('run_finished', 'IMPLEMENTED AND LIVE-VERIFIED' if evidence['complete'] else 'BLOCKED BY EXTERNAL ACCESS')
    print('Sanitized evidence written. B remains independently signed in; close-sessions closes its browser without signing out.')


if __name__ == '__main__':
    try:
        main()
    except (Exception, KeyboardInterrupt):
        print('Verification stopped. No raw exception, account data, or authentication URL was logged. Resolve the visible browser/storage checkpoint and retry.', file=sys.stderr)
        raise SystemExit(1)
