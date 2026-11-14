"""Anonymous browser reachability only. Does not create accounts or sign in."""
import json
from pathlib import Path
import tempfile
from tester import platform_record
from tester_sessions import request, close_profile, SessionError


def main():
    results = []
    with tempfile.TemporaryDirectory() as folder:
        path = Path(folder) / 'probe.vault'
        for provider in ('google', 'microsoft'):
            for action in ('signin', 'signup'):
                account = platform_record(provider, 'unregistered-fixture@example.invalid', signup=action == 'signup')
                try:
                    result = request(path, account, action)
                    results.append({'platform': provider, 'operation': action, 'scope': 'anonymous public portal only', **result})
                    print(provider, action, result['state'], result.get('checkpoint_code', ''), flush=True)
                except SessionError:
                    results.append({'platform': provider, 'operation': action, 'state': 'browser_unavailable', 'scope': 'anonymous portal probe; no account action completed'})
                    print(provider, action, 'browser_unavailable', flush=True)
                finally:
                    try:
                        close_profile(path, account)
                    except SessionError:
                        print('Profile close could not be confirmed', flush=True)
    Path('verification/provider-portals.json').write_text(json.dumps(results, indent=2))
    print('No credentials entered, no signup submitted, no accounts created. NOT authenticated integration evidence.')


if __name__ == '__main__':
    main()
