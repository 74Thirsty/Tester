#!/usr/bin/env python3
"""Tester: encrypted local email identity manager."""
from __future__ import annotations

import argparse
import base64
import copy as copy_module
import getpass
import json
import os
import re
import secrets
import shutil
import string
import subprocess
import sys
import tempfile
import time
import uuid
import webbrowser
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from filelock import FileLock, Timeout as LockTimeout
from tester_platforms import PLATFORMS, platform
from tester_sessions import SessionError, request as session_request, close_profile, forget_profile

VERSION = "1.0.0"
AAD = b"tester-vault-v1"
MAX_VAULT_BYTES = 16 * 1024 * 1024
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


class TesterError(Exception):
    pass


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def vault_path() -> Path:
    override = os.environ.get("TESTER_VAULT")
    if override:
        return Path(override).expanduser()
    if os.name == "nt":
        return Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData/Local")) / "Tester" / "vault.json"
    if sys.platform == "darwin":
        return Path.home() / "Library/Application Support/Tester/vault.json"
    return Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local/share")) / "tester" / "vault.json"


def derive(password: str, salt: bytes) -> bytes:
    if not password:
        raise TesterError("Master password cannot be empty.")
    return Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(password.encode())


def b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def encrypt(path: Path, password: str, data: dict, *, create: bool = False) -> None:
    """Write an authenticated vault atomically without changing parent-directory permissions."""
    path = path.expanduser()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.is_symlink():
        raise TesterError("Refusing to read or replace a vault symlink.")
    salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
    ciphertext = AESGCM(derive(password, salt)).encrypt(
        nonce, json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode(), AAD
    )
    envelope = json.dumps({"version": 1, "kdf": "scrypt-n32768-r8-p1", "cipher": "AES-256-GCM",
                           "salt": b64(salt), "nonce": b64(nonce), "ciphertext": b64(ciphertext)})
    if len(envelope.encode("utf-8")) > MAX_VAULT_BYTES:
        raise TesterError("Vault exceeds the 16 MiB safety limit; no changes saved.")
    fd, tmp = tempfile.mkstemp(prefix=".tester-", dir=path.parent)
    try:
        if os.name != "nt":
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            out.write(envelope)
            out.flush()
            os.fsync(out.fileno())
        if create:
            try:
                os.link(tmp, path)
            except FileExistsError as exc:
                raise TesterError(f"Vault already exists: {path}") from exc
            except OSError as exc:
                if path.exists():
                    raise TesterError(f"Vault already exists: {path}") from exc
                raise TesterError(f"Could not safely create vault: {exc}") from exc
        else:
            if path.exists() and not path.is_file():
                raise TesterError("Vault path is not a regular file.")
            os.replace(tmp, path)
            tmp = ""
        try:
            if os.name != "nt":
                os.chmod(path, 0o600)
        except OSError:
            pass
    finally:
        if tmp and os.path.exists(tmp):
            os.unlink(tmp)

def decrypt(path: Path, password: str) -> dict:
    try:
        if path.is_symlink():
            raise TesterError("Refusing to open a vault symlink.")
        if not path.is_file():
            raise TesterError("Vault does not exist or is not a regular file.")
        if path.stat().st_size > MAX_VAULT_BYTES:
            raise TesterError("Vault exceeds the 16 MiB safety limit.")
        box = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(box, dict) or box.get("version") != 1:
            raise TesterError("Unsupported or invalid vault format.")
        if box.get("kdf") != "scrypt-n32768-r8-p1" or box.get("cipher") != "AES-256-GCM":
            raise TesterError("Vault cryptographic parameters are unsupported or invalid.")
        salt = base64.b64decode(box["salt"], validate=True)
        nonce = base64.b64decode(box["nonce"], validate=True)
        encrypted = base64.b64decode(box["ciphertext"], validate=True)
        if len(salt) != 16 or len(nonce) != 12 or len(encrypted) < 16:
            raise ValueError("Invalid salt, nonce, or ciphertext length")
        plain = AESGCM(derive(password, salt)).decrypt(nonce, encrypted, AAD)
        data = json.loads(plain.decode("utf-8"))
        if not isinstance(data, dict) or data.get("schema") != 1 or not isinstance(data.get("accounts"), list):
            raise TesterError("Vault data schema is invalid.")
        required = {"id", "service", "email", "username", "password", "login_url", "status", "tags", "notes", "created_at", "updated_at", "last_used_at"}
        for account in data["accounts"]:
            if not isinstance(account, dict) or not required.issubset(account):
                raise TesterError("Vault contains an invalid account record.")
            string_fields = ("id", "service", "email", "username", "password", "login_url", "status", "notes", "created_at", "updated_at")
            if not all(isinstance(account[k], str) for k in string_fields):
                raise TesterError("Vault contains invalid account field types.")
            if not isinstance(account["tags"], list) or not all(isinstance(tag, str) for tag in account["tags"]):
                raise TesterError("Vault contains invalid account tags.")
            if account["last_used_at"] is not None and not isinstance(account["last_used_at"], str):
                raise TesterError("Vault contains an invalid last-used timestamp.")
            valid_email(account["email"])
            valid_login_url(account["login_url"])
            if 'platform' in account:
                validate_platform_account(account)
        profiles = [a['browser_profile'] for a in data['accounts'] if 'platform' in a]
        if len(profiles) != len(set(profiles)):
            raise TesterError('Vault contains shared browser profiles; account isolation cannot be guaranteed.')
        return data
    except TesterError:
        raise
    except InvalidTag as exc:
        raise TesterError("Incorrect master password or vault integrity check failed.") from exc
    except (OSError, KeyError, ValueError, TypeError, UnicodeError) as exc:
        raise TesterError(f"Could not read vault: {exc}") from exc

def password_prompt(confirm: bool = False) -> str:
    value = getpass.getpass("Master password: ")
    if confirm:
        if value != getpass.getpass("Confirm master password: "):
            raise TesterError("Passwords did not match.")
        if len(value) < 12:
            raise TesterError("Use a master password with at least 12 characters.")
    return value


def unlock(path: Path) -> tuple[dict, str]:
    if not path.exists():
        raise TesterError(f"No vault at {path}. Run 'tester init' first.")
    password = password_prompt()
    return decrypt(path, password), password


def save(path: Path, password: str, data: dict) -> None:
    data["updated_at"] = now()
    encrypt(path, password, data)


def backup_vault(path: Path, destination: Path, password: str) -> None:
    """Create a verified, encrypted, no-clobber copy of a vault."""
    path, destination = path.expanduser(), destination.expanduser()
    if path.resolve() == destination.resolve():
        raise TesterError("Backup destination must differ from the active vault.")
    decrypt(path, password)
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if destination.exists() or destination.is_symlink():
        raise TesterError(f"Backup destination already exists: {destination}")
    fd, temporary = tempfile.mkstemp(prefix=".tester-backup-", dir=destination.parent)
    try:
        with os.fdopen(fd, "wb") as output, path.open("rb") as source:
            shutil.copyfileobj(source, output)
            output.flush()
            os.fsync(output.fileno())
        if os.name != "nt":
            os.chmod(temporary, 0o600)
        try:
            os.link(temporary, destination)
        except FileExistsError as exc:
            raise TesterError(f"Backup destination already exists: {destination}") from exc
        except OSError as exc:
            if destination.exists():
                raise TesterError(f"Backup destination already exists: {destination}") from exc
            raise TesterError(f"Could not safely create backup: {exc}") from exc
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def restore_vault(path: Path, source: Path, password: str, *, force: bool = False) -> None:
    """Restore a verified encrypted backup, refusing replacement by default."""
    path, source = path.expanduser(), source.expanduser()
    if path.resolve() == source.resolve():
        raise TesterError("Restore source must differ from the active vault.")
    data = decrypt(source, password)
    if path.exists() and not force:
        raise TesterError(f"Vault already exists: {path}. Use --force to replace it.")
    encrypt(path, password, data, create=not force)


def valid_email(value: str) -> str:
    value = value.strip()
    if len(value) > 254 or not EMAIL_RE.fullmatch(value):
        raise TesterError("Enter a valid email address.")
    return value


def generate(base: str, domain: str, count: int, plus: bool) -> list[str]:
    if plus and not re.fullmatch(r"[a-zA-Z0-9._-]+", base.strip()):
        raise TesterError("For plus aliases, enter the exact existing mailbox local part using letters, digits, dots, underscores or hyphens; it will not be rewritten.")
    if plus and (base.strip().startswith((".", "-")) or base.strip().endswith((".", "-"))):
        raise TesterError("Plus alias base cannot start or end with a dot or hyphen.")
    base = re.sub(r"[^a-zA-Z0-9._-]+", "", base.strip()).strip(".-")
    domain = domain.strip().lower()
    labels = domain.split(".")
    valid_labels = all(
        len(label) <= 63 and re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
        for label in labels
    )
    if (not base or len(base) > 57 or ".." in base or not valid_labels
            or len(labels) < 2 or len(domain) > 253 or not re.fullmatch(r"[a-z]{2,}", labels[-1])):
        raise TesterError("Provide a base name and valid DNS domain, e.g. example.com.")
    if not 1 <= count <= 100:
        raise TesterError("Count must be between 1 and 100.")
    addresses = []
    seen = set()
    for _ in range(count * 20):
        token = "".join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(6))
        local = f"{base}+{token}" if plus else f"{base}.{token}"
        address = valid_email(f"{local}@{domain}")
        if address not in seen:
            addresses.append(address)
            seen.add(address)
        if len(addresses) == count:
            break
    if len(addresses) != count:
        raise TesterError("Could not generate unique candidates; retry generation.")
    return addresses


def valid_login_url(url: str) -> str:
    url = url.strip()
    if url:
        parsed = urlparse(url)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username
                or parsed.password or any(c.isspace() or ord(c) < 32 for c in url)):
            raise TesterError("Sign-in URL must be HTTPS and cannot contain whitespace or embedded credentials.")
        try:
            parsed.port
        except ValueError as exc:
            raise TesterError("Sign-in URL has an invalid port.") from exc
    return url


def make_account(service: str, email: str, username: str, secret: str, url: str,
                 tags: list[str], notes: str) -> dict:
    email = valid_email(email)
    url = valid_login_url(url)
    stamp = now()
    return {"id": uuid.uuid4().hex[:10], "service": service.strip()[:120] or "Unassigned",
            "email": email, "username": username.strip() or email, "password": secret,
            "login_url": url.strip(), "status": "active",
            "tags": sorted({x.strip().lower()[:40] for x in tags if x.strip()}),
            "notes": notes.strip()[:4000], "created_at": stamp, "updated_at": stamp, "last_used_at": None}


def add_account(data: dict, account: dict) -> None:
    if any(a["email"].lower() == account["email"].lower() and a["service"].lower() == account["service"].lower()
           for a in data["accounts"]):
        raise TesterError("That email is already saved for this service.")
    data["accounts"].append(account)
    data["accounts"].sort(key=lambda a: (a["service"].lower(), a["email"].lower()))


def find_account(data: dict, identifier: str) -> dict:
    found = [a for a in data["accounts"] if a["id"] == identifier or a["email"].lower() == identifier.lower()]
    if not found:
        raise TesterError(f"No account found for: {identifier}")
    if len(found) != 1:
        raise TesterError("Email matches multiple records; use the account ID.")
    return found[0]


def listing(accounts: list[dict]) -> None:
    if not accounts:
        print("No accounts saved yet.")
        return
    print(f"{'ID':10}  {'SERVICE':22}  {'EMAIL':38}  STATUS")
    print("-" * 88)
    for index, a in enumerate(accounts, 1):
        print(f"{a['id']:10}  {a['service'][:22]:22}  {a['email'][:38]:38}  {a['status']}")
        if 'platform' in a:
            session = a['session']
            print(f"  [{index}] {a['platform']} | last observation: {session['state']} at {session.get('observed_at') or 'never'} | last fresh check: {session.get('verified_state') or 'never'} at {session.get('verified_at') or 'never'} (cached; select Verify for a new check)")


def validate_platform_account(account: dict) -> None:
    platform(account.get('platform'))
    if not re.fullmatch(r'[a-f0-9]{32}', account.get('browser_profile', '')):
        raise TesterError('Vault contains an invalid browser profile identifier.')
    session = account.get('session')
    if (not isinstance(session, dict) or not isinstance(session.get('state'), str)
            or any(session.get(k) is not None and not isinstance(session[k], str)
                   for k in ('observed_at', 'verified_at', 'verified_state'))):
        raise TesterError('Vault contains invalid session metadata.')


def platform_record(provider: str, email: str, *, signup: bool = False) -> dict:
    adapter = platform(provider)
    account = make_account(adapter.name, email, '', '', adapter.mail_url, [], '')
    account.update(platform=provider, browser_profile=uuid.uuid4().hex,
                   status='signup_pending' if signup else 'unverified',
                   signup_started_at=now() if signup else None,
                   session={'state': 'never_checked', 'observed_at': None, 'verified_at': None, 'verified_state': None})
    return account


def platform_action(path: Path, master: str, data: dict, identifier: str, action: str) -> dict:
    selected = time.perf_counter()
    original = find_account(data, identifier)
    if 'platform' not in original:
        raise TesterError('This is a generic vault record. Use add-existing google|microsoft EMAIL for isolated platform sessions.')
    validate_platform_account(original)
    account = copy_module.deepcopy(original)
    selection_ms = (time.perf_counter() - selected) * 1000
    if action == 'remove':
        forget_profile(path, account)
        updated = copy_module.deepcopy(data)
        updated['accounts'] = [a for a in updated['accounts'] if a['id'] != account['id']]
        try:
            save(path, master, updated)
        except (OSError, TesterError):
            raise TesterError('Local profile removed, but saving record removal failed. The record remains; fix storage and retry remove. The provider account was not deleted.') from None
        data.clear(); data.update(updated)
        print('Removed local record and browser profile. The provider account was not deleted; provider sign-out/revocation was not performed.')
        return {'state': 'removed'}
    if action == 'close':
        close_profile(path, account)
        result = {'state': 'closed', 'fresh_check': False, 'checkpoint': 'Selected browser closed; persistent session retained. This is not provider sign-out.', 'timings': {}}
    else:
        print(f"{action}: {platform(account['platform']).name} | expected identity: {account['email']} | isolated browser profile", flush=True)
        result = session_request(path, account, 'open' if action == 'switch' else action)
    stamp = now()
    session = account['session']
    session.update(state=result['state'], observed_at=stamp)
    if result.get('fresh_check') and result['state'] in {'authenticated', 'signed_out', 'authentication_required', 'identity_mismatch'}:
        session.update(verified_at=stamp, verified_state=result['state'])
    if result['state'] == 'authenticated':
        account['status'] = 'identity_observed'
        account['last_used_at'] = stamp
        if account.get('signup_started_at'):
            account['signup_identity_confirmed_at'] = stamp
    elif result['state'] != 'closed':
        account['status'] = result['state']
    result['timings']['selection_ms'] = round(selection_ms, 2)
    updated = copy_module.deepcopy(data)
    updated['accounts'] = [account if a['id'] == account['id'] else a for a in updated['accounts']]
    saved = time.perf_counter()
    try:
        save(path, master, updated)
    except (OSError, TesterError):
        raise TesterError('Browser action may have occurred, but saving its result failed. No new session status was persisted; retry verify after fixing storage.') from None
    result['timings']['vault_save_ms'] = round((time.perf_counter()-saved)*1000, 2)
    data.clear(); data.update(updated)
    print(f"{result['state']}: {result['checkpoint']}")
    print('Observation: ' + ('fresh navigation' if result.get('fresh_check') else 'current browser UI; not a fresh provider authentication check'))
    print('Timings (ms; excludes password entry and manual provider steps): ' + json.dumps(result['timings'], sort_keys=True))
    return result


def add_platform(path: Path, master: str, data: dict, provider: str, email: str, signup: bool = False) -> dict:
    account = platform_record(provider, email, signup=signup)
    updated = copy_module.deepcopy(data)
    add_account(updated, account)
    save(path, master, updated)
    data.clear(); data.update(updated)
    print(f"Saved {'signup intent' if signup else 'unverified existing-account record'}: {account['id']}. No account creation or authentication is asserted.")
    if signup:
        platform_action(path, master, data, account['id'], 'signup')
    return account


def set_identifier(path: Path, master: str, data: dict, identifier: str, email: str) -> None:
    original = find_account(data, identifier)
    if 'platform' not in original:
        raise TesterError('Select a platform account.')
    email = valid_email(email)
    if any(a['id'] != original['id'] and a.get('platform') == original['platform'] and a['email'].lower() == email.lower() for a in data['accounts']):
        raise TesterError('That platform identity is already saved.')
    updated = copy_module.deepcopy(data)
    record = find_account(updated, original['id'])
    record.update(email=email, username=email, status='unverified', updated_at=now())
    record['session'] = {'state': 'never_checked', 'observed_at': None, 'verified_at': None, 'verified_state': None}
    record.pop('signup_identity_confirmed_at', None)
    save(path, master, updated)
    data.clear(); data.update(updated)
    print('Saved new expected identifier; browser profile retained. Run verify to check the actual identity.')


def prompt_account() -> dict:
    service = input("Service/site: ")
    email = input("Email address: ")
    username = input("Username (Enter uses email): ")
    secret = getpass.getpass("Password (Enter skips): ")
    url = input("HTTPS sign-in URL (optional): ")
    tags = [x.strip() for x in input("Tags (comma-separated): ").split(",") if x.strip()]
    notes = input("Notes (optional): ")
    return make_account(service, email, username, secret, url, tags, notes)


def copy(value: str) -> None:
    command = None
    for name, args in (("wl-copy", []), ("xclip", ["-selection", "clipboard"]),
                       ("xsel", ["--clipboard", "--input"]), ("pbcopy", []), ("clip", [])):
        if shutil.which(name):
            command = [name, *args]
            break
    if not command:
        raise TesterError("Clipboard utility missing. Install wl-clipboard, xclip, or xsel.")
    # X11 clipboard owners fork and keep running. They must not retain the CLI's
    # output pipes, or callers capturing output will wait indefinitely for EOF.
    subprocess.run(command, input=value, text=True, check=True, timeout=5,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def tui(path: Path) -> None:
    if path.exists():
        data, master = unlock(path)
    else:
        print("Welcome to Tester — create your encrypted local vault.")
        master = password_prompt(confirm=True)
        data = {"schema": 1, "created_at": now(), "accounts": []}
        encrypt(path, master, data, create=True)
    while True:
        print("\n" + "=" * 52 + "\n TESTER — EMAIL IDENTITY MANAGER\n" + "=" * 52)
        listing(data["accounts"])
        print("\n[A]dd  [G]enerate candidates  [S]how  [C]opy email  [P]assword copy")
        print("[O]pen sign-in  [D]elete  [Q]uit")
        print('[E]xisting platform account  [N]ew signup  [W]switch/open  [I]sign in')
        print('[R]esume signup/auth  [V]erify identity  [X]sign out  [Y]verify sign-out  [F]orget local account  [L]close sessions')
        print('[U]pdate expected identifier  [B]close selected browser (not sign-out)')
        print('Enter a displayed platform account number to switch directly.')
        choice = input("\nSelect: ").strip().lower()
        previous = copy_module.deepcopy(data)
        try:
            if choice == "q":
                break
            if choice.isdigit():
                index = int(choice) - 1
                if not 0 <= index < len(data['accounts']):
                    raise TesterError('Choose a displayed account number.')
                platform_action(path, master, data, data['accounts'][index]['id'], 'switch')
            elif choice == "a":
                add_account(data, prompt_account()); save(path, master, data); print("Saved.")
            elif choice == "g":
                base, domain = input("Base name: "), input("Domain: ")
                count = int(input("Count (1-100): ") or "1")
                plus = input("Plus aliases for an existing mailbox? [y/N] ").strip().lower() == "y"
                print("\n".join(generate(base, domain, count, plus)))
                print("Candidates only: not saved, provisioned, or delivery-verified. Use Add to save a record.")
            elif choice in {'e', 'n'}:
                add_platform(path, master, data, input('Platform (google/microsoft): ').strip().lower(),
                             input('Account email (desired address for signup): ').strip(), choice == 'n')
            elif choice in {'w', 'i', 'r', 'v', 'x', 'y', 'f', 'b'}:
                action = {'w': 'switch', 'i': 'signin', 'r': 'resume', 'v': 'verify', 'x': 'signout', 'y': 'verify-signout', 'f': 'remove', 'b': 'close'}[choice]
                platform_action(path, master, data, input('Account ID or email: ').strip(), action)
            elif choice == 'u':
                set_identifier(path, master, data, input('Account ID or email: ').strip(), input('Expected account email: ').strip())
            elif choice == 'l':
                for record in data['accounts']:
                    if 'platform' in record:
                        close_profile(path, record)
                print('Browser sessions closed. Persistent sessions retained; this is not provider sign-out.')
            elif choice in {"s", "c", "p", "o", "d"}:
                account = find_account(data, input("Account ID or email: ").strip())
                if choice == "s":
                    print(f"Service: {account['service']}\nEmail: {account['email']}\nUsername: {account['username']}\nSign-in: {account['login_url']}\nStatus: {account['status']}\nTags: {', '.join(account['tags'])}\nNotes: {account['notes']}\nPassword: {'(saved)' if account['password'] else '(not saved)'}")
                elif choice == "c":
                    copy(account["email"]); print("Email copied.")
                elif choice == "p":
                    if not account["password"]: print("No password saved.")
                    else: copy(account["password"]); print("Password copied; clear clipboard after use.")
                elif choice == "o":
                    if 'platform' in account:
                        platform_action(path, master, data, account['id'], 'open')
                        continue
                    if not account["login_url"]: print("No sign-in URL saved.")
                    else:
                        if not webbrowser.open(account["login_url"]):
                            raise TesterError("Could not open the sign-in page in a browser.")
                        account["last_used_at"] = now()
                        save(path, master, data); print("Opened sign-in page; website controls its own session.")
                elif choice == "d" and input("Delete this record? [y/N] ").lower() == "y":
                    if 'platform' in account:
                        platform_action(path, master, data, account['id'], 'remove')
                        continue
                    data["accounts"].remove(account); save(path, master, data); print("Deleted.")
            else:
                print("Choose one of the listed actions.")
        except (TesterError, SessionError, ValueError, OSError, subprocess.SubprocessError) as exc:
            try:
                data = decrypt(path, master)
            except TesterError:
                data = previous
            print(f"Error: {exc}")
    print("Vault locked. Goodbye.")


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="tester", description="Encrypted terminal email identity manager")
    p.add_argument("--version", action="version", version=f"Tester {VERSION}")
    p.add_argument("--vault", type=Path, default=vault_path(), help="vault file path (or TESTER_VAULT)")
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("init", help="create encrypted vault")
    sub.add_parser("tui", help="interactive terminal menu")
    sub.add_parser("list", help="list saved identities")
    sub.add_parser("add", help="add email and website login record")
    sub.add_parser('accounts', help='list saved platform accounts and explicitly cached session observations')
    sub.add_parser('close-sessions', help='close isolated browsers; preserve sessions without signing out')
    q = sub.add_parser('set-identifier', help='correct expected signup identity without discarding the browser profile; invalidates prior observations')
    q.add_argument('identifier'); q.add_argument('email')
    for name in ('add-existing', 'signup'):
        q = sub.add_parser(name, help='save an existing platform identity' if name == 'add-existing' else 'start user-completed consumer signup in an isolated browser')
        q.add_argument('platform', choices=sorted(PLATFORMS))
        q.add_argument('email', help='existing email, or desired email for pending signup')
    for name in ('signin', 'switch', 'resume', 'verify', 'signout', 'verify-signout', 'remove', 'close'):
        q = sub.add_parser(name, help={'remove': 'remove local record/profile, not the external account', 'verify': 'fresh browser navigation and identity observation', 'verify-signout': 'check that fresh mail navigation requires authentication'}.get(name, name + ' the selected isolated platform session'))
        q.add_argument('identifier')
    backup = sub.add_parser("backup", help="create a verified encrypted backup")
    backup.add_argument("destination", type=Path)
    restore = sub.add_parser("restore", help="restore a verified encrypted backup")
    restore.add_argument("source", type=Path)
    restore.add_argument("--force", action="store_true", help="replace an existing vault")
    g = sub.add_parser("generate", help="generate address candidates, not mailboxes")
    g.add_argument("--base", required=True); g.add_argument("--domain", required=True)
    g.add_argument("--count", type=int, default=1); g.add_argument("--plus", action="store_true")
    for name, help_text in (("show", "show record"), ("copy", "copy email"),
                            ("copy-password", "copy saved password"), ("open", "open sign-in page"),
                            ("delete", "delete record")):
        q = sub.add_parser(name, help=help_text); q.add_argument("identifier")
    return p


def main() -> None:
    args = parser().parse_args()
    path = args.vault.expanduser()
    try:
        if args.command == "generate":
            print("\n".join(generate(args.base, args.domain, args.count, args.plus)))
            print("\nCandidates only: not saved, provisioned, or delivery-verified. Use 'tester add' to save a record.", file=sys.stderr)
            return
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        # Cross-platform OS-backed lock prevents lost updates from simultaneous Tester processes.
        with FileLock(str(path) + ".lock", timeout=0):
            if args.command == "init":
                master = password_prompt(confirm=True)
                data = {"schema": 1, "created_at": now(), "accounts": []}
                encrypt(path, master, data, create=True)
                print(f"Encrypted vault created: {path}")
                return
            if args.command == "tui":
                tui(path)
                return
            if args.command == "restore":
                master = password_prompt()
                restore_vault(path, args.source, master, force=args.force)
                print(f"Encrypted vault restored from: {args.source}")
                return
            data, master = unlock(path)
            if args.command == "backup":
                backup_vault(path, args.destination, master)
                print(f"Encrypted backup created: {args.destination}")
                return
            if args.command == "list":
                listing(data["accounts"])
                return
            if args.command == 'accounts':
                listing([a for a in data['accounts'] if 'platform' in a])
                return
            if args.command == 'close-sessions':
                for account in data['accounts']:
                    if 'platform' in account:
                        close_profile(path, account)
                print('Browser sessions closed; persistent authentication retained. This is not provider sign-out.')
                return
            if args.command in {'add-existing', 'signup'}:
                record = add_platform(path, master, data, args.platform, args.email, args.command == 'signup')
                if args.command == 'signup' and find_account(data, record['id'])['session']['state'] == 'browser_error':
                    raise SystemExit(3)
                return
            if args.command == 'set-identifier':
                set_identifier(path, master, data, args.identifier, args.email)
                return
            if args.command in {'signin', 'switch', 'resume', 'verify', 'signout', 'verify-signout', 'remove', 'close'}:
                result = platform_action(path, master, data, args.identifier, args.command)
                if result['state'] not in {'authenticated', 'signed_out', 'removed', 'closed'}:
                    raise SystemExit(3)
                return
            if args.command == "add":
                account = prompt_account()
                add_account(data, account)
                save(path, master, data)
                print(f"Saved {account['email']} ({account['id']}).")
                return
            account = find_account(data, args.identifier)
            if args.command == "show":
                print(f"ID: {account['id']}\nService: {account['service']}\nEmail: {account['email']}\nUsername: {account['username']}\nSign-in URL: {account['login_url']}\nStatus: {account['status']}\nTags: {', '.join(account['tags'])}\nNotes: {account['notes']}\nPassword: {'(saved; use copy-password)' if account['password'] else '(not saved)'}")
            elif args.command == "copy":
                copy(account["email"])
                print("Email copied.")
            elif args.command == "copy-password":
                if not account["password"]:
                    raise TesterError("No password saved for this account.")
                copy(account["password"])
                print("Password copied; clear clipboard after use.")
            elif args.command == "open":
                if 'platform' in account:
                    result = platform_action(path, master, data, account['id'], 'open')
                    if result['state'] != 'authenticated':
                        raise SystemExit(3)
                    return
                if not account["login_url"]:
                    raise TesterError("No sign-in URL saved.")
                if not webbrowser.open(account["login_url"]):
                    raise TesterError("Could not open the sign-in page in a browser.")
                account["last_used_at"] = now()
                save(path, master, data)
                print("Opened sign-in page; authentication remains site-controlled.")
            elif args.command == "delete":
                if input(f"Delete {account['email']} ({account['service']})? [y/N] ").lower() == "y":
                    if 'platform' in account:
                        platform_action(path, master, data, account['id'], 'remove')
                        return
                    data["accounts"].remove(account)
                    save(path, master, data)
                    print("Deleted.")
    except (EOFError, KeyboardInterrupt) as exc:
        print("\ntester: cancelled; vault locked.", file=sys.stderr)
        raise SystemExit(130) from exc
    except LockTimeout as exc:
        print("tester: this vault is already open in another Tester process.", file=sys.stderr)
        raise SystemExit(2) from exc
    except (TesterError, SessionError, ValueError, OSError, subprocess.SubprocessError) as exc:
        print(f"tester: {exc}", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
