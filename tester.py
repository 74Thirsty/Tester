"""Tester: encrypted local email identity manager."""
from __future__ import annotations

import argparse
import base64
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
import uuid
import webbrowser
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

VERSION = "1.0.0"
AAD = b"tester-vault-v1"
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
        if path.stat().st_size > 16 * 1024 * 1024:
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


def valid_email(value: str) -> str:
    value = value.strip()
    if len(value) > 254 or not EMAIL_RE.fullmatch(value):
        raise TesterError("Enter a valid email address.")
    return value


def generate(base: str, domain: str, count: int, plus: bool) -> list[str]:
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
    for _ in range(count):
        token = "".join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(6))
        local = f"{base}+{token}" if plus else f"{base}.{token}"
        addresses.append(valid_email(f"{local}@{domain}"))
    return addresses


def make_account(service: str, email: str, username: str, secret: str, url: str,
                 tags: list[str], notes: str) -> dict:
    email = valid_email(email)
    if url:
        parsed = urlparse(url.strip())
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            raise TesterError("Sign-in URL must be HTTPS and cannot contain embedded credentials.")
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
    for a in accounts:
        print(f"{a['id']:10}  {a['service'][:22]:22}  {a['email'][:38]:38}  {a['status']}")


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
    subprocess.run(command, input=value, text=True, check=True, timeout=5)


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
        print("\n[A]dd  [G]enerate  [S]how  [C]opy email  [P]assword copy")
        print("[O]pen sign-in  [D]elete  [Q]uit")
        choice = input("\nSelect: ").strip().lower()
        try:
            if choice == "q":
                break
            if choice == "a":
                add_account(data, prompt_account()); save(path, master, data); print("Saved.")
            elif choice == "g":
                base, domain = input("Base name: "), input("Domain: ")
                count = int(input("Count (1-100): ") or "1")
                plus = input("Plus aliases? [y/N] ").lower() == "y"
                print("\n".join(generate(base, domain, count, plus)))
                print("These are candidates only; provision/verify them with your provider.")
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
                    if not account["login_url"]: print("No sign-in URL saved.")
                    else:
                        if not webbrowser.open(account["login_url"]):
                            raise TesterError("Could not open the sign-in page in a browser.")
                        account["last_used_at"] = now()
                        save(path, master, data); print("Opened sign-in page; website controls its own session.")
                elif choice == "d" and input("Delete this record? [y/N] ").lower() == "y":
                    data["accounts"].remove(account); save(path, master, data); print("Deleted.")
            else:
                print("Choose one of the listed actions.")
        except (TesterError, ValueError, OSError, subprocess.SubprocessError) as exc:
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
        if args.command == "init":
            master = password_prompt(confirm=True)
            data = {"schema": 1, "created_at": now(), "accounts": []}
            encrypt(path, master, data, create=True)
            print(f"Encrypted vault created: {path}"); return
        if args.command == "tui":
            tui(path); return
        if args.command == "generate":
            print("\n".join(generate(args.base, args.domain, args.count, args.plus)))
            print("\nCandidates only. Create/verify them with your provider."); return
        data, master = unlock(path)
        if args.command == "list":
            listing(data["accounts"]); return
        if args.command == "add":
            account = prompt_account(); add_account(data, account); save(path, master, data)
            print(f"Saved {account['email']} ({account['id']})."); return
        account = find_account(data, args.identifier)
        if args.command == "show":
            print(f"ID: {account['id']}\nService: {account['service']}\nEmail: {account['email']}\nUsername: {account['username']}\nSign-in URL: {account['login_url']}\nStatus: {account['status']}\nTags: {', '.join(account['tags'])}\nNotes: {account['notes']}\nPassword: {'(saved; use copy-password)' if account['password'] else '(not saved)'}")
        elif args.command == "copy":
            copy(account["email"]); print("Email copied.")
        elif args.command == "copy-password":
            if not account["password"]: raise TesterError("No password saved for this account.")
            copy(account["password"]); print("Password copied; clear clipboard after use.")
        elif args.command == "open":
            if not account["login_url"]: raise TesterError("No sign-in URL saved.")
            if not webbrowser.open(account["login_url"]):
                raise TesterError("Could not open the sign-in page in a browser.")
            account["last_used_at"] = now()
            save(path, master, data); print("Opened sign-in page; authentication remains site-controlled.")
        elif args.command == "delete":
            if input(f"Delete {account['email']} ({account['service']})? [y/N] ").lower() == "y":
                data["accounts"].remove(account); save(path, master, data); print("Deleted.")
    except (TesterError, ValueError, OSError, subprocess.SubprocessError) as exc:
        print(f"tester: {exc}", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
