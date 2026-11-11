# Tester — email identity manager

A terminal-first local vault for organizing email identities and associated website logins.

## Install
Requires Python 3.11+.

    git clone https://github.com/74Thirsty/Tester.git
    cd Tester
    python3 -m venv .venv
    . .venv/bin/activate
    python -m pip install -e .
    tester init

Windows PowerShell: .venv\Scripts\Activate.ps1

## Use
    tester tui
    tester generate --base chris --domain example.com --count 5
    tester add
    tester list
    tester show ACCOUNT_ID
    tester copy ACCOUNT_ID
    tester open ACCOUNT_ID
    tester copy-password ACCOUNT_ID
    tester delete ACCOUNT_ID

Set TESTER_VAULT to override the vault path. Run tester --help for details.

## What address generation means
Generated addresses are candidates, not provisioned mailboxes. The default creates unique local-part candidates at a domain you specify; --plus creates plus-addresses such as name+shopping@example.com. You must own/control the domain and create or configure the address with your mail provider. Plus-address delivery is provider-dependent. Tester does not pretend it has created a live mailbox.

Actual mailbox provisioning requires a provider API and authorized credentials. No provider or credentials were specified, so this release records addresses you create and provides an adapter-ready boundary rather than silently signing up for services.

## Account switching
Records can include service, email, username, password, HTTPS sign-in URL, tags, and notes. The app can copy an email/password and open the saved sign-in page. Websites control their own authentication, sessions, and logout; no universal safe mechanism can log in/out of arbitrary websites.

## Security
All vault contents are encrypted using AES-256-GCM. A 256-bit key is derived from the master password using scrypt with a random per-vault salt. The vault is stored outside this repository, written atomically, and restricted to owner permissions where supported. Passwords are never accepted as command-line arguments. The master password is never stored.

Default locations: Linux ~/.local/share/tester/vault.json; macOS ~/Library/Application Support/Tester/vault.json; Windows %LOCALAPPDATA%\Tester\vault.json.

There is no password recovery. Keep a secure backup of the encrypted vault and remember the master password. Clipboard history may retain copied secrets; clear it after use. This is a local encrypted vault, not a completed independent security audit or replacement for full-disk encryption.

## Tests
    python -m pip install -e '.[dev]'
    python -m unittest discover -s tests -v
