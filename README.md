# Tester — Google and Microsoft account session manager

A terminal-first account list with isolated persistent browser sessions for Google/Gmail and Microsoft/Outlook, plus an encrypted vault for account metadata and optional generic login records. Browser authentication is separate from email API authorization. Real authenticated provider acceptance remains unverified; see the verification report.

## Install
Requires Python 3.11+.

    git clone https://github.com/74Thirsty/Tester.git
    cd Tester
    python3 -m venv .venv
    . .venv/bin/activate
    python -m pip install -e .
    tester init

For isolated sessions, install a browser with `python -m playwright install chromium`,
or set `TESTER_BROWSER` to an installed Chrome/Chromium executable. A graphical
desktop and a working browser sandbox are required; browser automation restrictions
are never bypassed. Browser profiles are owner-only on POSIX; Windows uses a
current-user-only directory ACL (Windows/macOS execution remains unverified).

Windows PowerShell: .venv\Scripts\Activate.ps1

## Platform account workflows

    tester add-existing google you@gmail.com
    tester add-existing microsoft you@outlook.com
    tester accounts
    tester signin ACCOUNT_ID
    tester switch ACCOUNT_ID
    tester verify ACCOUNT_ID
    tester signout ACCOUNT_ID
    tester verify-signout ACCOUNT_ID
    tester remove ACCOUNT_ID

`add-existing` saves an **unverified** identity; it does not assert that the account
exists. `signin`, `switch`, and platform `open` select the dedicated browser profile
and navigate to Gmail/Outlook, reusing its cookies. Enter credentials, MFA, CAPTCHA,
consent and terms directly in the provider window yourself. Use `resume ACCOUNT_ID`
after completing a checkpoint. Resume preserves a currently visible authentication
checkpoint instead of navigating away from it. If a provider rejects the browser,
stop and use a supported browser; this application does not evade that restriction.

For one-selection switching, run `tester tui`, unlock once, and enter the displayed
account number. The browser workers stay alive across CLI/application restarts, so
valid sessions do not require repeated provider credentials. Standalone commands
still unlock the metadata vault; the TUI avoids repeated master-password prompts.
Fresh mail navigation is used to detect expiry. Observations require the expected
email in provider account UI and a visible mail main region. Unrecognized layouts,
wrong identities and missing evidence fail closed. Open the provider's account menu
if its email is hidden, then Verify. Selectors target English UI; other layouts may
require manual handoff and remain unverified.

The account list explicitly labels saved observations as **cached**, with separate
observation and last-fresh-navigation timestamps/states. A browser launch, login
page, or API authorization never counts as an authenticated mail session.

## Consumer signup

    tester signup google desired@gmail.com
    tester signup microsoft desired@outlook.com
    tester resume ACCOUNT_ID
    tester set-identifier ACCOUNT_ID actual-chosen-address@example.com
    tester verify ACCOUNT_ID

Signup saves a pending local intent and opens the official consumer signup page in
its own browser. You complete every provider-controlled step yourself. If the
requested address is unavailable, `set-identifier` corrects the expected identity
without losing the profile, and invalidates prior identity observations. Completion
is observed only after the expected account and usable mail UI appear. That proves
account presence, not independently that the provider created it during this run;
the live signup acceptance runner records user-confirmed creation separately.

Closing and reopening retains cookies/browser state. A provider may expire a
signup checkpoint or decline to restore form fields after browser restart. Use
Resume; the app does not store passwords, CAPTCHA answers or secret continuation
URLs to reconstruct expired forms. Repeated signup for the same saved identity is
rejected; resume its existing record instead.

There is no consumer account-creation API integration, no Workspace/Microsoft 365
administrator provisioning, and no Gmail/Graph API authorization. Those are distinct
capabilities, not implied by website access. No accounts were created during the
current verification run.

## Sign-out, closing and removal

- `signout ID` uses the provider's account-menu sign-out control inside that isolated
  profile, then checks a fresh mail navigation for a visible authentication form.
  If the control/layout cannot be recognized, sign out manually there and run
  `verify-signout ID`. An authentication-domain URL alone is insufficient proof.
- `close ID` or `close-sessions` closes browser windows/workers and preserves session
  data. It **does not sign out** or revoke the provider session.
- `remove ID` closes the selected browser, removes its local profile and saved
  record, and makes no external-account deletion request. It does not claim provider
  sign-out or token revocation. Failed persistence reports any partial local effect.
- TUI Quit locks the vault but deliberately leaves browser sessions available for
  reuse. Use Close sessions before Quit when you want their windows closed.

Each saved identity has a random, dedicated profile under `VAULT_PATH.profiles/`.
Do not add unrelated accounts inside a provider's own multi-account menu in that
profile. Wrong/ambiguous observed identity is rejected; signing out a mismatched
profile is refused. The app never imports a personal/default browser profile.

## Generic vault tools and candidate helper

    tester generate --base chris --domain example.com --count 5
    tester add
    tester list
    tester show ACCOUNT_ID
    tester copy ACCOUNT_ID
    tester copy-password ACCOUNT_ID
    tester open ACCOUNT_ID
    tester delete ACCOUNT_ID
    tester backup /secure/path/tester-backup.vault
    tester restore /secure/path/tester-backup.vault

Generic records keep their existing browser-launch behavior; platform records use
isolated sessions. `delete` retains its confirmation prompt; `remove` is the direct
platform-local removal operation.

Set `TESTER_VAULT` to override the vault path. Pass `--vault PATH` **before** the
subcommand to override that variable. Activate the virtual environment so `tester`
is on PATH, or use `.venv/bin/tester` (Windows: `.venv\Scripts\tester.exe`). Direct
execution uses `python tester.py` followed by the same arguments.

Exit codes: 0 = requested local operation/confirmed browser observation completed;
1 = storage/browser/input failure; 2 = argument error or locked vault; 3 = a browser
checkpoint, identity mismatch or unconfirmed authentication/sign-out; 130 = canceled
input. `signup` returning 0 means its pending intent and browser handoff succeeded,
not that the external account was created.

## What address generation means
Generated addresses are candidates, not provisioned mailboxes. The default creates local-part candidates unique within each invocation at a domain you specify; `--plus` creates plus-address candidates such as `name+abc123@example.com`. They are printed, not automatically saved. Use `tester add` to record an address after configuring it. Generation does not require a vault. CLI stdout contains only addresses; the candidate notice goes to stderr.

Default generation removes characters outside letters, digits, dots, underscores and hyphens from the base, and trims leading/trailing dots and hyphens. Plus mode requires the exact existing mailbox local part within that supported character set and rejects inputs that would be rewritten. Both modes reject consecutive dots, bases longer than 57 characters, invalid DNS domains, and counts outside 1–100. Domains are lowercased. These checks do not establish domain ownership, DNS availability or delivery.

Address generation remains only a helper. For a consumer Google/Microsoft account, use the separate browser signup workflow above. Plus-address delivery depends on an existing mailbox and provider; generation does not register anything. See [the verification matrix](verification/REPORT.md).

## Account switching
Records can include service, email, username, password, HTTPS sign-in URL, tags, and notes. The app can copy an email/password and open the saved sign-in page. Websites control their own authentication, sessions, and logout; no universal safe mechanism can log in/out of arbitrary websites.

Clipboard operations require an active desktop session and one of `wl-copy`, `xclip`,
`xsel`, `pbcopy`, or Windows `clip` on PATH. Opening a sign-in page requires a browser;
Python's `BROWSER` environment variable can select one. A successful launch records
`last_used_at`; it does not assert successful authentication. Missing utilities,
failed launches, missing saved passwords/URLs and ambiguous email lookups report errors.
Use the account ID when an email is saved for multiple services.

## Security
Vault metadata is encrypted using AES-256-GCM. **Browser profiles are separate sensitive session storage, not encrypted by the vault.** They use OS access controls (POSIX owner-only directories/files, or Windows current-user-only inheritable ACLs); protect the OS account and disk. Workers run with a restrictive umask and private browser pipes, not public debugging ports. Browser/SDK exceptions, console output, traces, screenshots, cookies and authentication URLs are not logged. Workers never receive the vault password. Backups below contain vault metadata only, not browser sessions; restoring to another path/device requires signing in again.

All vault contents are encrypted using AES-256-GCM. A 256-bit key is derived from the master password using scrypt with a random per-vault salt. Writes use a same-directory temporary file and atomic replacement; initial creation uses an atomic no-clobber link so an existing vault cannot be overwritten by a create race. On POSIX systems, the vault file is set to owner-only permissions (0600). The application does not change permissions on an existing parent directory. Symlink vault paths, unsupported crypto metadata, malformed records, and vault files larger than 16 MiB are rejected. Passwords are never accepted as command-line arguments. The master password is never stored.

Default locations: Linux ~/.local/share/tester/vault.json; macOS ~/Library/Application Support/Tester/vault.json; Windows %LOCALAPPDATA%\Tester\vault.json.

There is no password recovery. Create backups with `tester backup DESTINATION`; backups remain encrypted and are never overwritten. Restore with `tester restore BACKUP`; an existing vault is protected unless you explicitly pass `--force`. Store backups separately from the device containing the original vault, and remember the master password. Clipboard history may retain copied secrets; clear it after use. This is a local encrypted vault, not a completed independent security audit or replacement for full-disk encryption. The interactive TUI remains unlocked until you choose Quit; close it when unattended. An OS-backed cross-platform lock prevents two Tester processes from accessing the same vault simultaneously. Clipboard managers may retain copied secrets. Windows file ACLs are inherited from the containing directory; protect your Windows user profile and device accordingly.

## Tests
    python -m pip install -e '.[dev]'
    python -m unittest discover -s tests -v

For per-command evidence, set `TESTER_EVIDENCE_DIR=verification` when running the
suite. The process tests exercise both installed and direct entry points with
temporary synthetic vaults. On Linux with an active X11 desktop, run
`python verification/check_desktop.py` to check real clipboard round trips and
Chromium navigation to a temporary local HTTPS fixture. This check temporarily
replaces and restores the clipboard, uses an isolated browser profile, and requires
`xclip` and `chromium`. It does not test email delivery or third-party authentication.

See [verification/REPORT.md](verification/REPORT.md) for commands, results, artifacts,
repaired defects and remaining platform/provider blockers.

## Verification and timing

The [current report](verification/REPORT.md) separates local automated tests,
real-browser fixture checks, anonymous provider probes, and blocked authenticated
provider acceptance. Timings report selection, browser activation, navigation and
observation, worker startup/IPC, and vault persistence separately. They exclude
manual user authentication. Fixture results are not real-provider performance claims.

Reproduce additional checks (synthetic data only):

    python verification/check_sessions.py
    python verification/check_worker_workflows.py
    python verification/probe_provider_portals.py

For authorized real acceptance, run on a graphical desktop with **two controlled
test accounts per provider**, using a dedicated test vault. Secrets are entered in
the provider browser and master passwords via hidden prompts:

    python verification/verify_live_accounts.py --platform google --vault /secure/path/google-test.vault --output verification/live-google.json
    python verification/verify_live_accounts.py --platform microsoft --vault /secure/path/microsoft-test.vault --output verification/live-microsoft.json

The runner tests sign-in, switching, process/browser restart, user-performed
revocation/recovery, isolated sign-out, and local removal followed by re-sign-in to
confirm the external account survives. It intentionally signs out/removes test
record A; record B remains available. Skipped checkpoints stay blocked. Use
`--signup` for a separate user-completed creation test, and do not create extra
accounts just to repeat tests. Sanitized evidence contains labels A/B and timings,
not identities, passwords, cookies, message content or authentication URLs.
