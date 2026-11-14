# Tester implementation and verification report

## Scope and requirements

Inspected `README.md`, `tester.py`, `pyproject.toml`, `tests/test_core.py`, `.github/workflows/tests.yml`, repository file inventory, and README history at `c9424de` and `9f29aae`. The original documented product is a local encrypted email/login record manager. Its advertised Generate contract is **address candidates**, including plus-address syntax; the history does not contain a provisioning implementation or configured provider. This report preserves that contract and separately marks live mailbox capability blocked, rather than presenting strings as working mailboxes. No account access or credentials are inferred from unrelated connected applications.

Status definitions: PASS means the stated scope was exercised with assertions; BLOCKED means the stated integration/platform could not be verified. Component mocks are explicitly distinguished from real checks. Tests use disposable vaults and synthetic data, never the user's vault. Local results do not establish a security audit or universal platform compatibility.

Final automated result: **26 tests passed** on Python 3.11/Linux, including subprocess workflows for both entry points and a real terminal check. The separate real desktop integration completed all nine CLI/menu checks. `pip check`, Python compilation and `git diff --check` also passed. [Automated test output](tests.log) and [desktop output](desktop.log) are retained alongside the per-command logs.

## Reproduce

```sh
python3 -m venv /tmp/tester-verification-venv
/tmp/tester-verification-venv/bin/python -m pip install -e '.[dev]'
TESTER_EVIDENCE_DIR=verification /tmp/tester-verification-venv/bin/python -m unittest discover -s tests -v
/tmp/tester-verification-venv/bin/python -m pip check
/tmp/tester-verification-venv/bin/python verification/check_desktop.py
./tester.py --version
```

The desktop check requires Linux/X11, xclip, Chromium, local socket access, and permission to launch a browser. It preserves the previous clipboard in memory, restores it, and deletes its temporary vault, certificate and browser profile. Its Chromium certificate exception is confined to the temporary test process and self-signed local fixture, not application configuration. A real unique HTTPS request and persisted `last_used_at` are asserted; third-party login is not claimed.

In the matrix, `tester` denotes `/tmp/tester-verification-venv/bin/tester`; CLI workflows also run `/tmp/tester-verification-venv/bin/python /home/thompy420/GitHub/Tester/tester.py` from outside the repository. `$V`, `$B`, and `$R` denote disposable vault, backup and restore paths. `<id>` denotes a synthetic account ID or `fixture@example.com`. Passwords are entered through prompts and omitted from logs. Exact non-secret input sequences and assertions are in [test_workflows.py](../tests/test_workflows.py). Captured logs include exact expanded subprocess argument lists, exit codes and output.

## Feature verification matrix

| Feature / expected behavior | Command or interaction exercised | Actual result | Status / evidence |
|---|---|---|---|
| Clean installation installs dependencies and console entry point | `python3 -m venv /tmp/tester-verification-venv`; environment Python `-m pip install -e '.[dev]'` | Editable build and installation succeeded; pip check reports no broken requirements. Initial sandbox DNS failure resolved with approved network access. | PASS [installation](install.log), [environment](environment.log) |
| Installed CLI and direct script work outside source directory | Both entry points run the complete CLI lifecycle; `./tester.py --version` | Both report version 1.0.0 and execute workflows; executable script also reports 1.0.0. | PASS [lifecycle](test_workflows.WorkflowTests.test_cli_lifecycle_both_entrypoints.log), [executable](direct-executable.log) |
| Help describes all commands; version available | `--help`, `--version`, all 12 subcommands `--help` | Exit 0, usage/version present. | PASS [lifecycle](test_workflows.WorkflowTests.test_cli_lifecycle_both_entrypoints.log) |
| Initialize encrypted vault; reject overwrite | `tester init`, repeat `init`, prompted password/confirmation | Creates vault; existing vault rejected with exit 1. | PASS [lifecycle](test_workflows.WorkflowTests.test_cli_lifecycle_both_entrypoints.log) |
| Enforce master-password confirmation/minimum length | `init` with mismatched confirmation and short password | Exit 1 with useful errors, no traceback. | PASS [invalid inputs](test_workflows.WorkflowTests.test_eof_invalid_records_and_lock.log) |
| Configuration chooses explicit vault and environment override | `TESTER_VAULT=$V tester …`; `tester --vault $R restore $B`; default path unit checks | Environment path used; explicit path wins; Linux XDG and macOS path calculations asserted. | PASS (path logic only) [lifecycle](test_workflows.WorkflowTests.test_cli_lifecycle_both_entrypoints.log), [tests](tests.log) |
| Generate distinct candidate addresses without vault creation | Both entry points: `generate --base chris --domain example.com --count 100` | Exactly 100 distinct candidate strings per invocation, no vault created. Notice explicitly says not saved/provisioned/delivery-verified. | PASS [generation](test_workflows.WorkflowTests.test_generate_and_errors.log) |
| Generate plus-address candidates preserving mailbox base | Same command with `--plus`; invalid `--base a+b --plus`; menu G | Correct plus syntax; unsupported base rejected instead of silently rewritten. | PASS [generation](test_workflows.WorkflowTests.test_generate_and_errors.log), [terminal](terminal.log), [regressions](tests.log) |
| Generation rejects invalid/count/missing arguments; handles collisions | `--count 0`, `101`, `abc`; missing flags; invalid domain; deterministic RNG collision regression | Exit 1 for invalid values, 2 for argument syntax; collisions retried with bounded failure. | PASS [generation](test_workflows.WorkflowTests.test_generate_and_errors.log), [tests](tests.log) |
| Add service/email/login metadata and avoid duplicates | `tester add`, repeat same service/email | Record saved with defaults and normalized tags; duplicate rejected. | PASS [lifecycle](test_workflows.WorkflowTests.test_cli_lifecycle_both_entrypoints.log) |
| Validate emails and HTTPS URLs | `add` with malformed email, HTTP URL, invalid port; authenticated vault with unsafe URL | Inputs rejected; decrypted records cannot bypass URL validation. | PASS [invalid inputs](test_workflows.WorkflowTests.test_eof_invalid_records_and_lock.log), [regressions](tests.log) |
| List empty/nonempty records | `tester list` before and after Add/Delete | Empty message or saved identity appears as expected. | PASS [lifecycle](test_workflows.WorkflowTests.test_cli_lifecycle_both_entrypoints.log) |
| Show metadata without exposing password; missing lookup errors | `tester show <id>`; `show missing` | Metadata present, synthetic password absent, missing record exit 1. | PASS [lifecycle](test_workflows.WorkflowTests.test_cli_lifecycle_both_entrypoints.log) |
| Disambiguate one email used at multiple services | `show fixture@example.com`, then `show <id>` with two services saved | Email lookup rejected as ambiguous; ID returns the requested record. | PASS [lookup](test_workflows.WorkflowTests.test_ambiguous_email_requires_id.log) |
| Copy email to actual OS clipboard | Both entry points: `copy <id>`; menu C → ID → Q | xclip readback equals synthetic email; contents omitted from evidence. | PASS (X11) [desktop](desktop.log), [reproducer](check_desktop.py) |
| Copy password to actual OS clipboard | Both entry points: `copy-password <id>`; menu P → ID → Q | xclip readback equals synthetic password; contents omitted. | PASS (X11) [desktop](desktop.log) |
| Report missing clipboard tool / saved password | `copy` with utility-free PATH; `copy-password` without password; menu P | Helpful failure, no traceback or false success. | PASS [failures](test_workflows.WorkflowTests.test_missing_optional_fields_and_desktop_failures.log), [menu](test_workflows.WorkflowTests.test_tui_full_menu_and_reopen.log) |
| Open saved HTTPS URL and persist last-used timestamp | Both entry points: `open <id>`; menu O → ID → Q, configured Chromium | Real browser fetched unique controlled HTTPS path; timestamp persisted. | PASS (configured Chromium) [desktop](desktop.log) |
| Missing URL and browser failure handling | `open` with no URL; menu O without URL; mocked browser false return | Missing URL rejected; dispatch regression verifies failure output and success persistence. Browser-failure branch uses mock, not live failure evidence. | PASS (stated scope) [failures](test_workflows.WorkflowTests.test_missing_optional_fields_and_desktop_failures.log), [tests](tests.log) |
| Delete only after confirmation | `delete <id>` with N then Y; menu D with N then Y | N preserves record, Y deletes; persisted state checked. | PASS [lifecycle](test_workflows.WorkflowTests.test_cli_lifecycle_both_entrypoints.log), [menu](test_workflows.WorkflowTests.test_tui_full_menu_and_reopen.log) |
| Backup encrypted vault without overwrite | `backup $B`, repeat backup; unit wrong-password check | Verified encrypted backup created; existing destination/wrong password rejected. | PASS [lifecycle](test_workflows.WorkflowTests.test_cli_lifecycle_both_entrypoints.log), [tests](tests.log) |
| Restore to new path; require force for replacement | `--vault $R restore $B`; `restore $B`; `restore $B --force` | New path restored; replacement rejected without force; forced restore recovers deleted account. | PASS [lifecycle](test_workflows.WorkflowTests.test_cli_lifecycle_both_entrypoints.log) |
| TUI creation/unlock and every menu action | A/G/S/C/P/O/D/Q plus invalid choice, invalid count, missing account | Menu workflows, recovery and persistence asserted; desktop actions separately exercised live. | PASS [menu](test_workflows.WorkflowTests.test_tui_full_menu_and_reopen.log), [desktop](desktop.log) |
| Actual terminal interaction hides passwords | PTY: new TUI → master/confirm → G → plus candidate → Q | Password absent from terminal echo; candidate displayed; clean quit. | PASS [terminal](terminal.log) |
| EOF cancellation exits cleanly | `init` with closed stdin; `tui` with EOF after unlock | Exit 130, “cancelled; vault locked”, no traceback. | PASS [invalid inputs](test_workflows.WorkflowTests.test_eof_invalid_records_and_lock.log) |
| Encrypt/authenticate; reject wrong password/tampering/schema/symlinks | Core and regression suite; CLI wrong-password/corrupt JSON | Round trip passes, sensitive fixture strings absent from encrypted file, unsafe files rejected. | PASS [tests](tests.log), [invalid inputs](test_workflows.WorkflowTests.test_eof_invalid_records_and_lock.log) |
| Owner-only permissions and concurrent access protection | Stat newly created vault; hold FileLock while second CLI runs | Mode 0600; second process exit 2 with lock message. | PASS (Linux) [lifecycle](test_workflows.WorkflowTests.test_cli_lifecycle_both_entrypoints.log), [lock](test_workflows.WorkflowTests.test_eof_invalid_records_and_lock.log) |
| Failed save does not display unsaved records; oversize write preserves prior vault | Inject disk-full save failure; lower byte limit for deterministic oversize regression | Menu rollback verified; old encrypted bytes remain unchanged. Fault injection is component-level. | PASS [tests](tests.log) |
| Provision real mailbox/provider-managed alias | No provider integration/configuration available | Not implemented; no mailbox created. Required: provider selection, supported API, provisioning credentials via secure setup, controlled domain and authorization. | BLOCKED |
| Verify delivery to controlled account | No controlled recipient or configured send/read access supplied | No message sent or received; no delivery asserted. Required: authorized sender/recipient plus receipt access; send unique-ID message and confirm receipt after integration. | BLOCKED |
| Windows/macOS desktop and full application execution | CI defines those OSes, but this run has Linux only | No Windows/macOS execution evidence. Required: run CI matrix and native clipboard/browser checks on each OS. | BLOCKED |
| Wayland clipboard / user's default browser | Live checks used X11 and explicitly configured Chromium | Other desktop backends/default browser not exercised. Required: test in those sessions with utilities installed. | BLOCKED |

## Repaired defects

- Plus mode silently changed mailbox identity (`chris+existing` became `chrisexisting`). Unsupported plus bases now fail explicitly.
- Random suffix collisions violated the advertised uniqueness guarantee. Generation now retries and fails safely if it cannot produce the requested distinct set.
- Closed stdin caused an unhandled EOF traceback. Cancellation now exits 130 and releases the vault lock.
- TUI mutations survived failed saves in memory. The menu restores the prior state on an operation failure.
- Oversized writes could create vaults the reader refused. The serialized envelope size is checked before replacement.
- URL validation accepted invalid ports/whitespace, and decrypted records could bypass it. Both entry and decrypted records now validate URLs.
- Live X11 Copy hung output-capturing callers because the clipboard owner inherited output descriptors. Clipboard subprocess output is now detached. [Before-fix failure](desktop-before-fix.log) and [successful live rerun](desktop.log) document this repair.
- Generate's UI and stdout were unclear about persistence/provisioning. Menu labels and notices now state the actual result; CLI stdout is address-only. README no longer implies an unimplemented adapter exists.

## Completion limits

The verified local Linux candidate/vault workflows and configured X11/Chromium integrations pass. **The application is not claimed fully working across all requested capabilities.** Real mailbox provisioning/receipt and untested platforms remain blocked as shown above. Selecting a provider and supplying secure authorized access is necessary before designing and testing a real provisioning adapter; inventing an API or using an unrelated connected inbox would not resolve that requirement.
