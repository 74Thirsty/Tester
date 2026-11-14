from playwright.sync_api import sync_playwright
from urllib.parse import urlsplit
import tempfile
with tempfile.TemporaryDirectory() as directory, sync_playwright() as p:
    context = p.chromium.launch_persistent_context(directory, executable_path='/usr/bin/chromium', headless=False, chromium_sandbox=True)
    page = context.pages[0]
    try:
        for url in ('https://outlook.live.com/mail/0/', 'https://outlook.live.com/owa/?nlp=1', 'https://accounts.google.com/signup'):
            try:
                page.goto(url, wait_until='domcontentloaded', timeout=25000)
                page.wait_for_timeout(3000)
                print('REQUEST', urlsplit(url).hostname, 'OBSERVED HOST', urlsplit(page.url).hostname,
                      'email_inputs', page.locator('input[type=email]').count(), 'password_inputs', page.locator('input[type=password]').count(),
                      'signin_links', page.get_by_role('link', name='Sign in', exact=True).count(), flush=True)
            except Exception:
                print('Browser navigation failed; details suppressed', flush=True)
    finally:
        context.close()
