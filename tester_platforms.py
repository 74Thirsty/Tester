"""Provider website adapters. No password entry, API tokens or private endpoints."""
from dataclasses import dataclass
import re
from urllib.parse import urlsplit


@dataclass(frozen=True)
class Platform:
    key: str
    name: str
    mail_url: str
    signup_url: str
    mail_hosts: tuple[str, ...]
    auth_hosts: tuple[str, ...]
    identity_selectors: tuple[str, ...]
    ready_selectors: tuple[str, ...]
    account_selectors: tuple[str, ...]
    signout_selectors: tuple[str, ...]
    signin_url: str = ''

    def observe(self, page, expected: str) -> dict:
        """Read only account chrome, never message bodies, cookies, or full URLs."""
        location = urlsplit(page.url)
        host = location.hostname or ''
        if location.scheme != urlsplit(self.mail_url).scheme:
            return {'state': 'unknown', 'identity_match': False, 'checkpoint': 'No trusted provider page observed. Open the selected mail application.'}
        if host in self.auth_hosts:
            checkpoints = (
                ('provider_restriction', 'text="This browser or app may not be secure"', 'Provider rejected this browser. Use a provider-supported browser; do not bypass this restriction.'),
                ('captcha', 'iframe[src*="recaptcha"], iframe[src*="arkoselabs"], iframe[src*="hcaptcha"]', 'Complete the visible CAPTCHA yourself in the browser, then resume.'),
                ('mfa', 'input[autocomplete="one-time-code"], input[name="totpPin"], #idTxtBx_SAOTCC_OTC', 'Complete the provider verification/MFA challenge yourself in the browser, then resume.'),
                ('password', 'input[type="password"]', 'Enter your password directly in the provider browser window, then complete any further challenges and resume.'),
                ('identifier', 'input[type="email"], input[name="loginfmt"]', 'Enter the account identifier directly in the provider browser window, then resume after authentication.'),
            )
            for code, selector, instruction in checkpoints:
                candidates = page.locator(selector)
                if candidates.count() and candidates.first.is_visible():
                    return {'state': 'authentication_pending' if code == 'provider_restriction' else 'authentication_required', 'identity_match': False,
                            'checkpoint_code': code, 'checkpoint': instruction}
            return {'state': 'authentication_pending', 'identity_match': False,
                    'checkpoint_code': 'provider_page',
                    'checkpoint': 'Complete the provider page (verification, CAPTCHA, MFA or consent) yourself; then resume.'}
        if host not in self.mail_hosts:
            return {'state': 'unknown', 'identity_match': False,
                    'checkpoint': 'No supported mail page observed. Open the mail application or retry after the provider recovers.'}
        found = set()
        for selector in self.identity_selectors:
            locator = page.locator(selector)
            for i in range(min(locator.count(), 8)):
                item = locator.nth(i)
                if not item.is_visible():
                    continue
                # Account chrome only; an email in a message is never identity proof.
                text = ' '.join(filter(None, [item.get_attribute('aria-label'), item.get_attribute('title'), item.text_content()]))
                found.update(x.lower() for x in re.findall(r'[\w.!#$%&*+/=?^`{|}~-]+@[\w.-]+\.[a-zA-Z]{2,}', text))
        ready = any(page.locator(s).count() and page.locator(s).first.is_visible() for s in self.ready_selectors)
        if found and expected.lower() not in found:
            return {'state': 'identity_mismatch', 'identity_match': False,
                    'checkpoint': 'The isolated profile shows a different identity. Sign out in this profile and sign in to the saved account.'}
        if ready and found == {expected.lower()}:
            return {'state': 'authenticated', 'identity_match': True, 'checkpoint': 'Mail UI and expected account identity observed.'}
        return {'state': 'identity_unconfirmed', 'identity_match': False,
                'checkpoint': 'Open the provider account menu to expose the account email, then verify. A loaded page alone is not authentication proof.'}

    def signout(self, page) -> bool:
        def click_signout():
            scopes = [page] + [frame for frame in page.frames if frame != page.main_frame
                               and urlsplit(frame.url).hostname in self.mail_hosts + self.auth_hosts
                               and urlsplit(frame.url).scheme == urlsplit(self.mail_url).scheme]
            for scope in scopes:
                for selector in self.signout_selectors:
                    item = scope.locator(selector).first
                    if item.count() and item.is_visible():
                        item.click(timeout=5000)
                        return True
            return False
        if click_signout():
            return True
        for selector in self.account_selectors:
            item = page.locator(selector).first
            if item.count() and item.is_visible():
                item.click(timeout=3000)
                break
        for _ in range(10):
            if click_signout():
                return True
            page.wait_for_timeout(100)
        return False


PLATFORMS = {
    'google': Platform(
        'google', 'Google / Gmail', 'https://mail.google.com/mail/u/0/', 'https://accounts.google.com/signup',
        ('mail.google.com',), ('accounts.google.com',),
        ('a[aria-label^="Google Account:"]', 'button[aria-label^="Google Account:"]'),
        ('[role="main"]',),
        ('a[aria-label^="Google Account:"]', 'button[aria-label^="Google Account:"]'),
        ('a:text-is("Sign out of all accounts")', 'button:text-is("Sign out of all accounts")', 'a:text-is("Sign out")', 'button:text-is("Sign out")')),
    'microsoft': Platform(
        'microsoft', 'Microsoft / Outlook', 'https://outlook.live.com/mail/0/', 'https://signup.live.com/',
        ('outlook.live.com', 'outlook.office.com', 'outlook.office365.com', 'outlook.cloud.microsoft'),
        ('login.live.com', 'login.microsoftonline.com', 'login.microsoft.com', 'signup.live.com'),
        ('#O365_MainLink_Me', '#mectrl_currentAccount_secondary', '#mectrl_currentAccount_primary', '[data-testid="mectrl-current-account"]'),
        ('[role="main"]', '[aria-label="Message list"]'),
        ('#O365_MainLink_Me', '#mectrl_main_trigger'),
        ('#O365_MainLink_Signout', '#mectrl_body_signOut', 'a:text-is("Sign out")', 'button:text-is("Sign out")'),
        signin_url='https://outlook.live.com/mail/?prompt=select_account'),
}


def platform(key: str) -> Platform:
    try:
        return PLATFORMS[key]
    except (KeyError, TypeError):
        raise ValueError('Platform must be google or microsoft.') from None
