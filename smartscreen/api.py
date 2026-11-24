"""Additional SmartScreen reputation request schemas and server presentation metadata.

The download and beforeExecute schemas below were exercised with benign controls.
See analysis/api_expansion/ for request objects, saved response records, and native
code evidence. validation_summary.json describes raw-byte preservation per case.
"""
import copy
import hashlib
from html.parser import HTMLParser
import re

from smartscreen import ENDPOINTS, check_url, file_payload, url_payload
from smartscreen.auth import EDGE_AUTH_ID


API_ROUTES = {
    'download': {
        'endpoint': ENDPOINTS['download'], 'method': 'POST', 'auth_id': EDGE_AUTH_ID,
        'validation': 'live_validated', 'validation_date': '2026-11-23',
        'purpose': 'URL reputation before download; file bytes and hashes are not required',
        'verdict_path': 'result.$type', 'category_path': 'result.responseCategory',
        'evidence': 'analysis/api_expansion/download_{example,microsoft_demo}.response.json',
    },
    'shell': {
        'endpoint': ENDPOINTS['shell'], 'method': 'POST', 'auth_id': EDGE_AUTH_ID,
        'validation': 'live_validated', 'validation_date': '2026-11-23',
        'purpose': 'Shell application cloud reputation from file metadata',
        'verdict_path': '$type', 'category_path': 'responseCategory', 'rating_code_path': 'rating',
        'evidence': 'analysis/api_expansion/shell_{baseline,unknown}.response.json',
        'context': 'Validated using the default Edge-compatible identity and auth ID; this does not reproduce every native-shell input.',
    },
    'package-install': {
        'endpoint': 'https://checkappexec.microsoft.com/windows/shell/service/packageInstall/2',
        'method': 'POST', 'auth_id': EDGE_AUTH_ID, 'validation': 'live_validated',
        'validation_date': '2026-11-24',
        'purpose': 'Appx/MSIX package-install cloud reputation from explicit footprint metadata',
        'reader': 'smartscreen-1.2.2312.1-prefix4096',
        'verdict_path': '$type', 'category_path': 'responseCategory',
        'evidence': 'analysis/signature_catalog_expansion/findings.json and package_response.json',
        'context': 'One benign Microsoft Notepad package returned allow with the recovered legacy 4096-byte footprint reader and Edge-compatible auth/identity. Current native runtime wire parity and installation enforcement are not established.',
    },
}


def api_catalog():
    """Return an independent copy so callers cannot alter module-wide route state."""
    return [{'name': name, **copy.deepcopy(details)} for name, details in API_ROUTES.items()]


def _set_context(payload, referrer=None, config=None):
    if referrer is not None:
        payload['referrer'] = {'uri': check_url(referrer), 'ip': None}
    if config is not None:
        if not isinstance(config, dict):
            raise ValueError('Reputation config must be a JSON object')
        payload['config'] = copy.deepcopy(config)
    return payload


def download_payload(url, referrer=None, profile=None, config=None):
    """Build the validated /download/3 pre-check schema with type=download."""
    if profile is not None and not isinstance(profile, dict):
        raise ValueError('Identity profile must be a JSON object')
    payload = url_payload(url, referrer=referrer, profile=profile)
    payload['type'] = 'download'
    return _set_context(payload, config=config)


def shell_payload(sha256, size, filename, source, referrer=None, profile=None, config=None):
    """Build the validated beforeExecute/2 metadata query.

    A returned cloud block or HTML template does not establish actual local execution
    enforcement. The caller should retain both the top-level $type and opaque rating.
    """
    if profile is not None and not isinstance(profile, dict):
        raise ValueError('Identity profile must be a JSON object')
    if not isinstance(sha256, str) or not re.fullmatch(r'[0-9a-fA-F]{64}', sha256):
        raise ValueError('SHA-256 must contain exactly 64 hexadecimal characters')
    if type(size) is not int or size < 0:
        raise ValueError('File size must be a nonnegative integer')
    if not isinstance(filename, str) or not filename:
        raise ValueError('File name must be a nonempty string')
    return _set_context(file_payload(sha256, size, filename, source, profile=profile), referrer, config)


class _PresentationText(HTMLParser):
    """Read text nodes only; never load resources or evaluate server HTML."""
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack = []
        self.parts = {'messageTitle': [], 'messageBody': []}
        self.buttons = []
        self.suppressed = 0

    def handle_starttag(self, tag, attributes):
        attrs = dict(attributes)
        if tag in {'script', 'style'}:
            self.suppressed += 1
        identifier = attrs.get('id')
        button = None
        if tag == 'button':
            button = {'id': identifier, 'parts': []}
            self.buttons.append(button)
        if tag not in {'area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input', 'link', 'meta', 'param', 'source', 'track', 'wbr'}:
            self.stack.append((tag, identifier, button))

    def handle_endtag(self, tag):
        if tag in {'script', 'style'}:
            self.suppressed = max(0, self.suppressed - 1)
        for index in range(len(self.stack) - 1, -1, -1):
            if self.stack[index][0] == tag:
                del self.stack[index:]
                break

    def handle_data(self, text):
        if self.suppressed:
            return
        for _, identifier, button in self.stack:
            if identifier in self.parts:
                self.parts[identifier].append(text)
            if button is not None:
                button['parts'].append(text)


def summarize_presentation(response):
    """Describe optional server HTML without treating template controls as enabled UI."""
    html = response.get('html') if isinstance(response, dict) else None
    if not isinstance(html, str):
        return {'present': False}
    encoded = html.encode('utf-8')
    result = {'present': True, 'size': len(encoded), 'sha256': hashlib.sha256(encoded).hexdigest(),
              'note': 'Server-provided template only; button visibility and local enforcement have not been observed.'}
    if len(encoded) > 4 * 1024 * 1024:
        result['text_extraction'] = 'skipped_size_limit'
        return result
    parser = _PresentationText()
    parser.feed(html)
    parser.close()
    normalize = lambda parts: ' '.join(' '.join(parts).split())
    result['message_title'] = normalize(parser.parts['messageTitle']) or None
    result['message_body'] = normalize(parser.parts['messageBody']) or None
    result['buttons_in_template'] = [{'id': button['id'], 'text': normalize(button['parts'])}
                                     for button in parser.buttons]
    return result
