"""Fixed, secret-free W07-A browser evidence contract (not a UI simulation)."""
from pathlib import Path

MEMBERS_SCREENSHOTS = frozenset({
    'members-desktop-first.png', 'members-desktop-last.png',
    'members-mobile-first.png', 'members-mobile-last.png',
    'members-desktop-english-dark.png', 'members-mobile-english-dark.png',
})
MEMBERS_CHECKS = frozenset({
    'actual_mysql_inventory_205', 'desktop_complete_pagination', 'previous_page',
    'refresh_returns_first', 'same_identity_refresh_keeps_page',
    'failed_next_keeps_rows', 'retry_requested_page', 'loading_keeps_rows',
    'mobile_complete_pagination', 'mobile_320_layout', 'custom_controls',
    'english_dark_layout', 'keyboard_pagination_focus', 'logout_cancels_pending_read',
    'anonymous_read_denied', 'viewer_read_denied', 'no_business_writes',
    'six_actual_screenshots',
})
MEMBERS_ACCEPTANCE = {
    'schema': 1, 'passed': True, 'real_mysql': True, 'read_only': True,
    'total': 205, 'pages': 3, 'anonymous_status': 401, 'viewer_status': 403,
    'business_writes': 0, 'foreign_requests': 0,
}


def validate_members_browser_report(report, output):
    """Refuse partial, coerced, contaminated or non-owned screenshot evidence."""
    if not isinstance(report, dict):
        raise ValueError('MEMBERS_REPORT_INVALID')
    proof = report.get('members_acceptance')
    if (not isinstance(proof, dict) or set(proof) != set(MEMBERS_ACCEPTANCE)
            or any(type(proof[k]) is not type(v) or proof[k] != v
                   for k, v in MEMBERS_ACCEPTANCE.items())):
        raise ValueError('MEMBERS_PROOF_INVALID')
    checks = report.get('members_checks')
    if not isinstance(checks, list) or len(checks) != len(MEMBERS_CHECKS):
        raise ValueError('MEMBERS_CHECKS_INCOMPLETE')
    names = set()
    for check in checks:
        if (not isinstance(check, dict) or set(check) != {'name', 'passed'}
                or not isinstance(check['name'], str)
                or check['name'] not in MEMBERS_CHECKS or check['name'] in names
                or check['passed'] is not True):
            raise ValueError('MEMBERS_CHECK_INVALID')
        names.add(check['name'])
    shots = report.get('members_screenshots')
    if (not isinstance(shots, list) or len(shots) != len(MEMBERS_SCREENSHOTS)
            or any(not isinstance(name, str) for name in shots)
            or set(shots) != MEMBERS_SCREENSHOTS):
        raise ValueError('MEMBERS_SCREENSHOTS_INCOMPLETE')
    output = Path(output)
    for name in shots:
        file = output / name
        if file.is_symlink() or not file.is_file() or file.stat().st_size < 8:
            raise ValueError('MEMBERS_SCREENSHOT_MISSING')
        with file.open('rb') as stream:
            if stream.read(8) != b'\x89PNG\r\n\x1a\n':
                raise ValueError('MEMBERS_SCREENSHOT_INVALID')
    return MEMBERS_SCREENSHOTS
