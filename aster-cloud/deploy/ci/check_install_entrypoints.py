#!/usr/bin/env python3
"""Check the unified entry and its immutable, already published RC delegate.

No command execution or networking. Download/cryptographic plan acceptance is a
separate workflow. These pinned facts must migrate before the old repo is deleted.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

REPOSITORY = 'xiaoqiqixi/betteridcsys'
RELEASE_ID = 425041579
TAG = 'cloud-v0.1.0-rc.1'
SOURCE = '8092c3cc0517c69562e8a5cdd94bc5e389e1bc8e'
BOOTSTRAP_SHA256 = '14b9a22b9c06ac7f743621adf650197064d0c971383935ccb861db1d6bbd397f'
URL = 'https://raw.githubusercontent.com/' + REPOSITORY + '/' + SOURCE + '/aster-cloud/deploy/install/release_verify.py'
RELEASE_URL = 'https://github.com/' + REPOSITORY + '/releases/tag/' + TAG
ENTRY_SOURCE = '92e484389a84312ab5b5f8d25688a93d7047926f'
ENTRY_SHA256 = '5573783622f7ebea88c1c1bbc789a6533e30cf08c5ff8f210a21e7ad5e3eea01'
ENTRY_URL = 'https://raw.githubusercontent.com/xiaoqiqixi/betteridcsys-cloud/' + ENTRY_SOURCE + '/aster-cloud/deploy/install/cloud.py'


class Rejected(ValueError):
    pass


def bounded(path):
    with path.open('rb') as stream:
        raw = stream.read(1048577)
    if not 0 < len(raw) <= 1048576:
        raise Rejected('input exceeds fixed size limit')
    return raw


def command(role):
    if role not in ('controller', 'node'):
        raise Rejected('unknown role')
    return ('bash -o pipefail -c \'curl --fail --silent --show-error --proto "=https" --tlsv1.2 '
            '--connect-timeout 10 --max-time 60 --max-filesize 1048576 ' + URL +
            ' | sudo /usr/bin/python3 -I - ' + role + "'")


def commands(text):
    return re.findall(r'(?m)^```sh\n([^`]+)\n```$', text)


def unified_command():
    return ('bash -o pipefail -c \'curl --fail --silent --show-error --proto "=https" --tlsv1.2 '
            '--connect-timeout 10 --max-time 60 --max-filesize 1048576 ' + ENTRY_URL +
            " | sudo /usr/bin/python3 -I -'")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--readme', type=Path, required=True)
    parser.add_argument('--bootstrap', type=Path)
    parser.add_argument('--entry', type=Path)
    parser.add_argument('--release-metadata', type=Path)
    args = parser.parse_args(argv)
    try:
        expected = [unified_command()]
        if commands(bounded(args.readme).decode('utf-8')) != expected:
            raise Rejected('README must contain exactly the reviewed unified command without extra flags or mutable URLs')
        if args.entry is not None and hashlib.sha256(bounded(args.entry)).hexdigest() != ENTRY_SHA256:
            raise Rejected('unified entry digest mismatch')
        if args.bootstrap is not None and hashlib.sha256(bounded(args.bootstrap)).hexdigest() != BOOTSTRAP_SHA256:
            raise Rejected('bootstrap digest mismatch')
        if args.release_metadata is not None:
            release = json.loads(bounded(args.release_metadata))
            if (not isinstance(release, dict) or type(release.get('id')) is not int or release['id'] != RELEASE_ID or
                    release.get('tag_name') != TAG or release.get('draft') is not False or release.get('prerelease') is not True or
                    release.get('html_url') != RELEASE_URL or not isinstance(release.get('body'), str) or
                    commands(release['body']) != [command('controller'), command('node')]):
                raise Rejected('public release identity or documented commands changed')
        print(json.dumps({'schema': 1, 'roles': ['controller', 'node'], 'release_url': RELEASE_URL,
                          'source_commit': SOURCE, 'entry_source': ENTRY_SOURCE,
                          'unified_command_matches_reviewed_contract': True,
                          'legacy_delegate_contract_matches': True,
                          'entry_matches_reviewed_bytes': args.entry is not None,
                          'bootstrap_matches_published_bytes': args.bootstrap is not None,
                          'release_metadata_checked': args.release_metadata is not None,
                          'host_installation_tested': False}, sort_keys=True))
        return 0
    except (Rejected, OSError, UnicodeError, ValueError, TypeError, RecursionError) as error:
        print('Published command check refused: ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
