#!/usr/bin/env python3
"""Check user-facing commands against the immutable, already published RC.

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


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--readme', type=Path, required=True)
    parser.add_argument('--bootstrap', type=Path)
    parser.add_argument('--release-metadata', type=Path)
    args = parser.parse_args(argv)
    try:
        expected = [command('controller'), command('node')]
        if commands(bounded(args.readme).decode('utf-8')) != expected:
            raise Rejected('README must contain exactly the two published role commands without extra flags or mutable URLs')
        if args.bootstrap is not None and hashlib.sha256(bounded(args.bootstrap)).hexdigest() != BOOTSTRAP_SHA256:
            raise Rejected('bootstrap digest mismatch')
        if args.release_metadata is not None:
            release = json.loads(bounded(args.release_metadata))
            if (not isinstance(release, dict) or type(release.get('id')) is not int or release['id'] != RELEASE_ID or
                    release.get('tag_name') != TAG or release.get('draft') is not False or release.get('prerelease') is not True or
                    release.get('html_url') != RELEASE_URL or not isinstance(release.get('body'), str) or
                    commands(release['body']) != expected):
                raise Rejected('public release identity or documented commands changed')
        print(json.dumps({'schema': 1, 'roles': ['controller', 'node'], 'release_url': RELEASE_URL,
                          'source_commit': SOURCE, 'commands_match_published_contract': True,
                          'bootstrap_matches_published_bytes': args.bootstrap is not None,
                          'release_metadata_checked': args.release_metadata is not None,
                          'host_installation_tested': False}, sort_keys=True))
        return 0
    except (Rejected, OSError, UnicodeError, ValueError, TypeError, RecursionError) as error:
        print('Published command check refused: ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
