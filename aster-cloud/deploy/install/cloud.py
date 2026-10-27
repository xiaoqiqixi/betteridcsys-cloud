#!/usr/bin/env python3
"""Single interactive entry for the authenticated controller/node installer.

This reviewed, immutable initial script is an operator trust root. It selects
one role, verifies the exact published bootstrap bytes and then delegates all
release verification and installation to that bootstrap. No arbitrary URL,
shell, application code or implicit apply/start is accepted here.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import select
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request

VERSION = '0.1.0-rc.1'
SOURCE = '8092c3cc0517c69562e8a5cdd94bc5e389e1bc8e'
URL = ('https://raw.githubusercontent.com/xiaoqiqixi/betteridcsys/' + SOURCE +
       '/aster-cloud/deploy/install/release_verify.py')
BOOTSTRAP_SHA256 = '14b9a22b9c06ac7f743621adf650197064d0c971383935ccb861db1d6bbd397f'
BOOTSTRAP_SIZE = 39436
MAX_DOWNLOAD = 1024 * 1024
ROLES = {'1': 'controller', '2': 'node'}


class Refused(Exception):
    pass


def choose_role():
    # stdin may contain this very script (curl | python -). Never read answers
    # from that pipe, assume a default role, or consume unattended input.
    fd = os.open('/dev/tty', os.O_RDWR | os.O_NOCTTY)
    try:
        if not os.isatty(fd):
            raise Refused('需要交互终端；自动化调用请明确指定 controller 或 node。')
        os.write(fd, ('\n星屿云安装向导\n'
                      '  1  安装云主控（管理台）\n'
                      '  2  安装 KVM 被控（专用计算宿主）\n'
                      '  0  退出，不作任何修改\n\n'
                      '请选择 [1/2/0]，无默认选项：').encode())
        if not select.select([fd], [], [], 300)[0]:
            raise Refused('选择超时，未下载或安装。')
        answer = os.read(fd, 64)
        if len(answer) >= 64 or not answer.endswith(b'\n'):
            raise Refused('无效选择，未下载或安装。')
        selected = answer.decode('ascii', errors='strict').strip()
        if selected == '0':
            return None
        if selected not in ROLES:
            raise Refused('请选择 1、2 或 0；未下载或安装。')
        return ROLES[selected]
    finally:
        os.close(fd)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def download_bootstrap():
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
                                       urllib.request.HTTPSHandler(context=context))
    request = urllib.request.Request(URL, headers={'User-Agent': 'aster-cloud-unified-installer',
                                                   'Accept-Encoding': 'identity'})
    try:
        with opener.open(request, timeout=20) as response:
            if response.status != 200 or response.geturl() != URL or response.headers.get('Content-Encoding', 'identity') != 'identity':
                raise Refused('安装入口下载来源不符。')
            deadline, size, chunks = time.monotonic() + 60, 0, []
            while True:
                if time.monotonic() > deadline:
                    raise Refused('安装入口下载超时。')
                chunk = response.read(min(65536, MAX_DOWNLOAD + 1 - size))
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_DOWNLOAD:
                    raise Refused('安装入口大小异常。')
                chunks.append(chunk)
            raw = b''.join(chunks)
    except (OSError, urllib.error.URLError):
        raise Refused('无法下载已核验版本；请检查网络，不会改用其他来源。') from None
    if len(raw) != BOOTSTRAP_SIZE or hashlib.sha256(raw).hexdigest() != BOOTSTRAP_SHA256:
        raise Refused('安装入口校验失败，未执行下载内容。')
    return raw


def delegate(role, args):
    if sys.platform != 'linux' or os.geteuid() != 0 or os.uname().machine != 'x86_64':
        raise Refused('安装需要 Ubuntu 22.04/24.04 amd64 和 root 权限。')
    # The authenticated installer independently checks Ubuntu, protected paths,
    # configuration and host state. This launcher cannot bypass those checks.
    raw = download_bootstrap()
    command = ['/usr/bin/python3', '-I', '-', role]
    if args.download_only:
        command.append('--download-only')
    if args.evidence:
        command.extend(['--evidence', str(args.evidence)])
    if args.resume:
        command.append('--resume')
    env = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8',
           'HOME': '/root', 'PYTHONDONTWRITEBYTECODE': '1'}
    print('正在核验 ' + VERSION + ' 安装文件；安装与启动仍需在向导中明确确认。', flush=True)
    # No shell, inherited tokens/proxy variables or user-chosen executable.
    # The child opens its controlling tty for the actual installation wizard.
    return subprocess.run(command, input=raw, env=env, check=False).returncode


def main(argv=None):
    parser = argparse.ArgumentParser(description='星屿云统一安装入口：选择主控或 KVM 被控。')
    parser.add_argument('role', nargs='?', choices=('controller', 'node'))
    parser.add_argument('--select-only', action='store_true', help='仅检查交互选择，不下载、不安装')
    parser.add_argument('--download-only', action='store_true', help='实际验签并生成只读安装计划，不安装或启动')
    parser.add_argument('--evidence', type=Path, help='仅用于 download-only 的全新脱敏证明文件')
    parser.add_argument('--resume', action='store_true', help='明确恢复同一次安装，不覆盖旧操作')
    args = parser.parse_args(argv)
    try:
        if args.evidence and not args.download_only or args.select_only and (args.download_only or args.evidence or args.resume):
            raise Refused('参数组合不允许。')
        role = args.role or choose_role()
        if role is None:
            print('已退出，未下载或安装。')
            return 0
        if args.select_only:
            print(json.dumps({'role': role, 'downloaded': False, 'installed': False}, sort_keys=True))
            return 0
        return delegate(role, args)
    except (Refused, OSError, UnicodeError, ValueError) as exc:
        message = str(exc) if isinstance(exc, Refused) else '无法使用交互终端或读取安全安装状态；未继续。'
        print('安装未继续：' + message, file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print('\n已取消；如已进入安装向导，请保留原操作记录并检查状态。', file=sys.stderr)
        return 130


if __name__ == '__main__':
    raise SystemExit(main())
