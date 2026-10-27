#!/usr/bin/env python3
"""Protected source-host isolation for the native controller installation.

Only fixed controller/approved heartbeat units may be changed. Source isolation
is not encrypted export, target activation, distributed fencing or VM migration.
The installed root-owned bundle is the local trust boundary, not a JSON claim
that a new release has been authenticated.
"""
import argparse
import contextlib
import ctypes
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

PROTOCOL = 'aster.controller-migration/1'
SYSTEMD = Path('/etc/systemd/system')
CONFIG = Path('/etc/aster-controller/config.json')
INSTALL_STATE = Path('/var/lib/aster-cloud-installer/controller/state.json')
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8',
       'HOME': '/root', 'SYSTEMD_PAGER': 'cat', 'SYSTEMD_COLORS': '0'}
OP = re.compile(r'[0-9a-f]{32}\Z')
NODE = re.compile(r'[a-z0-9][a-z0-9_-]{0,63}\Z')
SHA = re.compile(r'[0-9a-f]{64}\Z')
PROPS = ('Id,Names,FragmentPath,DropInPaths,NeedDaemonReload,LoadState,ActiveState,SubState,'
         'MainPID,ControlPID,ControlGroup,KillMode,User,Group,Type,ExecStop,ExecStopPost,UnitFileState')


class Refused(Exception):
    pass


def require(ok, code):
    if not ok:
        raise Refused(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def install_module():
    spec = importlib.util.spec_from_file_location('aster_host_installer', Path(__file__).with_name('install.py'))
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    sys.dont_write_bytecode = True
    spec.loader.exec_module(module)
    return module


def run(argv, timeout=60, confirmed_errors=False):
    # No shell, inherited environment, user URL, unit override or executable.
    try:
        r = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=ENV,
                           stdin=subprocess.DEVNULL, timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        raise Refused('FIXED_HOST_COMMAND_UNCONFIRMED') from None
    require(len(r.stdout) <= 1024 * 1024 and len(r.stderr) <= 65536, 'HOST_OUTPUT_BOUND_EXCEEDED')
    if confirmed_errors and r.returncode != 0:
        try:
            error = json.loads(r.stderr)
        except (ValueError, UnicodeError):
            raise Refused('TARGET_COMMAND_UNCONFIRMED') from None
        require(not r.stdout and isinstance(error, dict) and
                set(error) == {'time', 'level', 'msg', 'component', 'code'} and
                error['level'] == 'ERROR' and error['msg'] == 'aster_command_failed' and
                error['component'] == 'controller' and
                ((r.returncode == 1 and error['code'] in ('COMMAND_FAILED', 'CONTROLLER_MIGRATION_BUSY')) or
                 (r.returncode == 78 and error['code'] == 'CONTROLLER_MIGRATION_FENCED')),
                'TARGET_COMMAND_UNCONFIRMED')
        raise Refused('TARGET_COMMAND_REJECTED')
    require(r.returncode == 0, 'FIXED_HOST_COMMAND_REJECTED')
    return r.stdout


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def inode(path, kind):
    value = path.lstat()
    require(value.st_uid == 0 and value.st_nlink == 1, 'HOST_INODE_OWNER_OR_LINKS')
    if kind == 'mask':
        require(stat.S_ISLNK(value.st_mode) and os.readlink(path) == '/dev/null', 'HOST_MASK_NOT_DEV_NULL')
    else:
        require(stat.S_ISREG(value.st_mode) and stat.S_IMODE(value.st_mode) == 0o644, 'HOST_UNIT_MODE_INVALID')
    return {'device': value.st_dev, 'inode': value.st_ino}


def exchange(source, target, flags):
    # Atomic exchange preserves the original /etc unit and leaves no unmasked
    # gap. NOREPLACE installs an instance mask without replacing a foreign file.
    libc = ctypes.CDLL(None, use_errno=True)
    function = libc.renameat2
    function.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    function.restype = ctypes.c_int
    if function(-100, os.fsencode(source), -100, os.fsencode(target), flags) != 0:
        raise Refused('ATOMIC_UNIT_RENAME_REFUSED')
    sync_directory(source.parent)
    if target.parent != source.parent:
        sync_directory(target.parent)


def inode_record(value):
    return (isinstance(value, dict) and set(value) == {'device', 'inode'} and
            all(type(v) is int and v > 0 for v in value.values()))


def bundle_bytes(installer, path):
    # Empty static assets are valid manifest entries, unlike configuration and
    # credential files. Keep their ownership, inode and length checks intact.
    installer.protected_path(str(path))
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        st = os.fstat(stream.fileno())
        require(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and st.st_nlink == 1 and
                not st.st_mode & 0o022 and st.st_size <= installer.MAX_FILE_BYTES, 'INSTALLED_FILE_UNSAFE')
        raw = stream.read(installer.MAX_FILE_BYTES + 1)
        require(len(raw) == st.st_size, 'INSTALLED_FILE_LENGTH_CHANGED')
        return raw


def verify_installation(self, installer, target=False):
    state_raw = installer.protected_read(str(INSTALL_STATE), 1024 * 1024)
    state = installer.strict_json(state_raw)
    require(state.get('schema') == 1 and state.get('component') == 'controller' and isinstance(state.get('steps'), list),
            'MANAGED_INSTALLATION_REQUIRED')
    if target:
        require(state.get('status') == 'software-installed' and state.get('configuration') == 'waiting-approval' and
                state.get('service') == 'not-started' and state.get('current_step') is None and
                'software-installed' in state['steps'] and set(state['steps']) <= {'software-installed', 'native-dependencies'} and
                not state.get('approval_sha256') and not state.get('wizard_request_sha256'), 'FRESH_SOFTWARE_TARGET_REQUIRED')
    else:
        require(state.get('status') in ('configuration-approved', 'service-ready') and
                {'software-installed', 'configuration-approved', 'inactive-systemd-unit'} <= set(state['steps']),
                'MANAGED_INSTALLATION_REQUIRED')
    version, bundle_sha, source = state.get('version'), state.get('bundle_sha256'), state.get('source_commit')
    require(isinstance(version, str) and re.fullmatch(r'0\.[0-9]+\.[0-9]+-(?:dev(?:\.[0-9]+)?|rc\.[0-9]+)', version) and
            isinstance(bundle_sha, str) and SHA.fullmatch(bundle_sha) and isinstance(source, str) and
            re.fullmatch(r'[0-9a-f]{40}', source), 'INSTALLATION_IDENTITY_INVALID')
    self.version_dir = Path('/opt/aster-cloud/controller/versions') / (version + '-' + bundle_sha[:16])
    manifest_raw = installer.protected_read(str(self.version_dir / 'manifest.json'), 4 * 1024 * 1024, False)
    manifest = installer.strict_json(manifest_raw)
    require(manifest.get('schema') == 1 and manifest.get('component') == 'aster-cloud-controller' and
            manifest.get('version') == version and manifest.get('source_commit') == source and
            manifest.get('platform') == 'linux-amd64', 'INSTALLED_MANIFEST_MISMATCH')
    entries = manifest.get('files')
    require(isinstance(entries, list) and 1 <= len(entries) <= 10000, 'INSTALLED_INVENTORY_INVALID')
    names, total = set(), 0
    for entry in entries:
        require(isinstance(entry, dict) and set(entry) == {'path', 'sha256', 'size', 'mode'}, 'INSTALLED_ENTRY_INVALID')
        name = installer.safe_member(entry['path'])
        require(name not in names and name != 'manifest.json' and type(entry['size']) is int and
                0 <= entry['size'] <= installer.MAX_FILE_BYTES and entry['mode'] in ('0644', '0755') and
                isinstance(entry['sha256'], str) and SHA.fullmatch(entry['sha256']), 'INSTALLED_ENTRY_INVALID')
        raw = bundle_bytes(installer, self.version_dir / name)
        require(len(raw) == entry['size'] and digest(raw) == entry['sha256'] and
                stat.S_IMODE((self.version_dir / name).stat().st_mode) == int(entry['mode'], 8), 'INSTALLED_BYTES_CHANGED')
        names.add(name)
        total += len(raw)
        require(total <= installer.MAX_TOTAL_BYTES, 'INSTALLED_TOTAL_EXCEEDED')
    actual = set()
    for base, directories, files in os.walk(self.version_dir, followlinks=False):
        installer.protected_path(str(Path(base)), directory=True)
        for name in directories:
            installer.protected_path(str(Path(base) / name), directory=True)
        for name in files:
            actual.add((Path(base) / name).relative_to(self.version_dir).as_posix())
            require(len(actual) <= 10001, 'INSTALLED_TOTAL_EXCEEDED')
    require(actual == names | {'manifest.json'} and {'bin/aster-controller', 'ui/index.html'} <= names, 'INSTALLED_INVENTORY_CHANGED')
    self.binary = self.version_dir / 'bin/aster-controller'
    require(stat.S_IMODE(self.binary.stat().st_mode) == 0o755, 'CONTROLLER_NOT_EXECUTABLE')
    caps = installer.strict_json(run([str(self.binary), 'migration-capabilities'], 10))
    require(caps.get('schema') == 1 and caps.get('protocol') == 'aster.controller-host/1' and
            caps.get('runtime_fence') is True and caps.get('host_migration_seal') is True,
            'OLD_CONTROLLER_LACKS_HOST_SEAL')
    return state_raw, manifest_raw, source, bundle_sha


class Host:
    def __init__(self, installer):
        self.i = installer
        installer.check_target()
        self.config_raw = installer.protected_read(str(CONFIG), 65536)
        self.config = installer.strict_json(self.config_raw)
        self.id = self.config.get('controller_id')
        require(isinstance(self.id, str) and NODE.fullmatch(self.id), 'CONTROLLER_ID_INVALID')
        self.nodes = self.config.get('nodes')
        require(isinstance(self.nodes, list) and len(self.nodes) <= 64, 'APPROVED_NODES_INVALID')
        ids = [n.get('id') for n in self.nodes if isinstance(n, dict)]
        require(len(ids) == len(self.nodes) and all(isinstance(n, str) and NODE.fullmatch(n) for n in ids) and
                len(set(ids)) == len(ids), 'APPROVED_NODES_INVALID')
        self.node_ids = sorted(ids)
        state_raw, manifest_raw, source, bundle_sha = verify_installation(self, installer)
        self.root = Path('/var/lib/aster-controller') / self.id
        machine = installer.protected_read('/etc/machine-id', 128, False).strip()
        require(re.fullmatch(b'[0-9a-f]{32}', machine), 'MACHINE_ID_INVALID')
        require(Path('/sys/fs/cgroup/cgroup.controllers').is_file(), 'CGROUP_V2_REQUIRED')
        self.identity = {'controller_id': self.id, 'configuration_sha256': digest(self.config_raw),
                         'installation_sha256': digest(state_raw), 'manifest_sha256': digest(manifest_raw),
                         'source_commit': source, 'bundle_sha256': bundle_sha, 'machine_id_sha256': digest(machine),
                         'runtime_materials_sha256': self.material_digest()}

    def material_digest(self):
        # A config file with unchanged path strings is not an unchanged source
        # when its DSN, tokens or TLS files have been replaced underneath it.
        # Only digests enter the private journal; no secret bytes reach output.
        fields = [(key, self.config.get(key), key != 'tls_cert_file', 65536 if key.startswith('tls_') else 4096)
                  for key in ('dsn_file', 'tls_cert_file', 'tls_key_file', 'billing_token_file',
                              'admin_read_token_file', 'admin_write_token_file')]
        for node in sorted(self.nodes, key=lambda n: n['id']):
            fields += [(node['id'] + ':' + key, node.get(key), key == 'client_key_file', 1024 * 1024)
                       for key in ('ca_file', 'client_cert_file', 'client_key_file')]
        h = hashlib.sha256()
        for label, path, private, maximum in fields:
            require(isinstance(path, str), 'RUNTIME_MATERIAL_REFERENCE_INVALID')
            raw = self.i.protected_read(path, maximum, private)
            h.update(json.dumps([label, path, digest(raw)], separators=(',', ':')).encode() + b'\n')
        return h.hexdigest()

    def fresh_identity(self):
        require(digest(self.i.protected_read(str(CONFIG), 65536)) == self.identity['configuration_sha256'] and
                digest(self.i.protected_read(str(INSTALL_STATE), 1024 * 1024)) == self.identity['installation_sha256'] and
                self.material_digest() == self.identity['runtime_materials_sha256'],
                'HOST_SOURCE_IDENTITY_CHANGED')

    def command(self, action, operation=None):
        argv = [str(self.binary), 'migration-' + action, '-config', str(CONFIG)]
        if operation:
            argv += ['-operation', operation]
        return self.i.strict_json(run(argv, 45))

    def show(self, names):
        raw = run(['/usr/bin/systemctl', 'show', '--no-pager', '--property=' + PROPS, '--', *names], 30).decode()
        result = {}
        for block in raw.strip().split('\n\n'):
            item = {}
            for line in block.splitlines():
                require('=' in line, 'SYSTEMD_PROPERTIES_INVALID')
                key, value = line.split('=', 1)
                require(key not in item and key in PROPS.split(','), 'SYSTEMD_PROPERTIES_INVALID')
                item[key] = value
            name = item.get('Id')
            require(name in names and name not in result, 'SYSTEMD_UNIT_IDENTITY_INVALID')
            result[name] = item
        require(set(result) == set(names), 'SYSTEMD_UNIT_INVENTORY_INCOMPLETE')
        return result

    def inventory(self):
        names = ['aster-controller.service']
        for suffix in ('service', 'timer'):
            template = SYSTEMD / ('controller-heartbeat@.' + suffix)
            if template.exists() or template.is_symlink():
                expected = self.i.protected_read(str(self.version_dir / 'templates' / template.name), 16384, False)
                if suffix == 'service':
                    expected = expected.replace(b'/opt/aster-cloud/bin/aster-controller', os.fsencode(self.binary))
                require(self.i.protected_read(str(template), 16384, False) == expected, 'HEARTBEAT_TEMPLATE_CHANGED')
                names += ['controller-heartbeat@' + n + '.' + suffix for n in self.node_ids]
        require(not any(n.endswith('.timer') for n in names) or all(n[:-6] + '.service' in names for n in names if n.endswith('.timer')),
                'HEARTBEAT_TIMER_WITHOUT_SERVICE')
        listed = run(['/usr/bin/systemctl', 'list-units', '--all', '--plain', '--no-pager', '--no-legend',
                      'aster-controller*', 'controller-aster*', 'controller-heartbeat*'], 30).decode()
        observed = [line.split()[0] for line in listed.splitlines() if line.strip()]
        require(set(observed) <= set(names), 'UNMANAGED_CONTROLLER_UNIT_PRESENT')
        return sorted(names)

    def plan(self):
        # The installed binary's capability says nothing about an older copy
        # left running outside its unit. Refuse recognizable foreign controller
        # processes; never kill them or pretend their writes were drained.
        expected = self.binary.stat()
        processes = [p for p in Path('/proc').iterdir() if p.name.isdigit()]
        require(len(processes) <= 32768, 'PROCESS_INVENTORY_LIMIT')
        for process in processes:
            try:
                executable = os.readlink(process / 'exe')
                if Path(executable.removesuffix(' (deleted)')).name != 'aster-controller':
                    continue
                actual = (process / 'exe').stat()
            except FileNotFoundError:
                continue # process exited; no guessed PID is signalled
            except PermissionError:
                raise Refused('PROCESS_INVENTORY_UNCONFIRMED') from None
            require((actual.st_dev, actual.st_ino) == (expected.st_dev, expected.st_ino), 'UNMANAGED_CONTROLLER_PROCESS')
        names = self.inventory()
        props = self.show(names)
        units = []
        for index, name in enumerate(names):
            p = props[name]
            require(p.get('LoadState') == 'loaded' and p.get('NeedDaemonReload') == 'no' and not p.get('DropInPaths') and
                    p.get('Names', '').split() == [name] and not p.get('ExecStop') and not p.get('ExecStopPost'), 'UNMANAGED_UNIT_SETTINGS')
            target = SYSTEMD / name
            if name == 'aster-controller.service':
                raw = self.i.protected_read(str(target), 16384, False)
                prefix = 'ExecStart=' + str(self.binary) + ' serve -config ' + str(CONFIG)
                lines = [s for s in raw.decode().splitlines() if s.startswith('ExecStart=')]
                require(len(lines) == 1 and lines[0].startswith(prefix), 'CONTROLLER_EXECUTABLE_CHANGED')
                tail, approval = lines[0][len(prefix):], None
                if tail:
                    suffix = ' -ui-dir ' + str(self.version_dir / 'ui')
                    require(tail.startswith(' -console-origin ') and tail.endswith(suffix), 'CONTROLLER_ARGUMENTS_CHANGED')
                    origin = tail[len(' -console-origin '):-len(suffix)]
                    self.i.parse_origin(origin)
                    approval = {'console_origin': origin}
                require(raw == self.i.unit_bytes('controller', self.version_dir, approval), 'CONTROLLER_UNIT_NOT_MANAGED')
                fragment, original_inode = target, inode(target, 'unit')
                executable_args = lines[0][len('ExecStart='):].split()
            else:
                require(not target.exists() and not target.is_symlink(), 'HEARTBEAT_INSTANCE_OVERRIDE_PRESENT')
                fragment = SYSTEMD / ('controller-heartbeat@.' + name.rsplit('.', 1)[1])
                raw = self.i.protected_read(str(fragment), 16384, False)
                original_inode = None
                executable_args = [str(self.binary), 'heartbeat', '-config', str(CONFIG), '-node', name.split('@', 1)[1].rsplit('.', 1)[0]]
            require(p.get('FragmentPath') == str(fragment), 'UNIT_FRAGMENT_UNEXPECTED')
            if name.endswith('.service'):
                require(p.get('KillMode') == 'control-group' and p.get('User') == 'root' and p.get('Group') == 'root' and
                        p.get('ControlPID') == '0', 'SERVICE_STOP_NOT_BOUNDED')
                pid = p.get('MainPID', '')
                require(pid.isdigit(), 'SERVICE_PID_UNCONFIRMED')
                if int(pid):
                    info, expected = Path('/proc', pid, 'exe').stat(), self.binary.stat()
                    require((info.st_dev, info.st_ino) == (expected.st_dev, expected.st_ino) and
                            Path('/proc', pid, 'cmdline').read_bytes() == b'\0'.join(os.fsencode(a) for a in executable_args) + b'\0',
                            'RUNNING_CONTROLLER_IDENTITY_CHANGED')
            require(p.get('ActiveState') in ('active', 'inactive', 'failed'), 'UNIT_TRANSITION_IN_PROGRESS')
            units.append({'name': name, 'fragment': str(fragment), 'sha256': digest(raw), 'original_inode': original_inode,
                          'control_group': p.get('ControlGroup', ''), 'enabled': p.get('UnitFileState', ''), 'index': index})
        return {'schema': 1, 'identity': self.identity, 'units': units}

    def write(self, path, value):
        raw = json.dumps(value, sort_keys=True, separators=(',', ':')).encode() + b'\n'
        require(len(raw) <= 256 * 1024, 'HOST_RECORD_LIMIT')
        self.i.write_new(path, raw)
        sync_directory(path.parent)

    def read(self, path):
        return self.i.strict_json(self.i.protected_read(str(path), 256 * 1024))

    @contextlib.contextmanager
    def lock(self, name):
        path = self.root / name
        self.i.protected_path(str(path), private=True, allow_missing=True)
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        try:
            st = os.fstat(fd)
            require(st.st_uid == 0 and st.st_nlink == 1 and stat.S_ISREG(st.st_mode) and stat.S_IMODE(st.st_mode) == 0o600,
                    'HOST_LOCK_INVALID')
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise Refused('HOST_OPERATION_BUSY') from None
            yield
        finally:
            os.close(fd)

    def bind(self, operation, initial=None):
        directory = self.root / 'host-migrations' / operation
        marker = self.root / 'host-migration.json'
        if initial is not None:
            self.i.ensure_dir(directory)
            if (directory / 'plan.json').exists():
                # A crash after the immutable plan but before the seal can let
                # systemd finish stopping a fenced process. Keep the ORIGINAL
                # cgroup evidence, not a fresh empty-group observation.
                saved = self.read(directory / 'plan.json')
                self.validate_plan(saved)
                def stable(p):
                    return {'schema': p['schema'], 'identity': p['identity'],
                            'units': [{k: v for k, v in u.items() if k != 'control_group'} for u in p['units']]}
                require(stable(saved) == stable(initial), 'UNSEALED_PLAN_CHANGED')
                initial = saved
            self.write(directory / 'plan.json', initial)
            with self.lock('control.lock'):
                fence = self.read(self.root / 'fence.json')
                require(fence.get('operation_id') == operation and fence.get('controller_id') == self.id, 'RUNTIME_FENCE_IDENTITY_MISMATCH')
                self.write(marker, {'schema': 1, 'operation_id': operation, 'controller_id': self.id,
                                    'plan_sha256': digest(self.i.protected_read(str(directory / 'plan.json'), 256 * 1024))})
        plan = self.read(directory / 'plan.json')
        self.validate_plan(plan)
        seal = self.read(marker) if marker.exists() or marker.is_symlink() else self.read(directory / 'resumed-marker.json')
        require(seal == {'schema': 1, 'operation_id': operation, 'controller_id': self.id,
                         'plan_sha256': digest(self.i.protected_read(str(directory / 'plan.json'), 256 * 1024))}, 'HOST_SEAL_CHANGED')
        return directory, plan

    def validate_plan(self, plan):
        require(isinstance(plan, dict) and set(plan) == {'schema', 'identity', 'units'} and
                type(plan['schema']) is int and plan['schema'] == 1 and plan['identity'] == self.identity,
                'HOST_SOURCE_IDENTITY_CHANGED')
        names = self.inventory()
        require(isinstance(plan['units'], list) and len(plan['units']) == len(names), 'HOST_UNIT_PLAN_CHANGED')
        for index, (unit, name) in enumerate(zip(plan['units'], names)):
            fragment = SYSTEMD / (name if name == 'aster-controller.service' else 'controller-heartbeat@.' + name.rsplit('.', 1)[1])
            require(isinstance(unit, dict) and set(unit) == {'name', 'index', 'fragment', 'sha256', 'original_inode', 'control_group', 'enabled'} and
                    unit['name'] == name and type(unit['index']) is int and unit['index'] == index and
                    unit['fragment'] == str(fragment) and isinstance(unit['sha256'], str) and SHA.fullmatch(unit['sha256']) and
                    (inode_record(unit['original_inode']) if name == 'aster-controller.service' else unit['original_inode'] is None) and
                    isinstance(unit['enabled'], str) and unit['enabled'] in ('enabled', 'enabled-runtime', 'disabled', 'static', 'indirect') and
                    isinstance(unit['control_group'], str) and len(unit['control_group']) <= 1024 and
                    (not unit['control_group'] or re.fullmatch(r'/system\.slice/[A-Za-z0-9_.@\\\x2d/]+', unit['control_group'])) and
                    all(p not in ('.', '..') for p in unit['control_group'].split('/')), 'HOST_UNIT_PLAN_INVALID')

    def validate_mask_record(self, record, unit):
        require(isinstance(record, dict) and set(record) == {'name', 'index', 'mask_inode'} and
                record['name'] == unit['name'] and type(record['index']) is int and record['index'] == unit['index'] and
                inode_record(record['mask_inode']), 'MASK_RECORD_INVALID')

    def paths(self, operation, unit):
        target = SYSTEMD / unit['name']
        stage = SYSTEMD / ('.aster-migration-' + operation + '-' + str(unit['index']) + '.saved')
        return target, stage

    def mask(self, directory, operation, unit):
        target, stage = self.paths(operation, unit)
        record_path = directory / ('unit-' + str(unit['index']) + '.json')
        if record_path.exists():
            record = self.read(record_path)
        else:
            require(not stage.exists() and not stage.is_symlink(), 'UNRECORDED_MASK_STAGE_REQUIRES_REVIEW')
            if unit['original_inode'] is not None:
                require(inode(target, 'unit') == unit['original_inode'] and digest(self.i.protected_read(str(target), 16384, False)) == unit['sha256'], 'SOURCE_UNIT_CHANGED')
            else:
                require(not target.exists() and not target.is_symlink(), 'INSTANCE_UNIT_APPEARED')
            os.symlink('/dev/null', stage)
            sync_directory(SYSTEMD)
            record = {'name': unit['name'], 'index': unit['index'], 'mask_inode': inode(stage, 'mask')}
            self.write(record_path, record)
        self.validate_mask_record(record, unit)
        if target.is_symlink() and inode(target, 'mask') == record['mask_inode']:
            self.masked_unit(operation, unit, record)
            return
        require(inode(stage, 'mask') == record['mask_inode'], 'MASK_STAGE_CHANGED')
        if unit['original_inode'] is not None:
            require(inode(target, 'unit') == unit['original_inode'] and digest(self.i.protected_read(str(target), 16384, False)) == unit['sha256'], 'SOURCE_UNIT_CHANGED')
            exchange(stage, target, 2) # RENAME_EXCHANGE
        else:
            require(not target.exists() and not target.is_symlink(), 'INSTANCE_UNIT_APPEARED')
            exchange(stage, target, 1) # RENAME_NOREPLACE
        self.masked_unit(operation, unit, record)

    def masked_unit(self, operation, unit, record):
        self.validate_mask_record(record, unit)
        target, stage = self.paths(operation, unit)
        require(inode(target, 'mask') == record['mask_inode'], 'PERSISTENT_MASK_CHANGED')
        if unit['original_inode'] is not None:
            require(inode(stage, 'unit') == unit['original_inode'] and digest(self.i.protected_read(str(stage), 16384, False)) == unit['sha256'], 'SAVED_SOURCE_UNIT_CHANGED')
        else:
            require(not stage.exists() and not stage.is_symlink(), 'UNEXPECTED_MASK_STAGE')

    def verify_stopped(self, units, masked):
        self.fresh_identity()
        props = self.show([u['name'] for u in units])
        for unit in units:
            p = props[unit['name']]
            require(p.get('LoadState') == ('masked' if masked else 'loaded') and
                    p.get('ActiveState') in ('inactive', 'failed') and p.get('NeedDaemonReload') == 'no' and
                    p.get('MainPID', '0') == '0' and p.get('ControlPID', '0') == '0' and not p.get('DropInPaths'),
                    'SOURCE_UNIT_NOT_ISOLATED')
            group = unit['control_group']
            if group:
                require(group.startswith('/system.slice/') and '..' not in group.split('/') and '\0' not in group, 'CGROUP_PATH_INVALID')
                root = Path('/sys/fs/cgroup') / group.lstrip('/')
                require(not root.is_symlink(), 'CGROUP_UNCONFIRMED')
                if root.exists():
                    count = 0
                    for base, dirs, files in os.walk(root, followlinks=False):
                        count += 1
                        require(count <= 256 and len(dirs) <= 128 and len(files) <= 256 and
                                len(Path(base).relative_to(root).parts) <= 16 and not Path(base).is_symlink() and
                                all(not (Path(base) / d).is_symlink() for d in dirs) and 'cgroup.procs' in files,
                                'CGROUP_UNCONFIRMED')
                        with (Path(base) / 'cgroup.procs').open() as stream:
                            require(not stream.read(65537).strip(), 'SOURCE_CGROUP_STILL_POPULATED')
        runtime = self.command('status')
        require(runtime.get('admission_blocked') is True and runtime.get('guarded_processes_drained') is True, 'SOURCE_PROCESS_NOT_DRAINED')

    def isolate(self, operation):
        marker = self.root / 'host-migration.json'
        exists = marker.exists() or marker.is_symlink()
        initial = None if exists else self.plan()
        if not exists:
            self.command('fence', operation)
        with self.lock('host-operation.lock'):
            directory, plan = self.bind(operation, initial)
            require(not (directory / 'resumed.json').exists(), 'ISOLATION_ALREADY_RESUMED')
            for unit in plan['units']:
                self.mask(directory, operation, unit)
            run(['/usr/bin/systemctl', 'daemon-reload'])
            for suffix in ('.timer', '.service'):
                names = [u['name'] for u in plan['units'] if u['name'].endswith(suffix)]
                if names:
                    run(['/usr/bin/systemctl', 'stop', '--', *names])
            self.verify_stopped(plan['units'], True)
            self.write(directory / 'isolated.json', {'schema': 1, 'operation_id': operation, 'identity': self.identity})
            return self.status(operation)

    def status(self, operation):
        directory, plan = self.bind(operation)
        if not (self.root / 'host-migration.json').exists():
            require(self.read(directory / 'resumed.json') == {'schema': 1, 'operation_id': operation, 'identity': self.identity},
                    'SOURCE_RESUME_RECEIPT_CHANGED')
            self.restored_units(operation, plan['units'])
            active = self.command('status').get('admission_blocked') is False
            return {'schema': 1, 'protocol': PROTOCOL, 'controller_id': self.id, 'operation_id': operation,
                    'phase': 'source-resumable' if active else 'source-resuming', 'source_isolated': False,
                    'migration_ready': False, 'export_restore': False, 'service_start_requested': False}
        complete = (directory / 'isolated.json').exists()
        if complete:
            require(self.read(directory / 'isolated.json') == {'schema': 1, 'operation_id': operation, 'identity': self.identity}, 'ISOLATION_RECEIPT_CHANGED')
            for unit in plan['units']:
                self.masked_unit(operation, unit, self.read(directory / ('unit-' + str(unit['index']) + '.json')))
            self.verify_stopped(plan['units'], True)
        return {'schema': 1, 'protocol': PROTOCOL, 'controller_id': self.id, 'operation_id': operation,
                'phase': 'source-isolated' if complete else 'source-isolating', 'source_isolated': complete,
                'migration_ready': False, 'export_restore': False, 'units': [u['name'] for u in plan['units']],
                'release_publisher_reverified': False, 'vm_actions_performed': False}

    def resume(self, operation):
        with self.lock('host-operation.lock'):
            directory, plan = self.bind(operation)
            require(not (directory / 'export-started.json').exists() and not (directory / 'export-started.json').is_symlink(),
                    'EXPORTED_SOURCE_CANNOT_BE_RESUMED_LOCALLY')
            # Draining must have finished even when isolation stopped halfway.
            runtime = self.command('status')
            if (self.root / 'host-migration.json').exists():
                require(runtime.get('guarded_processes_drained') is True, 'SOURCE_PROCESS_NOT_DRAINED')
            # Validate EVERY original/mask pair before undoing any mask. A
            # foreign controller inode must not partially unmask its timers.
            restorations = []
            for unit in reversed(plan['units']):
                record_path = directory / ('unit-' + str(unit['index']) + '.json')
                target, stage = self.paths(operation, unit)
                if not record_path.exists():
                    require(not stage.exists() and not stage.is_symlink(), 'UNRECORDED_MASK_STAGE_REQUIRES_REVIEW')
                    self.restored_units(operation, [unit])
                    continue
                record = self.read(record_path)
                self.validate_mask_record(record, unit)
                if target.is_symlink():
                    self.masked_unit(operation, unit, record)
                    restorations.append((unit, record, True))
                else:
                    self.restored_units(operation, [unit])
                    require(inode(stage, 'mask') == record['mask_inode'], 'RESTORED_MASK_STAGE_CHANGED')
                    restorations.append((unit, record, False))
            for unit, record, masked in restorations:
                target, stage = self.paths(operation, unit)
                if masked:
                    self.masked_unit(operation, unit, record)
                    exchange(stage, target, 2) if unit['original_inode'] is not None else exchange(target, stage, 1)
                require(inode(stage, 'mask') == record['mask_inode'], 'RESTORED_MASK_STAGE_CHANGED')
            run(['/usr/bin/systemctl', 'daemon-reload'])
            self.restored_units(operation, plan['units'])
            # Even restored units must stay stopped until the fence is removed.
            if (self.root / 'host-migration.json').exists():
                self.verify_stopped(plan['units'], False)
                with self.lock('control.lock'):
                    require(not (directory / 'export-started.json').exists() and not (directory / 'export-started.json').is_symlink(),
                            'EXPORT_STARTED_DURING_RESUME')
                    self.write(directory / 'resumed.json', {'schema': 1, 'operation_id': operation, 'identity': self.identity})
                    exchange(self.root / 'host-migration.json', directory / 'resumed-marker.json', 1)
                    sync_directory(self.root)
                    sync_directory(directory)
            result = self.command('cancel', operation)
            require(result.get('phase') == 'active' and result.get('admission_blocked') is False, 'SOURCE_RESUME_UNCONFIRMED')
            return {'schema': 1, 'operation_id': operation, 'phase': 'source-resumable', 'source_isolated': False,
                    'service_start_requested': False, 'migration_ready': False}

    def export(self, operation):
        with self.lock('host-operation.lock'):
            directory, plan = self.bind(operation)
            require(self.status(operation)['source_isolated'] is True, 'COMPLETE_SOURCE_ISOLATION_REQUIRED')
            # No implicit retry/resume after a possibly delivered backup. A
            # failed export remains isolated until the takeover protocol can
            # prove that no target has activated it.
            for name in ('export-started.json', 'recovery.key', 'backup.age', 'exported.json'):
                path = directory / name
                require(not path.exists() and not path.is_symlink(), 'EXPORT_ALREADY_STARTED')
            fields = [(key, self.config[key], key != 'tls_cert_file', 65536 if key.startswith('tls_') else 4096)
                      for key in ('dsn_file', 'tls_cert_file', 'tls_key_file', 'billing_token_file',
                                  'admin_read_token_file', 'admin_write_token_file')]
            for node in self.nodes:
                fields += [(node['id'] + ':' + key, node[key], key == 'client_key_file', 1024 * 1024)
                           for key in ('ca_file', 'client_cert_file', 'client_key_file')]
            materials = [{'label': label, 'path': path, 'sha256': digest(self.i.protected_read(path, maximum, private))}
                         for label, path, private, maximum in sorted(fields)]
            self.fresh_identity()
            self.write(directory / 'export-started.json', {
                'schema': 1, 'controller_id': self.id, 'operation_id': operation,
                'plan_sha256': digest(self.i.protected_read(str(directory / 'plan.json'), 256 * 1024)),
                'materials': materials})
            result = self.i.strict_json(run([str(self.binary), 'migration-export', '-config', str(CONFIG),
                                            '-operation', operation], 1860))
            require(set(result) == {'schema', 'controller_id', 'operation_id', 'archive_sha256', 'archive_bytes',
                                    'database_rows', 'source_readonly', 'source_isolated', 'migration_ready'} and
                    result.get('schema') == 1 and result.get('controller_id') == self.id and
                    result.get('operation_id') == operation and result.get('source_readonly') is True and
                    result.get('source_isolated') is False and result.get('migration_ready') is False and
                    type(result.get('database_rows')) is int and result['database_rows'] >= 0 and
                    type(result.get('archive_bytes')) is int and 0 < result['archive_bytes'] <= (8 << 30) + (64 << 20) and
                    isinstance(result.get('archive_sha256'), str) and SHA.fullmatch(result['archive_sha256']),
                    'EXPORT_RECEIPT_INVALID')
            self.fresh_identity()
            require(self.status(operation)['source_isolated'] is True, 'SOURCE_ISOLATION_CHANGED_DURING_EXPORT')
            result['source_isolated'] = True
            self.write(directory / 'exported.json', result)
            return result

    def restored_units(self, operation, units):
        self.fresh_identity()
        for unit in units:
            target, _ = self.paths(operation, unit)
            if unit['original_inode'] is not None:
                require(inode(target, 'unit') == unit['original_inode'], 'RESTORED_UNIT_CHANGED')
            else:
                require(not target.exists() and not target.is_symlink(), 'RESTORED_INSTANCE_CHANGED')
            require(digest(self.i.protected_read(unit['fragment'], 16384, False)) == unit['sha256'], 'RESTORED_FRAGMENT_CHANGED')


class Target(Host):
    """Seal an inert target and explicitly provision its dedicated database."""
    def __init__(self, installer, operation):
        self.i = installer
        installer.check_target()
        self.operation = operation
        self.root = Path('/var/lib/aster-controller-restore') / operation
        for path in (self.root.parent, self.root):
            installer.protected_path(str(path), directory=True, private=True)
            require(stat.S_IMODE(path.stat().st_mode) == 0o700, 'TARGET_DIRECTORY_NOT_PRIVATE')
        verify_installation(self, installer, target=True)
        require(Path(__file__).resolve() == self.version_dir / 'templates/host-management/controller-migration.py' and
                Path(installer.__file__).resolve() == self.version_dir / 'templates/host-management/install.py',
                'TARGET_INSTALLED_COORDINATOR_REQUIRED')
        for name in ('install.py', 'controller-migration.py', 'provision.py'):
            require((self.version_dir / 'templates/host-management' / name).is_file(), 'TARGET_PROVISION_MODULE_MISSING')
        caps = installer.strict_json(run([str(self.binary), 'migration-capabilities'], 10))
        require(caps.get('target_preparation_seal') is True, 'TARGET_SEAL_NOT_SUPPORTED')

    @contextlib.contextmanager
    def installation_lock(self):
        path = INSTALL_STATE.parent / 'install.lock'
        self.i.protected_path(str(path), private=True)
        fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            st = os.fstat(fd)
            require(st.st_uid == 0 and st.st_nlink == 1 and stat.S_ISREG(st.st_mode) and
                    stat.S_IMODE(st.st_mode) == 0o600, 'TARGET_INSTALL_LOCK_UNSAFE')
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise Refused('TARGET_INSTALLATION_BUSY') from None
            yield
        finally:
            os.close(fd)

    def unused_host(self):
        require(set(p.name for p in self.root.iterdir()) <=
                {'request.json', 'backup.age', 'recovery.key', 'plan.json', 'target.lock', 'database-plan.json', 'database'}, 'TARGET_INPUT_INVENTORY_CHANGED')
        # A killed verification may leave private plaintext. Never silently
        # discard/reuse it, or turn an unreviewed partial run into success.
        require(not CONFIG.parent.exists() and not CONFIG.parent.is_symlink(), 'TARGET_CONFIGURATION_ALREADY_EXISTS')
        for base in ('/etc/systemd/system', '/run/systemd/system', '/usr/lib/systemd/system', '/lib/systemd/system'):
            for pattern in ('aster-controller*', 'controller-aster*', 'controller-heartbeat*'):
                require(not list(Path(base).glob(pattern)), 'TARGET_CONTROLLER_UNIT_ALREADY_EXISTS')
        require(not run(['/usr/bin/systemctl', 'list-units', '--all', '--no-pager', '--no-legend',
                         'aster-controller*', 'controller-aster*', 'controller-heartbeat*'], 30).strip(),
                'TARGET_FOREIGN_SYSTEMD_UNIT')
        # systemd 249/255 list-unit-files returns -ENOENT for zero matches.
        # Do NOT accept an arbitrary nonzero command as proof of an empty host.
        # Include the standard journald unit as a positive query control, require
        # exit zero, and accept exactly that one name, never a controller unit.
        inventory = run(['/usr/bin/systemctl', 'list-unit-files', '--full', '--no-pager', '--no-legend',
                         'systemd-journald.service', 'aster-controller*', 'controller-aster*',
                         'controller-heartbeat*'], 30).decode('utf-8').splitlines()
        require(len(inventory) == 1 and 2 <= len(inventory[0].split()) <= 3 and
                inventory[0].split()[0] == 'systemd-journald.service', 'TARGET_FOREIGN_SYSTEMD_UNIT')
        # No kill/stop action: an unidentified old controller must be diagnosed,
        # never adopted or stopped by a target preparation request.
        for process in Path('/proc').iterdir():
            if not process.name.isdigit():
                continue
            try:
                executable = os.readlink(process / 'exe')
            except FileNotFoundError:
                continue
            require(not Path(executable).name.startswith('aster-controller'), 'TARGET_CONTROLLER_PROCESS_PRESENT')

    def target_command(self, action):
        return self.i.strict_json(run([str(self.binary), 'migration-target-' + action,
                                       '-operation', self.operation], 1860, confirmed_errors=True))

    def prepare_database(self, action):
        # Full records and embedded migration checks precede directory creation,
        # APT, credentials, SQL and even the data-stage start journal.
        plan = self.target_command('database-plan')
        require(plan.get('schema') == 1 and plan.get('protocol') == 'aster.controller-target-database/1' and
                plan.get('operation_id') == self.operation, 'TARGET_DATABASE_PLAN_UNCONFIRMED')
        if action == 'target-database-plan':
            return {'schema': 1, 'plan': plan, 'readonly': True, 'database_provisioned': False,
                    'database_restored': False, 'target_restore_approved': False, 'migration_ready': False}
        if action in ('target-restore', 'target-data-status'):
            return self.restore_database(action, plan)
        path = self.root / 'database-plan.json'
        if path.exists() or path.is_symlink():
            require(self.read(path) == plan, 'TARGET_DATABASE_PLAN_CHANGED')
        else:
            self.write(path, plan)
        directory = self.root / 'database'
        if directory.exists() or directory.is_symlink():
            self.i.protected_path(str(directory), directory=True, private=True)
            require(stat.S_IMODE(directory.stat().st_mode) == 0o700, 'TARGET_DATABASE_DIRECTORY_UNSAFE')
        else:
            directory.mkdir(mode=0o700)
            sync_directory(self.root)
        require(not (directory / 'import-started.json').exists() and not (directory / 'import-started.json').is_symlink(),
                'TARGET_IMPORT_ALREADY_STARTED_USE_DATA_STATUS')
        require(set(p.name for p in directory.iterdir()) <= {'dependencies.json', 'mysql-provision.json',
                'restore-provision.json', 'runtime-mysql-dsn', 'migration-mysql-dsn', 'mysql-client-home'},
                'TARGET_DATABASE_INVENTORY_CHANGED')
        # Only the manifest-checked sibling bundled with this installation.
        module = self.i.provisioning_module()
        stage = 'TARGET_DEPENDENCIES_UNCONFIRMED'
        try:
            module.install_dependencies('controller', directory, with_mysql=True, resume=(directory / 'dependencies.json').exists())
            self.unused_host()
            require(self.target_command('database-plan') == plan, 'TARGET_DATABASE_PLAN_CHANGED')
            stage = 'TARGET_MYSQL_START_UNCONFIRMED'
            module.start_owned_mysql(directory)
            stage = 'TARGET_DATABASE_CREATE_UNCONFIRMED'
            module.provision_restore_mysql(self.operation, plan['data']['charset'], plan['data']['collation'],
                                           resume=(directory / 'restore-provision.json').exists())
            self.unused_host()
            require(self.target_command('database-plan') == plan, 'TARGET_DATABASE_PLAN_CHANGED')
            stage = 'TARGET_DATABASE_INVENTORY_UNCONFIRMED'
            module.verify_restore_mysql(self.operation, plan['data']['charset'], plan['data']['collation'])
            proof = self.target_command('provision-check')
            require(proof == {'database_provisioned': True, 'target_credentials_verified': True,
                              'database_restored': False, 'target_restore_approved': False, 'migration_ready': False},
                    'TARGET_PROVISION_UNCONFIRMED')
            return proof
        except module.ProvisionError as error:
            # Never leak DSNs, arbitrary database errors or output. Preserve
            # journals/partial installation; explicit same operation may resume.
            if error.code and (error.code.startswith('APT_') or error.code == 'TARGET_RESTORE_SERVER_INVENTORY_REJECTED'):
                raise Refused(error.code) from None
            raise Refused(stage) from None

    def restore_database(self, action, plan):
        require(self.read(self.root / 'database-plan.json') == plan, 'TARGET_DATABASE_PLAN_CHANGED')
        directory = self.root / 'database'
        self.i.protected_path(str(directory), directory=True, private=True)
        require(stat.S_IMODE(directory.stat().st_mode) == 0o700, 'TARGET_DATABASE_DIRECTORY_UNSAFE')
        allowed = {'dependencies.json', 'mysql-provision.json', 'restore-provision.json', 'runtime-mysql-dsn',
                   'migration-mysql-dsn', 'mysql-client-home', 'import-approval.json', 'import-started.json', 'structure.json'}
        require(set(p.name for p in directory.iterdir()) <= allowed, 'TARGET_DATABASE_INVENTORY_CHANGED')
        module = self.i.provisioning_module()
        try:
            started = directory / 'import-started.json'
            readonly = started.exists() or started.is_symlink()
            require(readonly or action == 'target-restore', 'TARGET_IMPORT_NOT_STARTED')
            module.verify_restore_mysql(self.operation, plan['data']['charset'], plan['data']['collation'], restored=readonly)
            proof = self.target_command('provision-check')
            require(proof.get('target_credentials_verified') is True, 'TARGET_PROVISION_UNCONFIRMED')
            approval = {'schema': 1, 'plan': plan,
                        'ownership_sha256': digest(self.i.protected_read(str(directory / 'mysql-provision.json'), 65536))}
            approval_path = directory / 'import-approval.json'
            if approval_path.exists() or approval_path.is_symlink():
                require(self.read(approval_path) == approval, 'TARGET_IMPORT_APPROVAL_CHANGED')
            else:
                require(not readonly, 'TARGET_IMPORT_APPROVAL_MISSING')
                self.write(approval_path, approval)
            if not readonly:
                self.target_command('import')
            # No INSERT/DDL on reentry. Even a saved success flag would not be
            # evidence: root inventory and every authenticated byte are reread.
            self.unused_host()
            module.verify_restore_mysql(self.operation, plan['data']['charset'], plan['data']['collation'], restored=True)
            result = self.target_command('data-status')
            data = result.get('data', {})
            require(result.get('schema') == 1 and result.get('operation_id') == self.operation and
                    result.get('database_restored') is True and result.get('read_only_verification') is True and
                    result.get('target_restore_approved') is False and result.get('migration_ready') is False and
                    data.get('tables') == 34 and data.get('rows') == plan['data']['rows'] and
                    all(data.get(k) is True for k in ('exact_rows_verified', 'declared_constraints_verified', 'provisioning_marker_preserved')) and
                    data.get('target_activation_approved') is False and data.get('migration_ready') is False,
                    'TARGET_IMPORTED_DATA_UNCONFIRMED')
            return {**result, 'root_inventory_verified': True}
        except module.ProvisionError:
            raise Refused('TARGET_RESTORE_INVENTORY_UNCONFIRMED') from None

    def prepare(self, action):
        with self.installation_lock():
            verify_installation(self, self.i, target=True)
            self.unused_host()
            plan = self.target_command('plan')
            require(plan.get('schema') == 1 and plan.get('protocol') == 'aster.controller-target/1' and
                    plan.get('operation_id') == self.operation, 'TARGET_PLAN_UNCONFIRMED')
            if action == 'target-plan':
                return {'schema': 1, 'protocol': PROTOCOL, 'plan': plan, 'readonly': True,
                        'database_restored': False, 'target_restore_approved': False, 'migration_ready': False}
            with self.lock('target.lock'):
                path = self.root / 'plan.json'
                if path.exists() or path.is_symlink():
                    require(self.read(path) == plan, 'TARGET_IMMUTABLE_PLAN_CHANGED')
                else:
                    require(action == 'target-seal', 'TARGET_PLAN_NOT_SEALED')
                    self.write(path, plan)
                self.unused_host()
                result = self.target_command('seal' if action == 'target-seal' else 'status')
                require(result.get('schema') == 1 and result.get('controller_id') == plan['controller_id'] and
                        result.get('operation_id') == self.operation and result.get('phase') == 'target-sealed' and
                        result.get('admission_blocked') is True and result.get('guarded_processes_drained') is True and
                        result.get('source_isolated') is False and result.get('migration_ready') is False,
                        'TARGET_SEAL_UNCONFIRMED')
                if action in ('target-database-plan', 'target-provision', 'target-restore', 'target-data-status'):
                    return self.prepare_database(action)
                return {**result, 'database_restored': False, 'target_restore_approved': False}


class Arguments(argparse.ArgumentParser):
    def error(self, message):
        raise Refused('INVALID_MIGRATION_ARGUMENTS')


def main():
    parser = Arguments(description=__doc__)
    parser.add_argument('action', choices=('capabilities', 'plan', 'isolate', 'status', 'resume-source', 'export', 'target-plan', 'target-seal', 'target-status', 'target-database-plan', 'target-provision', 'target-restore', 'target-data-status'))
    parser.add_argument('--operation')
    args = parser.parse_args()
    require((args.action in ('capabilities', 'plan') and args.operation is None) or
            (args.action not in ('capabilities', 'plan') and isinstance(args.operation, str) and OP.fullmatch(args.operation)),
            'EXACT_OPERATION_ID_REQUIRED')
    if args.action == 'capabilities':
        return {'schema': 1, 'protocol': PROTOCOL, 'actions': ['plan', 'isolate', 'status', 'resume-source', 'export', 'target-plan', 'target-seal', 'target-status', 'target-database-plan', 'target-provision', 'target-restore', 'target-data-status'],
                'export_restore': False, 'migration_ready': False}
    if args.action.startswith('target-'):
        return Target(install_module(), args.operation).prepare(args.action)
    host = Host(install_module())
    if args.action == 'plan':
        plan = host.plan()
        return {'schema': 1, 'protocol': PROTOCOL, 'controller_id': host.id, 'source_commit': host.identity['source_commit'],
                'units': [u['name'] for u in plan['units']], 'readonly': True, 'source_isolated': False,
                'migration_ready': False, 'vm_actions_performed': False}
    if args.action == 'isolate':
        return host.isolate(args.operation)
    if args.action == 'status':
        return host.status(args.operation)
    if args.action == 'export':
        return host.export(args.operation)
    return host.resume(args.operation)


if __name__ == '__main__':
    try:
        print(json.dumps(main(), sort_keys=True))
    except Exception as error:
        print(json.dumps({'error': str(error) if isinstance(error, Refused) else 'HOST_MIGRATION_UNCONFIRMED'}), file=sys.stderr)
        raise SystemExit(1)
