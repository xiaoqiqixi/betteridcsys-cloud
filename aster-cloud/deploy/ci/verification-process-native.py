#!/usr/bin/env python3
"""Disposable Linux root/non-root HTTPS + real minimum-SQL process acceptance.

Only called inside the owned TCG restore guest. These scenarios exercise the
installed root launcher and systemd management; source-host export, successful
staff login and browser/UI are NOT certified by these process checks.
"""
import base64
import ctypes
from datetime import datetime, timedelta, timezone
import errno
import fcntl
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import ssl
import subprocess
import time


FAILURE_CODES = set('VERIFICATION_HOST_GUARD VERIFICATION_HOST_EXECUTABLE VERIFICATION_LISTENER VERIFICATION_SPAWN VERIFICATION_HANDSHAKE VERIFICATION_EARLY_EXIT VERIFICATION_CHILD_AUTHORITY VERIFICATION_CHILD_IDENTITY VERIFICATION_CHILD_GUARD VERIFICATION_CHILD_BOOTSTRAP VERIFICATION_CHILD_LISTENER VERIFICATION_CHILD_SQL VERIFICATION_CHILD_RECHECK VERIFICATION_CHILD_SERVICE'.split())
SYSTEM_IDENTITY_FAILURES = set('TARGET_VERIFICATION_SYSTEM_APPROVAL_REQUIRED TARGET_VERIFICATION_SYSTEM_CREATE_UNCONFIRMED TARGET_VERIFICATION_SYSTEM_FOREIGN_IDENTITY TARGET_VERIFICATION_SYSTEM_HOME_PRESENT TARGET_VERIFICATION_SYSTEM_IDENTITY_BUSY TARGET_VERIFICATION_SYSTEM_IDENTITY_CHANGED TARGET_VERIFICATION_SYSTEM_IDENTITY_REJECTED TARGET_VERIFICATION_SYSTEM_INTENT_CHANGED TARGET_VERIFICATION_SYSTEM_LOOKUP_REJECTED TARGET_VERIFICATION_SYSTEM_LOOKUP_UNCONFIRMED TARGET_VERIFICATION_SYSTEM_NOT_PREPARED TARGET_VERIFICATION_SYSTEM_NSS_REJECTED TARGET_VERIFICATION_SYSTEM_PARTIAL_IDENTITY TARGET_VERIFICATION_SYSTEM_PHASE_CHANGED TARGET_VERIFICATION_SYSTEM_PROCESS_UNCONFIRMED'.split())

UNIT_FAILURES = set('TARGET_VERIFICATION_SERVICE_CONNECTIONS_NOT_DRAINED TARGET_VERIFICATION_SERVICE_UNCONFIRMED TARGET_VERIFICATION_UNIT_ALREADY_ACTIVE TARGET_VERIFICATION_UNIT_BINDING_CHANGED TARGET_VERIFICATION_UNIT_BYTES_CHANGED TARGET_VERIFICATION_UNIT_CGROUP_UNCONFIRMED TARGET_VERIFICATION_UNIT_FOREIGN TARGET_VERIFICATION_UNIT_INPUT_REJECTED TARGET_VERIFICATION_UNIT_MISSING TARGET_VERIFICATION_UNIT_NOT_OWNED TARGET_VERIFICATION_UNIT_PROCESS_UNCONFIRMED TARGET_VERIFICATION_UNIT_SETTINGS_CHANGED TARGET_VERIFICATION_UNIT_STATE_UNCONFIRMED TARGET_VERIFICATION_UNIT_STATE_UNSAFE'.split())

UNIT_FAILURES |= set('TARGET_VERIFICATION_UNIT_VERIFY_UNCONFIRMED TARGET_VERIFICATION_UNIT_RELOAD_UNCONFIRMED TARGET_VERIFICATION_UNIT_START_UNCONFIRMED TARGET_VERIFICATION_UNIT_STOP_UNCONFIRMED'.split())

def fixture_failure(raw):
    code = raw.decode('ascii', errors='replace').removesuffix('\n')
    return code if len(raw) <= 128 and code in FAILURE_CODES else 'TARGET_NATIVE_ASSERTION_FAILED'

def empty_ipv4_route_snapshot(raw):
    """Validate the kernel's public /proc/<pid>/net/route wire format."""
    # fib_route_seq_start returns NULL before emitting a header if there is no
    # RT_TABLE_MAIN. Both v5.15 and v6.8 use this behavior. Do not accept arbitrary
    # single-line text, whitespace, or a route row merely because it is one line.
    header = (b'Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT').ljust(127, b' ') + b'\n'
    return raw == b'' or raw == header


def accept_installed_handoff(inputs, operation, module, directory, version, expected_phase, require, progress):
    """Actual installed ELF + original approval + cleanup + private root channel.

    This scenario prepares and checks the real operation-owned system account.
    It certifies the root-to-service handoff, not a managed systemd lifecycle,
    source-host migration, successful staff login or browser appearance.
    """
    code = 'VERIFICATION_PROCESS_MANAGED_HANDOFF'
    require(os.geteuid() == 0, code)
    spec = importlib.util.spec_from_file_location('installed_migration_handoff',
        version/'templates/host-management/controller-migration.py')
    manager = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(manager)
    target = manager.Target(manager.install_module(), operation)
    def system_command(action):
        try:
            return target.prepare(action)
        except manager.Refused as error:
            require(False,str(error) if str(error) in SYSTEM_IDENTITY_FAILURES else code)
    binary = version/'bin/aster-controller'
    dbplan = target.read(inputs/'database-plan.json')
    arguments = (operation, expected_phase['plan_sha256'], dbplan['data']['charset'], dbplan['data']['collation'])
    phase = {k:v for k,v in expected_phase.items() if k != 'root_inventory_verified'}
    expected = {'schema':1,'operation_id':operation,'phase':phase,'credential_verified':True,
        'sql_identity_verified':True,'readonly':True,'service_started':False,'migration_ready':False}
    progress('target-verification-system-account')
    # Fixture-owned foreign name: preparation must refuse before creating its
    # journal or adopting the group. Cleanup never deletes an unexpected record.
    foreign = 'asterv-'+operation[:24]
    require(manager.system_account_lookup('group',foreign,missing=True) is None,code)
    manager.run(['/usr/sbin/groupadd','--system',foreign])
    foreign_record = manager.system_account_lookup('group',foreign)
    try:
        try:
            target.prepare('target-verification-system-prepare')
        except manager.Refused as error:
            require(str(error)=='TARGET_VERIFICATION_SYSTEM_FOREIGN_IDENTITY',code)
        else:
            require(False,code)
        require(manager.system_account_lookup('group',foreign)==foreign_record and
            not (inputs/'verification-system-started.json').exists() and
            not (inputs/'verification-system-account.json').exists(),code)
    finally:
        if manager.system_account_lookup('group',foreign)==foreign_record:
            manager.run(['/usr/sbin/groupdel',foreign])
    prepared = system_command('target-verification-system-prepare')
    require(set(prepared)=={'schema','operation_id','verification_plan_sha256','system_identity',
        'system_identity_verified','readonly','root_inventory_verified','service_started','migration_ready'} and
        prepared['schema']==1 and prepared['operation_id']==operation and
        prepared['verification_plan_sha256']==phase['plan_sha256'] and prepared['system_identity_verified'] is True and
        prepared['root_inventory_verified'] is True and prepared['readonly'] is False and
        prepared['service_started'] is False and prepared['migration_ready'] is False, code)
    system_identity = prepared['system_identity']
    require(set(system_identity)=={'name','uid','gid','receipt_sha256'} and
        system_identity['name']=='asterv-'+operation[:24] and
        type(system_identity['uid']) is int and type(system_identity['gid']) is int and
        100 <= system_identity['uid'] <= 999 and 100 <= system_identity['gid'] <= 999, code)
    require(system_command('target-verification-system-prepare')==prepared and
        system_command('target-verification-system-status')=={**prepared,'readonly':True},code)
    owned_receipts = {name:(inputs/name).read_bytes() for name in
        ('verification-system-started.json','verification-system-account.json')}
    # Modify only this fixture-owned, expired, locked account. /bin/false is
    # still noninteractive; status/prepare must refuse and must not repair it.
    manager.run(['/usr/sbin/usermod','--shell','/bin/false',system_identity['name']])
    drift = manager.system_account_lookup('passwd',system_identity['name'])
    try:
        for action in ('target-verification-system-prepare','target-verification-system-status'):
            try:
                target.prepare(action)
            except manager.Refused as error:
                require(str(error)=='TARGET_VERIFICATION_SYSTEM_IDENTITY_REJECTED',code)
            else:
                require(False,code)
            require(manager.system_account_lookup('passwd',system_identity['name'])==drift and
                all((inputs/name).read_bytes()==raw for name,raw in owned_receipts.items()),code)
    finally:
        manager.run(['/usr/sbin/usermod','--shell','/usr/sbin/nologin',system_identity['name']])
    require(system_command('target-verification-system-status')=={**prepared,'readonly':True},code)
    tls = ssl.create_default_context(cafile=str(inputs/'configuration-tls.crt'))
    tls.minimum_version = ssl.TLSVersion.TLSv1_2
    processes = []
    channels = []

    def start():
        parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        parent.settimeout(180)
        channels.append(parent)
        child_fd = child.fileno()
        def inherited_channel():
            # FD 3 is replaced only in the disposable child, never the parent.
            if child_fd != 3:
                os.dup2(child_fd, 3)
                os.close(child_fd)
            os.set_inheritable(3, True)
        try:
            process = subprocess.Popen([str(binary), 'migration-verification-coordinator'],
                pass_fds=tuple(sorted({3, child_fd})), preexec_fn=inherited_channel,
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                cwd='/', env={'PATH':'/usr/bin:/bin','LANG':'C'})
        finally:
            child.close()
        processes.append(process)
        nonce = os.urandom(32).hex()
        parent.sendall((json.dumps({'schema':1,'operation_id':operation,'nonce':nonce},
            separators=(',',':'))+'\n').encode())
        stream = parent.makefile('rb')
        channels.append(stream)
        return process, parent, stream, nonce

    def finish_refused(process, parent, stream, busy=False):
        stream.close()
        parent.close()
        stdout, stderr = process.communicate(timeout=20)
        require(process.returncode == 1 and not stdout and len(stderr) <= 4096, code)
        error = json.loads(stderr)
        require(set(error) == {'time','level','msg','component','code'} and
            error['code'] == ('CONTROLLER_MIGRATION_BUSY' if busy else 'COMMAND_FAILED') and
            error['component'] == 'controller' and error['level'] == 'ERROR', code)
        require(not list(inputs.glob('.restore-verify-*')), code)

    def proof_for(process, stream, nonce):
        raw = stream.readline((256 << 10) + 2)
        require(raw.endswith(b'\n') and len(raw) <= (256 << 10) + 1 and process.poll() is None, code)
        require(target.i.strict_json(raw) == {'schema':1,'nonce':nonce,'proof':expected}, code)
        # These are real root SQL and installed manifest checks, performed again
        # while Go holds the original target lock. No cached JSON permits start.
        require(module.complete_verification_mysql(*arguments, readonly=True) == account, code)
        manager.verify_installation(target, target.i, target=True)
        target.verify_verification_data(expected['phase'], target.read(inputs/'plan.json'), dbplan, readonly=True)
        require(target.system_identity(expected,readonly=True)==system_identity,code)
        require(len(list(inputs.glob('.restore-verify-*'))) == 1, code)
        return hashlib.sha256(raw).hexdigest()

    def ack(parent, nonce, digest, uid=None):
        parent.sendall((json.dumps({'schema':1,'nonce':nonce,'proof_sha256':digest,
            'uid':system_identity['uid'] if uid is None else uid,'gid':system_identity['gid']},
            separators=(',',':'))+'\n').encode())

    def request(path):
        with socket.create_connection(('127.0.0.1',9555), timeout=2) as raw:
            with tls.wrap_socket(raw, server_hostname='source.invalid') as connection:
                connection.sendall(('GET '+path+' HTTP/1.1\r\nHost: source.invalid:9555\r\nConnection: close\r\n\r\n').encode())
                response = http.client.HTTPResponse(connection)
                response.begin()
                body = response.read((5 << 20) + 1)
                require(len(body) <= (5 << 20), code)
                return response.status, body

    def stopped():
        # Do not count timeout or an arbitrary network error as closed admission.
        with socket.socket() as probe:
            probe.settimeout(1)
            require(probe.connect_ex(('127.0.0.1',9555)) == errno.ECONNREFUSED, code)
        deadline = time.monotonic()+10
        user = 'aster_v_'+operation[:23]
        while True:
            active = module.mysql_sql(directory,
                "SELECT COUNT(*) FROM performance_schema.threads WHERE PROCESSLIST_USER='"+user+"';\n")
            if active.strip() == b'0':
                return
            require(time.monotonic() < deadline, code)
            time.sleep(.1)

    with target.installation_lock(), target.lock('target.lock'):
        target.unused_host(configuration=True, verification=True)
        require(target.target_command('verification-runtime-check') == expected, code)
        account = module.complete_verification_mysql(*arguments, readonly=True)
        try:
            progress('target-verification-managed-handoff-refusal')
            for refusal in ('stale-proof', 'root-child'):
                process, parent, stream, nonce = start()
                digest = proof_for(process, stream, nonce)
                if refusal == 'stale-proof':
                    digest = '0'*64 if digest != '0'*64 else '1'*64
                ack(parent, nonce, digest, uid=0 if refusal == 'root-child' else None)
                require(stream.read(1) == b'', code)
                finish_refused(process, parent, stream)
                stopped()
                require(target.target_command('verification-runtime-check') == expected, code)

            progress('target-verification-managed-handoff-serving')
            process, parent, stream, nonce = start()
            ack(parent, nonce, proof_for(process, stream, nonce))
            deadline = time.monotonic()+20
            while True:
                require(process.poll() is None and time.monotonic() < deadline, code)
                try:
                    status, body = request('/')
                    break
                except (ConnectionRefusedError, TimeoutError):
                    time.sleep(.1)
            require(status == 200 and body == (version/'ui/index.html').read_bytes(), code)
            require(not list(inputs.glob('.restore-verify-*')), code)
            children = set()
            for task in (Path('/proc')/str(process.pid)/'task').iterdir():
                try:
                    children.update((task/'children').read_text().split())
                except FileNotFoundError:
                    continue
            require(len(children)==1 and all(value.isdigit() for value in children),code)
            child = Path('/proc')/children.pop()
            observed = 0
            for task in (child/'task').iterdir():
                try:
                    fields = dict(line.split(':',1) for line in (task/'status').read_text().splitlines() if ':' in line)
                except FileNotFoundError:
                    continue
                require(fields['Uid'].split()==[str(system_identity['uid'])]*4 and
                    fields['Gid'].split()==[str(system_identity['gid'])]*4 and not fields['Groups'].strip() and
                    fields['NoNewPrivs'].strip()=='1' and all(fields[key].strip()=='0000000000000000'
                    for key in ('CapInh','CapPrm','CapEff','CapAmb')),code)
                observed += 1
            require(observed>0,code)
            status, body = request('/console/v1/auth/me')
            require(status == 401 and isinstance(json.loads(body),dict), code)

            # A second coordinator must fail before asking for another approval,
            # even though its archive, original deadline and operation match.
            duplicate, other, other_stream, _ = start()
            require(other_stream.read(1) == b'', code)
            finish_refused(duplicate, other, other_stream, busy=True)
            require(request('/')[0] == 200, code)

            progress('target-verification-managed-handoff-stopped')
            stream.close()
            parent.close()
            stdout, stderr = process.communicate(timeout=20)
            require(process.returncode == 0 and not stdout and not stderr, code)
            stopped()
            target.unused_host(configuration=True, verification=True)
            require(target.target_command('verification-runtime-check') == expected, code)
            require(module.complete_verification_mysql(*arguments, readonly=True) == account, code)
            require(target.system_identity(expected,readonly=True)==system_identity,code)
            require(not list(inputs.glob('.restore-verify-*')), code)
        finally:
            for channel in reversed(channels):
                channel.close()
            for process in processes:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=15)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=10)

    # Now exercise the PRODUCTION installed root manager. The native fixture
    # no longer supplies its approval response, UID/GID or SQL checks here.
    # This foreground lifecycle is still not systemd or a staff browser login.
    progress('target-verification-installed-manager')
    entry = version/'templates/host-management/controller-migration.py'
    process = subprocess.Popen(['/usr/bin/python3','-I',str(entry),
        'target-verification-serve','--operation',operation],stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,stderr=subprocess.PIPE,cwd='/',env=manager.ENV)
    try:
        deadline = time.monotonic()+240
        while True:
            require(process.poll() is None and time.monotonic()<deadline,code)
            try:
                status, body = request('/')
                break
            except (ConnectionRefusedError,TimeoutError):
                time.sleep(.1)
        require(status==200 and body==(version/'ui/index.html').read_bytes() and
            not list(inputs.glob('.restore-verify-*')),code)
        status, body = request('/console/v1/auth/me')
        require(status==401 and isinstance(json.loads(body),dict),code)
        duplicate = subprocess.run(['/usr/bin/python3','-I',str(entry),
            'target-verification-serve','--operation',operation],stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,cwd='/',env=manager.ENV,timeout=60)
        require(duplicate.returncode==1 and not duplicate.stdout and
            json.loads(duplicate.stderr)=={'error':'TARGET_INSTALLATION_BUSY'} and request('/')[0]==200,code)
        process.terminate()  # fixed managed SIGTERM, not a fake stop receipt
        stdout,stderr = process.communicate(timeout=90)
        require(process.returncode==0 and not stderr and json.loads(stdout)=={
            'schema':1,'operation_id':operation,'coordinator_exited':True,
            'system_identity_idle':True,'original_data_phase_verified':True,
            'sql_connections_drained':True,'root_inventory_verified':True,
            'target_remains_sealed':True,'service_started':False,'migration_ready':False},code)
        stopped()
        require(target.prepare('target-verification-runtime-check')=={**expected,'root_inventory_verified':True},code)
        require(system_command('target-verification-system-status')=={**prepared,'readonly':True},code)
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=60)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)

    progress('target-verification-installed-manager-parent-death')
    process = subprocess.Popen(['/usr/bin/python3','-I',str(entry),
        'target-verification-serve','--operation',operation],stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,stderr=subprocess.PIPE,cwd='/',env=manager.ENV)
    try:
        deadline = time.monotonic()+240
        while True:
            require(process.poll() is None and time.monotonic()<deadline,code)
            try:
                require(request('/')[0]==200,code)
                break
            except (ConnectionRefusedError,TimeoutError):
                time.sleep(.1)
        def child_ids(pid):
            result = set()
            for task in (Path('/proc')/str(pid)/'task').iterdir():
                try:
                    result.update((task/'children').read_text().split())
                except FileNotFoundError:
                    continue
            require(len(result)==1 and all(value.isdigit() for value in result),code)
            return result
        coordinators = child_ids(process.pid)
        descendants = coordinators | child_ids(next(iter(coordinators)))
        # Observe real numeric identities and kernel start times before killing
        # only OUR Popen parent. No pidfile or arbitrary cleanup target is used.
        identities = {pid:(Path('/proc')/pid/'stat').read_text().rsplit(')',1)[1].split()[19]
                      for pid in descendants}
        process.kill()
        stdout,stderr = process.communicate(timeout=10)
        require(process.returncode==-signal.SIGKILL and not stdout and not stderr,code)
        deadline = time.monotonic()+30
        while identities:
            for pid,started in list(identities.items()):
                try:
                    current = (Path('/proc')/pid/'stat').read_text().rsplit(')',1)[1].split()[19]
                except FileNotFoundError:
                    current = None
                if current!=started:
                    del identities[pid]
            require(not identities or time.monotonic()<deadline,code)
            if identities:
                time.sleep(.1)
        stopped()
        require(target.prepare('target-verification-runtime-check')=={**expected,'root_inventory_verified':True} and
            system_command('target-verification-system-status')=={**prepared,'readonly':True},code)
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=60)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)

    progress('target-verification-systemd-lifecycle')
    def unit_command(action):
        result = subprocess.run(['/usr/bin/python3','-I',str(entry),action,'--operation',operation],
            stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
            cwd='/',env=manager.ENV,timeout=360)
        if result.returncode:
            # Never export private raw stderr. Only our fixed product errors
            # may leave this isolated guest for diagnosis.
            try:
                failure = json.loads(result.stderr)
                selected = failure.get('error') if isinstance(failure,dict) and set(failure)=={'error'} else ''
            except (ValueError,UnicodeError):
                selected = ''
            require(False,selected if selected in UNIT_FAILURES else code)
        require(not result.stderr and len(result.stdout)<=8192,code)
        return json.loads(result.stdout)
    name,unit,unit_state = target.verification_service_paths()
    require(not unit.exists() and not unit_state.exists(),code)
    foreign_unit = b'[Unit]\nDescription=Fixture owned foreign verification unit\n[Service]\nExecStart=/bin/false\n'
    target.i.write_new(unit,foreign_unit,0o644)
    try:
        result = subprocess.run(['/usr/bin/python3','-I',str(entry),'target-verification-start','--operation',operation],
            stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
            cwd='/',env=manager.ENV,timeout=180)
        require(result.returncode==1 and not result.stdout and
            json.loads(result.stderr)=={'error':'TARGET_VERIFICATION_UNIT_NOT_OWNED'} and
            unit.read_bytes()==foreign_unit and not unit_state.exists(),code)
    finally:
        if unit.read_bytes()==foreign_unit:
            unit.unlink()
            manager.run(['/usr/bin/systemctl','daemon-reload'])
    def wait_unit_http():
        deadline = time.monotonic()+240
        while True:
            state = unit_command('target-verification-service-status')
            require(state['unit_state'] in ('active','activating') and time.monotonic()<deadline,code)
            try:
                status,body = request('/')
                require(status==200 and body==(version/'ui/index.html').read_bytes(),code)
                require(request('/console/v1/auth/me')[0]==401,code)
                return state
            except (ConnectionRefusedError,TimeoutError):
                time.sleep(.2)
    try:
        start = unit_command('target-verification-start')
        require(start=={'schema':1,'operation_id':operation,'unit':name,'start_requested':True,
            'unit_state':start['unit_state'],'http_readiness_verified':False,'migration_ready':False},code)
        state = wait_unit_http()
        require(state['main_pid']>0 and state['readonly'] is True and
            state['http_readiness_verified'] is False and state['migration_ready'] is False,code)
        original_unit,original_receipt = unit.read_bytes(),(unit_state/'unit.json').read_bytes()
        stopped_report = unit_command('target-verification-stop')
        expected_stopped = {'schema':1,'operation_id':operation,'unit_stopped':True,'processes_drained':True,
            'sql_connections_drained':True,'original_data_phase_verified':True,'root_inventory_verified':True,
            'target_remains_sealed':True,'migration_ready':False}
        require(stopped_report==expected_stopped,code)
        stopped()
        require(unit_command('target-verification-service-status')['unit_state']=='inactive' and
            unit.read_bytes()==original_unit and (unit_state/'unit.json').read_bytes()==original_receipt,code)
        # Owned stopped fixture only: status must reject drift without repairing
        # or running the changed unit. Restore exact bytes before any new start.
        changed = original_unit.replace(b'Restart=no\n',b'Restart=always\n')
        unit.write_bytes(changed)
        try:
            result = subprocess.run(['/usr/bin/python3','-I',str(entry),'target-verification-service-status',
                '--operation',operation],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                cwd='/',env=manager.ENV,timeout=60)
            require(result.returncode==1 and not result.stdout and
                json.loads(result.stderr)=={'error':'TARGET_VERIFICATION_UNIT_BYTES_CHANGED'} and
                unit.read_bytes()==changed and (unit_state/'unit.json').read_bytes()==original_receipt,code)
        finally:
            unit.write_bytes(original_unit)
            manager.run(['/usr/bin/systemctl','daemon-reload'])
        # An explicit same-operation start reauthenticates all inputs, retaining
        # the original deadline and runtime receipt. No restart policy is used.
        require(unit_command('target-verification-start')['start_requested'] is True,code)
        wait_unit_http()
        manager.run(['/usr/bin/systemctl','kill','--kill-who=main','--signal=KILL','--',name])
        deadline = time.monotonic()+30
        while True:
            state = unit_command('target-verification-service-status')
            if state['main_pid']==0 and state['unit_state']=='failed':
                break
            require(time.monotonic()<deadline,code)
            time.sleep(.2)
        stopped()
        require((unit_state/'unit.json').read_bytes()==original_receipt and
            unit_command('target-verification-stop')==expected_stopped,code)
        require(target.prepare('target-verification-runtime-check')=={**expected,'root_inventory_verified':True},code)
    finally:
        # Clean up only through the product ownership/identity checks. Unknown
        # unit drift is a hard failure, never a license to stop another service.
        if unit_state.exists():
            unit_command('target-verification-stop')

def accept(root, inputs, controller, operation, module, directory, ui_directory, require, progress):
    require(os.geteuid() == 0)
    require(ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) == 0)
    case = Path('/opt') / ('aster-verification-native-' + operation)
    case.mkdir(mode=0o755)
    case.chmod(0o755)  # public test ELF only; independent of the guest umask
    binary = case/'fixture'
    shutil.copyfile(root/'verification-process.test', binary)
    binary.chmod(0o755)
    plan = json.loads((inputs/'plan.json').read_text())
    dbplan = json.loads((inputs/'database-plan.json').read_text())
    phase = json.loads((inputs/'verification-data-approval.json').read_text())
    original_end = datetime.fromisoformat(phase['expires_at'].replace('Z', '+00:00'))
    configuration = json.loads(Path('/etc/aster-controller/config.json').read_text())
    require(configuration['controller_id'] == controller and configuration['listen'] == '127.0.0.1:9555')
    cfg = dict(controller=configuration, operation=operation, origin='https://source.invalid:9555',
        expires_at=phase['expires_at'], uid=65532, gid=65532,
        dsn=(directory/'verification-mysql-dsn').read_text().removesuffix('\n'),
        certificate_pem=base64.b64encode((inputs/'configuration-tls.crt').read_bytes()).decode(),
        private_key_pem=base64.b64encode((inputs/'configuration-tls.key').read_bytes()).decode(),
        ui_directory=str(ui_directory))
    cert = ssl.create_default_context(cafile=str(inputs/'configuration-tls.crt'))
    cert.minimum_version = ssl.TLSVersion.TLSv1_2
    state = Path('/var/lib/aster-controller')/controller
    original_seal = (state/'target-restore.json').read_bytes()
    vuser = 'aster_v_' + operation[:23]

    def probe_drained(expected):
        fd = os.open(state/'runtime.lock', os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                drained = True
            except BlockingIOError:
                drained = False
            require(drained == expected, "VERIFICATION_PROCESS_GUARD_LOCK")
        finally:
            os.close(fd)
        require((state/'target-restore.json').read_bytes() == original_seal, 'VERIFICATION_PROCESS_TARGET_SEAL')

    def request_bytes(method, path):
        with socket.create_connection(('127.0.0.1', 9555), timeout=2) as raw:
            with cert.wrap_socket(raw, server_hostname='source.invalid') as tls:
                tls.sendall((method+' '+path+' HTTP/1.1\r\nHost: source.invalid:9555\r\nConnection: close\r\nContent-Length: 0\r\n\r\n').encode())
                response = http.client.HTTPResponse(tls)
                response.begin()
                payload = response.read((5 << 20) + 1)
                require(len(payload) <= (5 << 20), 'VERIFICATION_PROCESS_STATIC_UI')
                return response.status, {name.lower(): value for name, value in response.getheaders()}, payload

    def request(method, path):
        status, _, payload = request_bytes(method, path)
        require(len(payload) <= 65536)
        return status, json.loads(payload)

    def static_ui():
        # Installed, manifest-bound root-owned fixture assets, not a mocked
        # handler. This proves transport/file isolation, not visual acceptance.
        for path, filename in (('/', 'index.html'), ('/index.html', 'index.html'),
                               ('/assets/native.js', 'assets/native.js'), ('/assets/native.css', 'assets/native.css')):
            status, headers, payload = request_bytes('GET', path)
            require(status == 200 and payload == (ui_directory/filename).read_bytes(), 'VERIFICATION_PROCESS_STATIC_UI')
            require(headers.get('cache-control') == 'no-store' and headers.get('x-content-type-options') == 'nosniff',
                    'VERIFICATION_PROCESS_STATIC_UI')
            csp = headers.get('content-security-policy', '')
            require(all(value in csp for value in ("script-src 'self'", "connect-src 'self'", "frame-ancestors 'none'")),
                    'VERIFICATION_PROCESS_STATIC_UI')
        status, headers, payload = request_bytes('HEAD', '/assets/native.js')
        require(status == 200 and not payload and headers.get('etag'), 'VERIFICATION_PROCESS_STATIC_UI')
        for path in ('/console', '/v1', '/api/unknown', '/console/v1/unknown', '/v1/unknown',
                     '/console%2fv1/auth/me', '/assets/%6eative.js', '/?', '/assets/native.js?cache=1'):
            status, _, payload = request_bytes('GET', path)
            require(status == 403 and json.loads(payload).get('error', {}).get('code') == 'MIGRATION_VERIFICATION_READ_ONLY',
                    'VERIFICATION_PROCESS_STATIC_UI')
        for path in ('/assets/native.js.map', '/assets/private.json', '/assets/../index.html', '/assets//native.js'):
            status, _, payload = request_bytes('GET', path)
            require(status == 404 and b'PRIVATE_' not in payload, 'VERIFICATION_PROCESS_STATIC_UI')
        for method in ('POST', 'PUT', 'PATCH', 'DELETE'):
            status, body = request(method, '/assets/native.js')
            require(status == 403 and body.get('error', {}).get('code') == 'MIGRATION_VERIFICATION_READ_ONLY',
                    'VERIFICATION_PROCESS_STATIC_UI')
        # An asset becoming writable after startup must fail closed, not remain
        # available from a process cache. Restore only this injected mode fault.
        asset = ui_directory/'assets/native.js'
        try:
            asset.chmod(0o666)
            status, _, payload = request_bytes('GET', '/assets/native.js')
            require(status == 404 and b'nativeStaticFixture' not in payload, 'VERIFICATION_PROCESS_STATIC_UI')
        finally:
            asset.chmod(0o644)
        status, _, payload = request_bytes('GET', '/assets/native.js')
        require(status == 200 and payload == asset.read_bytes(), 'VERIFICATION_PROCESS_STATIC_UI')

    def child_of(parent):
        children = set()
        for task in (Path('/proc')/str(parent.pid)/'task').iterdir():
            try:
                children.update(map(int, (task/'children').read_text().split()))
            except FileNotFoundError:
                pass
        require(len(children) == 1, "VERIFICATION_PROCESS_CHILD_SET")
        child = children.pop()
        require(child > 1, "VERIFICATION_PROCESS_CHILD_SET")
        return child

    def restricted(child, parent):
        p = Path('/proc')/str(child)
        require((p/'ns/net').stat().st_ino != (Path('/proc')/str(parent.pid)/'ns/net').stat().st_ino, 'VERIFICATION_PROCESS_NAMESPACE')
        require((p/'cmdline').read_bytes().split(b'\0') == [str(binary).encode(), b'migration-verification-child', b''], 'VERIFICATION_PROCESS_COMMAND')
        require(set((p/'environ').read_bytes().split(b'\0')) == {b'PATH=/usr/bin:/bin', b'LANG=C', b''}, 'VERIFICATION_PROCESS_ENVIRONMENT')
        with (p/'net/route').open('rb') as stream:
            routes = stream.read(129)
        require(empty_ipv4_route_snapshot(routes), "VERIFICATION_PROCESS_NETWORK_ROUTES")
        # Independently query every IPv4 table through rtnetlink in the observed
        # child's namespace. Empty /proc bytes alone are not isolation proof.
        # This fixed read-only command neither creates a namespace nor adds a
        # link/route, and never queries a destination or publishes addresses.
        actual = subprocess.run(['/usr/bin/nsenter', '--target', str(child), '--net', '--',
                                 '/usr/sbin/ip', '-j', '-4', 'route', 'show', 'table', 'all'],
                                env={'PATH':'/usr/bin:/bin', 'LANG':'C'},
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
        require(actual.returncode == 0 and not actual.stderr and len(actual.stdout) <= 65536,
                'VERIFICATION_PROCESS_NETWORK_ROUTES')
        try:
            tables = json.loads(actual.stdout)
        except (ValueError, UnicodeError):
            require(False, 'VERIFICATION_PROCESS_NETWORK_ROUTES')
        require(tables == [], 'VERIFICATION_PROCESS_NETWORK_ROUTES')
        progress('target-verification-routes-empty-file' if routes == b'' else 'target-verification-routes-header-only')
        seen = 0
        for task in (p/'task').iterdir():
            try:
                fields = dict(line.split(':', 1) for line in (task/'status').read_text().splitlines() if ':' in line)
            except FileNotFoundError:
                continue
            seen += 1
            require(fields['NoNewPrivs'].strip() == '1' and not fields['Groups'].strip(), 'VERIFICATION_PROCESS_THREAD_PRIVILEGES')
            for key in ('CapInh', 'CapPrm', 'CapEff', 'CapAmb'):
                require(fields[key].strip() == '0000000000000000', 'VERIFICATION_PROCESS_THREAD_CAPABILITIES')
            for key in ('Uid', 'Gid'):
                require(fields[key].split() == ['65532']*4, 'VERIFICATION_PROCESS_THREAD_CREDENTIALS')
        require(seen > 0, "VERIFICATION_PROCESS_THREADS_MISSING")
        inode = (state/'runtime.lock').stat().st_ino
        inherited = 0
        for descriptor in (p/'fd').iterdir():
            try:
                inherited += descriptor.stat().st_ino == inode and descriptor.stat().st_dev == (state/'runtime.lock').stat().st_dev
            except FileNotFoundError:
                pass
        require(inherited == 1, "VERIFICATION_PROCESS_GUARD_COUNT")

    def sql_drained():
        deadline = time.monotonic()+10
        while True:
            raw = module.mysql_sql(directory, "SELECT COUNT(*) FROM performance_schema.threads WHERE PROCESSLIST_USER='"+vuser+"';\n")
            if raw.strip() == b'0':
                return
            require(time.monotonic() < deadline)
            time.sleep(.1)

    def require_parent_running(parent):
        if parent.poll() is None:
            return
        # This is fixed fixture output, never the child's private stderr/SQL.
        raw = parent.stdout.read(129)
        require(False, fixture_failure(raw))

    def run_case(mode):
        parent, child = None, None
        input_created = False
        path = root/('verification-process-'+mode+'.json')
        value = dict(cfg)
        if mode == 'expiry':
            end = datetime.now(timezone.utc)+timedelta(seconds=15)
            require(end < original_end)
            value['expires_at'] = end.isoformat().replace('+00:00', 'Z')
        if mode == 'bad-credential':
            value['dsn'] = vuser+':wrong-password-value-not-a-secret@unix(/run/mysqld/mysqld.sock)/aster_cloud_restore_'+operation
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            input_created = True
            with os.fdopen(fd, 'w') as f:
                json.dump({'config':value, 'configuration_sha':plan['canonical_configuration_sha256'],
                    'plan_sha':dbplan['target_plan_sha256']}, f)
            parent = subprocess.Popen([str(binary), 'native-process-fixture', str(path)],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env={'PATH':'/usr/bin:/bin', 'LANG':'C'})
            if mode == 'bad-credential':
                # Keep stdin open: closing it would test cancellation, not actual
                # minimum-account authentication rejection.
                require(parent.wait(timeout=20) == 27)
                out, err = parent.communicate()
                require(out == b'VERIFICATION_CHILD_SQL\n' and not err, fixture_failure(out))
                probe_drained(True); sql_drained()
                return
            deadline = time.monotonic()+12
            while True:
                require_parent_running(parent)
                try:
                    code, body = request('GET', '/console/v1/auth/me')
                    require(code == 401)
                    break
                except (OSError, http.client.HTTPException):
                    require(time.monotonic() < deadline)
                    time.sleep(.1)
            progress('target-verification-process-identity')
            child = child_of(parent)
            restricted(child, parent)
            probe_drained(False)
            if mode == 'stop':
                progress('target-verification-process-static-ui')
                static_ui()
            progress('target-verification-process-write-denied')
            code, body = request('POST', '/console/v1/users')
            require(code == 403 and body.get('error', {}).get('code') == 'MIGRATION_VERIFICATION_READ_ONLY')
            progress('target-verification-process-'+mode+'-drain')
            if mode == 'stop':
                parent.stdin.write(b'stop\n'); parent.stdin.flush()
            elif mode == 'parent-death':
                parent.kill()  # this exact Popen child, never an imported PID
            code = parent.wait(timeout=25)
            require(code == (-9 if mode == 'parent-death' else 0))
            if mode == 'parent-death':
                deadline = time.monotonic()+10
                while True:
                    pid, status = os.waitpid(child, os.WNOHANG)
                    if pid == child:
                        require(os.WIFSIGNALED(status) and os.WTERMSIG(status) == 9)
                        break
                    require(time.monotonic() < deadline)
                    time.sleep(.1)
            require(not (Path('/proc')/str(child)).exists())
            out, err = parent.communicate()
            require(not out and not err)
            probe_drained(True); sql_drained()
            try:
                connection = socket.create_connection(('127.0.0.1',9555), timeout=1)
            except OSError:
                connection = None
            if connection is not None:
                connection.close()
                require(False)
        finally:
            if parent is not None and parent.poll() is None:
                parent.kill(); parent.wait(timeout=10)
            # Any outstanding child is killed by the actual parent-death signal;
            # the owned guest is stopped on fixture failure, not reused.
            if input_created:
                path.unlink(missing_ok=True)
    try:
        for mode in ('bad-credential', 'stop', 'expiry', 'parent-death'):
            progress('target-verification-process-' + mode)
            run_case(mode)
    finally:
        binary.unlink(missing_ok=True)
        case.rmdir()
