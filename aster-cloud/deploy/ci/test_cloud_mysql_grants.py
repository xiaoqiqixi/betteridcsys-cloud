#!/usr/bin/env python3
"""Real SQL/privilege contract inside mysql-native.sh's owned private fixture.

Not a production installer, root-auth-socket test, APT/systemd operation or KVM
acceptance. No missing-fixture skip, host-client search or host-DB fallback.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import secrets
import stat
import subprocess
import sys
import tempfile

MAX_OUTPUT = 1024 * 1024
PREFIX = "aster_cloud_test_grants"
ACCOUNT_PREFIX = "aster_cg_"
DENIAL_CODES = {1044, 1045, 1142, 1143, 1227}


class ContractError(Exception):
    """Fixed nonsecret error code only; never forward SQL/client diagnostics."""


def require(condition, code):
    if not condition:
        raise ContractError(code)


def canonical(value):
    require(isinstance(value, str) and value and not any(ord(c) < 32 for c in value), "FIXTURE_PATH_INVALID")
    path = Path(value)
    require(path.is_absolute() and str(path) == value and ".." not in path.parts, "FIXTURE_PATH_INVALID")
    return path


def owned(path, uid, *, directory=False, private=False, socket=False, executable=False):
    info = path.lstat()
    require(info.st_uid == uid and not stat.S_ISLNK(info.st_mode), "FIXTURE_OWNERSHIP_INVALID")
    if socket:
        require(stat.S_ISSOCK(info.st_mode), "FIXTURE_SOCKET_INVALID")
    elif directory:
        require(stat.S_ISDIR(info.st_mode) and not info.st_mode & 0o022, "FIXTURE_DIRECTORY_INVALID")
    else:
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and not info.st_mode & 0o022, "FIXTURE_FILE_INVALID")
    if private:
        require(not info.st_mode & 0o077, "FIXTURE_PRIVATE_MODE_REQUIRED")
    if executable:
        require(bool(info.st_mode & 0o111), "FIXTURE_CLIENT_NOT_EXECUTABLE")
    return info


@dataclass(frozen=True)
class Fixture:
    root: Path
    mysql_root: Path
    socket: Path
    admin_cnf: Path
    client: Path
    admin_contents: bytes = field(default=b"", repr=False)


def validate_fixture(environment=None):
    """Read-only safety gate. Even a rejected invocation creates no scratch."""
    env = os.environ if environment is None else environment
    require(os.geteuid() != 0, "FIXTURE_MUST_BE_NONROOT")
    require(platform.system() == "Linux" and platform.machine() in ("x86_64", "amd64"), "FIXTURE_REQUIRES_LINUX_AMD64")
    keys = ("RUNNER_TEMP", "ASTER_NATIVE_MYSQL_ROOT", "ASTER_NATIVE_MYSQL_SOCKET", "ASTER_NATIVE_MYSQL_ADMIN_CNF", "ASTER_NATIVE_MYSQL_FIXTURE_ROOT")
    require(all(env.get(key) for key in keys), "FIXTURE_ENV_REQUIRED")
    parent, mysql_root, socket, admin, root = (canonical(env[key]) for key in keys)
    require(root.parent == parent and re.fullmatch(r"aster-mysql\.[A-Za-z0-9]{8}", root.name), "FIXTURE_ROOT_NOT_OWNED_NATIVE_CASE")
    require(mysql_root == root / "distribution/usr" and socket == root / "mysql.sock" and admin == root / "admin.cnf", "FIXTURE_PATHS_MUST_MATCH_NATIVE_LAYOUT")
    uid = os.geteuid()
    owned(parent, uid, directory=True, private=True)
    owned(root, uid, directory=True, private=True)
    require(parent.resolve(strict=True) == parent and root.resolve(strict=True) == root, "FIXTURE_SYMLINK_ANCESTRY_REJECTED")
    client, server = mysql_root / "bin/mysql", mysql_root / "sbin/mysqld"
    for target in (client, server, admin, root / "mysql.pid", root / "data", socket):
        require(target.is_relative_to(root), "FIXTURE_PATH_ESCAPES_CASE")
        for ancestor in reversed(target.parents):
            if ancestor == root or root in ancestor.parents:
                owned(ancestor, uid, directory=True)
        owned(target, uid, directory=target == root / "data", private=target == admin,
              socket=target == socket, executable=target in (client, server))
    require(admin.stat().st_size <= 4096, "FIXTURE_ADMIN_FILE_OVERSIZED")
    # The native wrapper creates this exact public fixture identity. Reject
    # arbitrary option-file hooks, remote hosts or production account inputs.
    fd = os.open(admin, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        require(info.st_uid == uid and info.st_nlink == 1 and stat.S_ISREG(info.st_mode) and not info.st_mode & 0o077 and info.st_size <= 4096, "FIXTURE_ADMIN_OPENED_INODE_REJECTED")
        admin_contents = stream.read(4097)
    require(0 < len(admin_contents) <= 4096, "FIXTURE_ADMIN_FILE_OVERSIZED")
    lines = [line.strip() for line in admin_contents.decode().splitlines() if line.strip()]
    require(lines and lines[0] == "[client]", "FIXTURE_ADMIN_LAYOUT_INVALID")
    entries = {}
    for line in lines[1:]:
        require("=" in line, "FIXTURE_ADMIN_LAYOUT_INVALID")
        key, value = line.split("=", 1)
        require(key not in entries and key in ("user", "password"), "FIXTURE_ADMIN_OPTIONS_REJECTED")
        entries[key] = value
    require(entries.get("user") == "aster_ci" and 1 <= len(entries.get("password", "")) <= 1024, "FIXTURE_ADMIN_IDENTITY_INVALID")
    pid_text = (root / "mysql.pid").read_text().strip()
    require(re.fullmatch(r"[1-9][0-9]{0,9}", pid_text), "FIXTURE_PID_INVALID")
    process = Path("/proc") / pid_text
    require(process.stat().st_uid == uid and (process / "exe").resolve(strict=True) == server.resolve(strict=True), "FIXTURE_SERVER_PROCESS_MISMATCH")
    command = (process / "cmdline").read_bytes()
    require(len(command) <= 65536, "FIXTURE_PROCESS_ARGUMENTS_INVALID")
    arguments = command.rstrip(b"\0").decode().split("\0")
    require(all(value in arguments for value in ("--no-defaults", "--skip-networking", "--mysqlx=0", "--datadir=" + str(root / "data"), "--socket=" + str(socket))), "FIXTURE_SERVER_PROCESS_MISMATCH")
    return Fixture(root, mysql_root, socket, admin, client, admin_contents)


def private_file(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


class Client:
    def __init__(self, fixture, work, cnf, principal="aster_ci"):
        self.fixture, self.cnf = fixture, cnf
        self.principal = principal
        home = work / "home"
        home.mkdir(mode=0o700, exist_ok=True)
        self.env = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "HOME": str(home),
                    "MYSQL_TEST_LOGIN_FILE": str(home / "absent-login-file"), "MYSQL_HISTFILE": "/dev/null"}

    def run(self, sql, *, database=None, denied=False):
        require(isinstance(sql, str) and len(sql.encode()) <= MAX_OUTPUT, "SQL_BOUND_EXCEEDED")
        # Option-file selection must precede normal client options. Keep the
        # explicit defaults file first, then suppress the separate login file.
        argv = [str(self.fixture.client), "--defaults-file=" + str(self.cnf), "--no-login-paths",
                "--protocol=SOCKET", "--socket=" + str(self.fixture.socket), "--batch", "--raw",
                "--skip-column-names", "--skip-reconnect", "--connect-timeout=5", "--binary-mode"]
        if database is not None:
            require(re.fullmatch(PREFIX + r"[_X][a-f0-9]{12}", database), "SQL_DATABASE_NOT_OWNED_TEST_NAME")
            argv.append("--database=" + database)
        submitted = ("SELECT CURRENT_USER();\n" + sql) if denied else sql
        result = subprocess.run(argv, input=submitted.encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                env=self.env, timeout=45, check=False)
        require(len(result.stdout) <= MAX_OUTPUT and len(result.stderr) <= MAX_OUTPUT, "CLIENT_OUTPUT_BOUND_EXCEEDED")
        if denied:
            codes = {int(value) for value in re.findall(rb"ERROR ([0-9]{4,5}) \([A-Z0-9]{5}\)", result.stderr)}
            # Authentication failure is not proof of SQL authorization. Confirm
            # this exact identity successfully executed the leading SELECT first.
            require(result.stdout.splitlines()[:1] == [(self.principal + "@localhost").encode()], "DENIAL_IDENTITY_NOT_AUTHENTICATED")
            require(result.returncode != 0 and bool(codes & DENIAL_CODES), "EXPECTED_PERMISSION_DENIAL_MISSING")
            return b""
        require(result.returncode == 0, "FIXTURE_SQL_COMMAND_FAILED")
        return result.stdout

    def json(self, sql):
        value = json.loads(self.run(sql))
        require(isinstance(value, dict), "FIXTURE_SQL_RESPONSE_INVALID")
        return value


def account_config(work, user, password):
    require(re.fullmatch(ACCOUNT_PREFIX + r"[rm][a-f0-9]{12}", user), "ACCOUNT_TEST_NAME_INVALID")
    require(isinstance(password, str) and 16 <= len(password) <= 1024 and not any(c in password for c in "\r\n\t\0"), "RANDOM_PASSWORD_RESPONSE_INVALID")
    quoted = password.replace("\\", "\\\\").replace('"', '\\"')
    path = work / (user + ".cnf")
    private_file(path, ('[client]\nuser=' + user + '\npassword="' + quoted + '"\n').encode())
    return path


def load_provision():
    spec = importlib.util.spec_from_file_location("cloud_grants_provision_contract", Path(__file__).resolve().parents[1] / "install/provision.py")
    module = importlib.util.module_from_spec(spec)
    previous = sys.dont_write_bytecode
    try:
        sys.dont_write_bytecode = True
        spec.loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = previous
    require(module.RUNTIME_PRIVILEGES == ("SELECT", "INSERT", "UPDATE", "DELETE"), "RUNTIME_PRIVILEGES_NOT_DML_ONLY")
    require(set(module.MIGRATION_PRIVILEGES) == {"SELECT", "INSERT", "UPDATE", "DELETE", "CREATE", "ALTER", "INDEX", "REFERENCES"}, "MIGRATION_PRIVILEGES_UNEXPECTED")
    return module


def run_contract(fixture):
    report = {"schema": 1, "scope": "owned-native-fixture-sql-and-grants-only", "passed": False,
              "checks": [], "migrations": [], "cleanup_confirmed": False,
              "not_root_socket_installer_or_host_acceptance": True}
    nonce = secrets.token_hex(32)
    suffix = secrets.token_hex(6)
    database, neighbor = PREFIX + "_" + suffix, PREFIX + "X" + suffix
    users = (ACCOUNT_PREFIX + "r" + suffix, ACCOUNT_PREFIX + "m" + suffix)
    planned_databases, planned_users = [], []
    with tempfile.TemporaryDirectory(prefix="cloud-grants-", dir=fixture.root) as directory:
        work = Path(directory)
        work.chmod(0o700)
        # Do not validate one mutable option file and let the client reread a
        # different one later. Use only this case's immutable validated snapshot.
        require(bool(fixture.admin_contents), "FIXTURE_ADMIN_SNAPSHOT_REQUIRED")
        admin_snapshot = work / "admin.cnf"
        private_file(admin_snapshot, fixture.admin_contents)
        admin = Client(fixture, work, admin_snapshot)
        server = admin.json("SELECT JSON_OBJECT('user',CURRENT_USER(),'version',VERSION(),'base',@@basedir,'data',@@datadir,'socket',@@socket,'tcp_disabled',@@skip_networking,'mysqlx',(SELECT COUNT(*) FROM information_schema.PLUGINS WHERE PLUGIN_NAME='mysqlx' AND PLUGIN_STATUS='ACTIVE'),'partial_revokes',@@partial_revokes,'mandatory_roles',@@mandatory_roles,'uuid',@@server_uuid);\n")
        require(server.get("user") == "aster_ci@localhost" and re.fullmatch(r"8\.4\.[0-9]+", server.get("version", "")), "FIXTURE_SERVER_IDENTITY_INVALID")
        require(Path(server.get("base", "")) == fixture.mysql_root and Path(server.get("data", "")) == fixture.root / "data" and server.get("socket") == str(fixture.socket), "FIXTURE_SERVER_PATHS_MISMATCH")
        require(server.get("tcp_disabled") == 1 and server.get("mysqlx") == 0 and server.get("partial_revokes") == 0 and not server.get("mandatory_roles"), "FIXTURE_SERVER_NOT_ISOLATED")
        require(re.fullmatch(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", server.get("uuid", "")), "FIXTURE_SERVER_UUID_INVALID")
        report["server_version"] = server["version"]
        report["checks"].append("owned-native-process-socket-and-server-identity")
        provision = load_provision()
        original_transport = provision.mysql_sql
        phase = "collision-preflight"
        try:
            collision = admin.json("SELECT JSON_OBJECT('databases',(SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME IN ('" + database + "','" + neighbor + "')),'accounts',(SELECT COUNT(*) FROM mysql.user WHERE User IN ('" + users[0] + "','" + users[1] + "')));\n")
            require(collision == {"databases": 0, "accounts": 0}, "TEST_OBJECT_COLLISION_REFUSED")
            phase = "owned-database-create"
            for name in (database, neighbor):
                planned_databases.append(name)
                admin.run("CREATE DATABASE `" + name + "` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;\nCREATE TABLE `" + name + "`.contract_ownership(nonce CHAR(64) PRIMARY KEY,server_uuid CHAR(36) NOT NULL);\nINSERT INTO `" + name + "`.contract_ownership VALUES('" + nonce + "','" + server["uuid"] + "');\n")
            admin.run("CREATE TABLE `" + neighbor + "`.contract_probe(id INT PRIMARY KEY); INSERT INTO `" + neighbor + "`.contract_probe VALUES(1);\n")
            clients = []
            phase = "random-password-account-create"
            for user, privileges in zip(users, (provision.RUNTIME_PRIVILEGES, provision.MIGRATION_PRIVILEGES)):
                planned_users.append(user)
                raw = admin.run("CREATE USER '" + user + "'@'localhost' IDENTIFIED WITH caching_sha2_password BY RANDOM PASSWORD ATTRIBUTE '{\"cloud_grants_contract\":\"" + nonce + "\"}';\n")
                values = raw.decode().rstrip("\n").split("\t")
                require(len(values) in (3, 4) and values[:2] == [user, "localhost"] and (len(values) == 3 or values[3] == "1"), "RANDOM_PASSWORD_RESPONSE_INVALID")
                clients.append(Client(fixture, work, account_config(work, user, values[2]), principal=user))
                del raw, values
                attribute = admin.json("SELECT JSON_OBJECT('nonce',ATTRIBUTE->>'$.cloud_grants_contract','host',HOST) FROM information_schema.USER_ATTRIBUTES WHERE USER='" + user + "';\n")
                require(attribute == {"nonce": nonce, "host": "localhost"}, "REAL_USER_ATTRIBUTE_MISMATCH")
                escaped = database.replace("_", "\\_")
                admin.run("GRANT " + ", ".join(privileges) + " ON `" + escaped + "`.* TO '" + user + "'@'localhost';\n")
            report["checks"].append("server-random-password-response-private-client-files-and-real-user-attributes")
            # Only replace this test transport; production ownership/root guards
            # and production bootstrap paths remain untouched and unexecuted.
            provision.mysql_sql = lambda _state, sql: admin.run(sql)
            phase = "real-show-grants-verifier"
            for user, privileges in zip(users, (provision.RUNTIME_PRIVILEGES, provision.MIGRATION_PRIVILEGES)):
                provision.verify_grants(work, user, database, privileges)
            report["checks"].append("production-exact-grant-verifier-on-real-show-grants")
            runtime, migrator = clients
            migration_dir = Path(__file__).resolve().parents[2] / "migrations"
            migrations = sorted(migration_dir.glob("[0-9][0-9][0-9]_*.sql"))
            versions = [int(path.name.split("_", 1)[0]) for path in migrations]
            require(versions and versions == list(range(1, len(versions) + 1)), "MIGRATION_INVENTORY_INVALID")
            for version, path in zip(versions, migrations):
                phase = "source-sql-migration"
                report["migration_under_test"] = version
                raw = path.read_bytes()
                digest = hashlib.sha256(raw).hexdigest()
                migrator.run(raw.decode(), database=database)
                migrator.run("INSERT INTO controller_schema(version,sha256,applied_at) VALUES(" + str(version) + ",'" + digest + "',UTC_TIMESTAMP(6));\n", database=database)
                report["migrations"].append({"version": version, "sha256": digest})
            require(admin.run("SELECT COUNT(*) FROM `" + database + "`.controller_schema;\n").strip() == str(len(migrations)).encode(), "MIGRATION_ROWS_MISMATCH")
            require(admin.run("SELECT COUNT(*) FROM information_schema.REFERENTIAL_CONSTRAINTS WHERE CONSTRAINT_SCHEMA='" + database + "' AND CONSTRAINT_NAME='controller_console_sessions_user_fk';\n").strip() == b"1", "REAL_IDENTITY_FOREIGN_KEY_MISSING")
            index_count = admin.run("SELECT COUNT(DISTINCT INDEX_NAME) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA='" + database + "' AND INDEX_NAME IN ('controller_audit_action_time','controller_audit_actor_time','controller_audit_target_time','controller_identity_audit_action_time','controller_identity_audit_actor_time','controller_identity_audit_target_time');\n").strip()
            require(index_count == b"6", "REAL_AUDIT_INDEXES_MISSING")
            report["checks"].append("all-source-sql-migrations-including-fk-and-six-004-indexes")
            users_index = admin.run("SELECT COUNT(*),SUM(CASE WHEN BINARY TABLE_NAME='controller_console_users' AND BINARY INDEX_NAME='controller_console_users_created_id' AND NON_UNIQUE=1 AND SUB_PART IS NULL AND INDEX_TYPE='BTREE' AND IS_VISIBLE='YES' AND EXPRESSION IS NULL AND COLLATION='A' AND ((SEQ_IN_INDEX=1 AND COLUMN_NAME='created_at') OR (SEQ_IN_INDEX=2 AND COLUMN_NAME='id')) THEN 1 ELSE 0 END) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA='" + database + "' AND TABLE_NAME='controller_console_users' AND INDEX_NAME='controller_console_users_created_id';\n").strip()
            require(users_index == b"2\t2", "REAL_USERS_PAGINATION_INDEX_INVALID")
            report["checks"].append("exact-011-users-pagination-index")
            report.pop("migration_under_test", None)
            phase = "real-runtime-dml-and-migration-ddl"
            migrator.run("CREATE TABLE contract_permissions(id INT PRIMARY KEY,note VARCHAR(40)); ALTER TABLE contract_permissions ADD COLUMN extra INT NULL; CREATE INDEX contract_note_idx ON contract_permissions(note);\n", database=database)
            runtime.run("INSERT INTO contract_permissions(id,note) VALUES(1,'one'); UPDATE contract_permissions SET note='two' WHERE id=1;\n", database=database)
            require(runtime.run("SELECT note FROM contract_permissions WHERE id=1;\n", database=database).strip() == b"two", "RUNTIME_DML_RESULT_MISMATCH")
            runtime.run("DELETE FROM contract_permissions WHERE id=1;\n", database=database)
            require(runtime.run("SELECT COUNT(*) FROM contract_permissions;\n", database=database).strip() == b"0", "RUNTIME_DELETE_NOT_CONFIRMED")
            report["checks"].append("real-runtime-four-dml-and-migrator-create-alter-index")
            phase = "negative-scope-and-wildcard-authorization"
            for sql in ("CREATE TABLE contract_forbidden(id INT);\n", "ALTER TABLE contract_permissions ADD COLUMN forbidden INT;\n", "GRANT SELECT ON `" + database.replace("_", "\\_") + "`.* TO '" + users[0] + "'@'localhost';\n"):
                runtime.run(sql, database=database, denied=True)
            for client, user in zip(clients, users):
                client.run("SELECT * FROM `" + neighbor + "`.contract_probe;\n", database=database, denied=True)
                client.run("GRANT SELECT ON *.* TO '" + user + "'@'localhost';\n", database=database, denied=True)
                client.run("DROP TABLE contract_permissions;\n", database=database, denied=True)
            migrator.run("CREATE TABLE `" + neighbor + "`.contract_forbidden(id INT);\n", database=database, denied=True)
            report["checks"].append("runtime-ddl-grant-and-both-identities-global-neighbor-wildcard-denials")
        except ContractError as error:
            report["error_code"] = str(error)
            report["failure_phase"] = phase
        except Exception:
            report["error_code"] = "NATIVE_SQL_GRANTS_CONTRACT_FAILED"
            report["failure_phase"] = phase
        finally:
            provision.mysql_sql = original_transport
            clean = True
            # A planned name alone is NOT ownership. Even after lost ACK, only
            # an exact nonce marker authorizes destroying that new test object.
            for user in reversed(planned_users):
                try:
                    owner = admin.json("SELECT JSON_OBJECT('nonce',ATTRIBUTE->>'$.cloud_grants_contract','host',HOST) FROM information_schema.USER_ATTRIBUTES WHERE USER='" + user + "';\n")
                    require(owner == {"nonce": nonce, "host": "localhost"}, "ACCOUNT_CLEANUP_OWNERSHIP_UNCONFIRMED")
                    admin.run("DROP USER '" + user + "'@'localhost';\n")
                except Exception:
                    clean = False
            for name in reversed(planned_databases):
                try:
                    owner = admin.json("SELECT JSON_OBJECT('nonce',nonce,'uuid',server_uuid) FROM `" + name + "`.contract_ownership;\n")
                    require(owner == {"nonce": nonce, "uuid": server["uuid"]}, "DATABASE_CLEANUP_OWNERSHIP_UNCONFIRMED")
                    admin.run("DROP DATABASE `" + name + "`;\n")
                except Exception:
                    clean = False
            if clean and (planned_databases or planned_users):
                try:
                    remaining = admin.json("SELECT JSON_OBJECT('databases',(SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME IN ('" + database + "','" + neighbor + "')),'accounts',(SELECT COUNT(*) FROM mysql.user WHERE User IN ('" + users[0] + "','" + users[1] + "')));\n")
                    require(remaining == {"databases": 0, "accounts": 0}, "OWNED_OBJECT_CLEANUP_NOT_CONFIRMED")
                except Exception:
                    clean = False
            report["cleanup_confirmed"] = clean
    report["passed"] = "error_code" not in report and report["cleanup_confirmed"]
    if not report["cleanup_confirmed"]:
        report["error_code"] = "OWNED_TEST_CLEANUP_UNCONFIRMED_FIXTURE_WILL_CLEAN"
    return report


def main():
    try:
        fixture = validate_fixture()
        report = run_contract(fixture)
    except ContractError as error:
        report = {"schema": 1, "passed": False, "scope": "owned-native-fixture-sql-and-grants-only", "error_code": str(error)}
    except Exception:
        report = {"schema": 1, "passed": False, "scope": "owned-native-fixture-sql-and-grants-only", "error_code": "FIXTURE_CONTRACT_REFUSED_DETAILS_WITHHELD"}
    print(json.dumps(report, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
