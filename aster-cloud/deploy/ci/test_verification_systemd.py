#!/usr/bin/env python3
"""systemd unit wire contract; no system services are changed by these tests."""
import importlib.util
from pathlib import Path
import unittest

ENTRY = Path(__file__).resolve().parents[1]/'install/controller-migration.py'
spec = importlib.util.spec_from_file_location('verification_systemd_contract',ENTRY)
manager = importlib.util.module_from_spec(spec)
spec.loader.exec_module(manager)


class VerificationUnitContract(unittest.TestCase):
    operation = '0123456789abcdef0123456789abcdef'
    version = Path('/opt/aster-cloud/controller/versions/0.1.0-rc.1-0123456789abcdef')
    nonce = 'b'*64

    def test_single_operation_unit_is_runtime_only_nonrestarting_and_bounded(self):
        raw = manager.verification_unit_bytes(self.operation,self.version,self.nonce)
        lines=raw.decode().splitlines()
        required = {'[Unit]','[Service]','Type=exec','User=root','Group=root','Restart=no',
            'KillMode=mixed','SendSIGKILL=yes','TimeoutStopSec=120','RuntimeMaxSec=3700',
            'NoNewPrivileges=yes','UMask=0077','WorkingDirectory=/',
            'StandardInput=null','StandardOutput=null','StandardError=journal',
            'ExecStart=/usr/bin/python3 -I '+str(self.version)+'/templates/host-management/controller-migration.py target-verification-serve --operation '+self.operation}
        self.assertTrue(required<=set(lines))
        self.assertEqual(sum(line.startswith('ExecStart=') for line in lines),1)
        self.assertNotIn('[Install]',lines)
        self.assertFalse(any(line.startswith(('ExecStop=','ExecStartPre=','EnvironmentFile=','RestartSec=')) for line in lines))
        self.assertIn(self.nonce,raw.decode())

    def test_paths_operations_and_unit_directives_cannot_be_injected(self):
        for operation,version,nonce in [('a'*31,self.version,self.nonce),
            ('A'*32,self.version,self.nonce),(self.operation,Path('/tmp/foreign'),self.nonce),
            (self.operation,Path(str(self.version)+'/../foreign'),self.nonce),
            (self.operation,Path(str(self.version)+'\nExecStop=/bin/sh'),self.nonce),
            (self.operation,self.version,'B'*64),(self.operation,self.version,self.nonce+'\n')]:
            with self.subTest(operation=operation,version=version):
                with self.assertRaises(manager.Refused):
                    manager.verification_unit_bytes(operation,version,nonce)

    def test_effective_systemd_properties_reject_privilege_restart_and_stop_overrides(self):
        name='aster-target-verification-'+self.operation+'.service'
        fragment='/run/systemd/system/'+name
        value={'Id':name,'Names':name,'FragmentPath':fragment,'LoadState':'loaded','NeedDaemonReload':'no',
            'User':'root','Group':'root','Type':'exec','KillMode':'mixed','Restart':'no',
            'SendSIGKILL':'yes','NoNewPrivileges':'yes','Transient':'no','WorkingDirectory':'/',
            'UnitFileState':'static','ControlPID':'0','MainPID':'0','ActiveState':'inactive',
            'DropInPaths':'','ExecStop':'','ExecStopPost':'','ExecStartPre':'','ExecStartPost':'',
            'ExecCondition':'','ExecReload':'','EnvironmentFiles':'','SupplementaryGroups':'',
            'RootDirectory':'','RootImage':''}
        self.assertEqual(manager.verification_unit_properties(value,name,fragment),0)
        for key,bad in [('Restart','always'),('User','nobody'),('NoNewPrivileges','no'),
                        ('KillMode','process'),('DropInPaths','/tmp/override.conf'),
                        ('NeedDaemonReload','yes'),('ExecStop','/bin/sh'),('ExecStartPre','/bin/sh'),
                        ('EnvironmentFiles','/tmp/foreign'),('Names',name+' alias.service'),
                        ('FragmentPath','/etc/systemd/system/'+name),('Transient','yes'),
                        ('SupplementaryGroups','sudo'),('ControlPID','1'),('UnitFileState','enabled')]:
            with self.subTest(key=key):
                with self.assertRaises(manager.Refused):
                    manager.verification_unit_properties({**value,key:bad},name,fragment)
        with self.assertRaises(manager.Refused):
            manager.verification_unit_properties({**value,'ActiveState':'active'},name,fragment)
        with self.assertRaises(manager.Refused):
            manager.verification_unit_properties({**value,'MainPID':'01'},name,fragment)


if __name__=='__main__':
    unittest.main()
