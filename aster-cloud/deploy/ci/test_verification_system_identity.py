#!/usr/bin/env python3
"""Public NSS/shadow record contract; never creates an account on this host."""
import importlib.util
from pathlib import Path
import unittest

ENTRY = Path(__file__).resolve().parents[1]/'install/controller-migration.py'
SPEC = importlib.util.spec_from_file_location('verification_system_identity_contract', ENTRY)
manager = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(manager)


class VerificationSystemIdentityContract(unittest.TestCase):
    operation = '0123456789abcdef0123456789abcdef'
    nonce = 'b'*64
    name = 'asterv-0123456789abcdef01234567'

    def records(self):
        # Different UID and GID are intentional: system allocation need not
        # choose matching numbers. No password credential or login shell exists.
        return {
            'passwd': 'root:x:0:0:root:/root:/bin/bash\n'+self.name+':x:999:998:Aster verification '+self.operation+' '+self.nonce+':/nonexistent:/usr/sbin/nologin\n',
            'group': 'root:x:0:\n'+self.name+':x:998:\n',
            'shadow': self.name+':!:20400::::::\n',
            'gshadow': self.name+':!::\n',
            'groups': '998\n',
        }

    def test_locked_nonlogin_service_identity_has_no_account_expiry(self):
        result = manager.system_identity_from_records(self.operation, self.nonce, self.records())
        self.assertEqual({k:result[k] for k in ('name','uid','gid')}, {'name':self.name,'uid':999,'gid':998})
        self.assertEqual(set(result), {'name','uid','gid','passwd_sha256','group_sha256','shadow_sha256','gshadow_sha256'})

    def rejected(self, records, operation=None, nonce=None):
        with self.assertRaisesRegex(manager.Refused, '^TARGET_VERIFICATION_SYSTEM_IDENTITY_REJECTED$'):
            manager.system_identity_from_records(operation or self.operation, nonce or self.nonce, records)

    def test_root_shared_uid_and_shared_primary_group_are_not_dedicated_accounts(self):
        base = self.records()
        for passwd in (base['passwd'].replace(':999:998:', ':0:998:'),
                       base['passwd'].replace(':999:998:', ':999:0:'),
                       base['passwd']+'foreign:x:999:997:Other:/nonexistent:/usr/sbin/nologin\n',
                       base['passwd']+'foreign:x:997:998:Other:/nonexistent:/usr/sbin/nologin\n'):
            with self.subTest(passwd=passwd):
                self.rejected({**base,'passwd':passwd})

    def test_group_alias_membership_and_supplementary_permissions_are_refused(self):
        base = self.records()
        for group in (base['group']+'foreign:x:998:\n', base['group']+'sudo:x:27:'+self.name+'\n',
                      base['group'].replace(':998:\n', ':998:foreign\n')):
            self.rejected({**base,'group':group})
        for memberships in ('998 27\n','998 998\n','0\n','998 \n'):
            self.rejected({**base,'groups':memberships})
        for value in (self.name+':!:root:\n',self.name+':!::foreign\n'):
            self.rejected({**base,'gshadow':value})

    def test_shell_home_and_original_operation_ownership_cannot_be_adopted(self):
        base = self.records()
        for old,new in (('/usr/sbin/nologin','/bin/bash'),('/nonexistent','/home/'+self.name),
                        (self.nonce,'c'*64),(self.operation,'d'*32)):
            self.rejected({**base,'passwd':base['passwd'].replace(old,new)})
        self.rejected(base,operation='d'*32)

    def test_password_unlock_hash_or_expiry_drift_is_refused_without_secret_output(self):
        base = self.records()
        for old,new in ((':!:',':PRIVATE_HASH:'),(':!:',':!PRIVATE_HASH:'),(':!:',':!!:'),
                        ('::::::', ':::::1:'),('::::::', ':::::99999:')):
            self.rejected({**base,'shadow':base['shadow'].replace(old,new)})

    def test_truncated_aliased_or_malformed_records_are_not_absence_proof(self):
        base = self.records()
        for key in base:
            for value in ('',base[key].removesuffix('\n'),base[key]+'\n',base[key].replace('\n','\r\n')):
                with self.subTest(record=key):
                    self.rejected({**base,key:value})
        self.rejected({**base,'passwd':base['passwd'].replace(':999:998:',':0999:998:')})
        self.rejected({**base,'extra':'unapproved'})
        self.rejected(base,nonce='B'*64)

    def test_any_selected_record_drift_changes_its_receipt_fingerprint(self):
        before = manager.system_identity_from_records(self.operation,self.nonce,self.records())
        changed = {**self.records(),'shadow':self.records()['shadow'].replace(':20400:',':20401:')}
        after = manager.system_identity_from_records(self.operation,self.nonce,changed)
        self.assertNotEqual(before['shadow_sha256'],after['shadow_sha256'])
        self.assertEqual(before['passwd_sha256'],after['passwd_sha256'])

    def test_remote_incomplete_or_overridden_nss_inventory_is_not_local_absence(self):
        raw = 'passwd: files systemd\ngroup: files systemd\nshadow: files\ngshadow: files\nhosts: files dns\n'
        self.assertIsNone(manager.local_system_identity_sources(raw))
        self.assertIsNone(manager.local_system_identity_sources(raw.replace('files systemd','files')))
        for value in (raw.replace('files systemd','files sss'),raw.replace('shadow: files\n','shadow: ldap\n'),
                      raw.replace('gshadow: files\n',''),raw+'passwd: files\n',
                      raw.replace('files systemd','files [NOTFOUND=return] systemd')):
            with self.assertRaisesRegex(manager.Refused,'^TARGET_VERIFICATION_SYSTEM_NSS_REJECTED$'):
                manager.local_system_identity_sources(value)


if __name__ == '__main__':
    unittest.main()
