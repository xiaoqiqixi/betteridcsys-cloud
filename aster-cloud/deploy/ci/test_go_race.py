#!/usr/bin/env python3
"""Public runner scheduling contract. Fake go is a process boundary, not SQL/crypto evidence."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ENTRY = Path(__file__).with_name('go-race.py')
PACKAGES = ['aster/cloud/cmd/aster-controller','aster/cloud/internal/control','aster/cloud/internal/controllerbackup','aster/cloud/added/future']

class GoRaceScheduling(unittest.TestCase):
    def invoke(self, *args, packages=None, fail=False):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            executable=root/'go'
            executable.write_text('#!'+sys.executable+'\n'+'''import os,json,sys,pathlib
r=pathlib.Path(os.environ['CASE_ROOT'])
with (r/'calls').open('a') as f:f.write(json.dumps(sys.argv[1:])+'\\n')
if sys.argv[1]=='list':print((r/'packages').read_text(),end='')
elif os.environ.get('FAIL_GROUP')=='1':raise SystemExit(1)
''')
            executable.chmod(0o700)
            (root/'packages').write_text('\n'.join(PACKAGES if packages is None else packages)+'\n')
            env={**os.environ,'PATH':str(root)+os.pathsep+os.environ['PATH'],'CASE_ROOT':str(root),'FAIL_GROUP':str(int(fail))}
            result=subprocess.run([sys.executable,'-I',str(ENTRY),*args],env=env,capture_output=True,text=True,timeout=10)
            calls=[json.loads(line) for line in (root/'calls').read_text().splitlines()] if (root/'calls').exists() else []
            return result,calls

    def test_all_current_and_future_packages_run_once_with_unchanged_budget(self):
        for args in ((),('--native-mysql',)):
            result,calls=self.invoke(*args)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(calls[0],['list','-mod=readonly','./...'])
            runs=calls[1:];self.assertEqual(len(runs),2)
            self.assertEqual(runs[0][-1],PACKAGES[0])
            self.assertEqual([p for run in runs for p in run if p.startswith('aster/cloud/')],PACKAGES)
            for run in runs:
                self.assertEqual(run[:6],['test','-mod=readonly','-race','-count=1','-v','-timeout=10m'])
                self.assertEqual('-skip' in run,bool(args))

    def test_failure_stops_without_claiming_later_packages_passed(self):
        result,calls=self.invoke(fail=True)
        self.assertEqual(result.returncode,1);self.assertEqual(len(calls),2)

    def test_missing_duplicate_foreign_packages_and_override_flags_refused(self):
        for packages in ([],PACKAGES*2,PACKAGES+['foreign/module'],PACKAGES+['aster/cloud/../escape']):
            result,calls=self.invoke(packages=packages)
            self.assertEqual(result.returncode,1);self.assertEqual(len(calls),1)
        result,calls=self.invoke('--timeout','30m')
        self.assertNotEqual(result.returncode,0);self.assertEqual(calls,[])

if __name__=='__main__':unittest.main()
