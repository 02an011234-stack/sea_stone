import json,shutil,subprocess,tempfile,unittest
from pathlib import Path
from os_guard_agent import MODULE_VERSION
from os_guard_agent.manifest import load_manifest
from os_guard_agent.models import Action,OsInfo
from os_guard_agent.module_runner import ModuleRunner
R=Path(__file__).parents[1];M=R/'modules/unix/U-48.sh';MF=R/'modules/manifest.json';S=lambda:shutil.which('sh') or r'C:\Program Files\Git\bin\sh.exe';O=lambda d='rocky',v='9.6':OsInfo(d,v,v,'fixture','host','x86_64',True)
class U48Tests(unittest.TestCase):
 def case(self,row,d='rocky',v='9.6'):
  with tempfile.TemporaryDirectory() as td:
   f=Path(td)/'f';f.write_text(row+'\n',newline='\n');e={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C','OS_GUARD_DISTRO':d,'OS_GUARD_VERSION_ID':v,'OS_GUARD_MODULE_VERSION':MODULE_VERSION,'OS_GUARD_TEST_ROOT':td,'OS_GUARD_TEST_U48_FILE':str(f)};p=subprocess.run([S(),str(M)],env=e,capture_output=True,text=True,timeout=5);self.assertEqual(p.returncode,0,p.stderr);return json.loads(p.stdout)
 def test_manifest(self):self.assertEqual(ModuleRunner(load_manifest(MF,'manifest-unix-67-v1',O()),O()).prepare_item('U-48',Action.CHECK).module_path.name,'U-48.sh')
 def test_unused_good(self):self.assertEqual(self.case('complete|0|0|0|0|none')['status'],'GOOD')
 def test_sendmail_good(self):self.assertEqual(self.case('complete|1|1|1|0|sendmail')['status'],'GOOD')
 def test_sendmail_vulnerable(self):self.assertEqual(self.case('complete|1|0|1|0|sendmail')['status'],'VULNERABLE')
 def test_postfix_good(self):self.assertEqual(self.case('complete|1|1|1|0|postfix')['status'],'GOOD')
 def test_exim_pending(self):self.assertIsNone(self.case('complete|1|0|0|1|exim')['status'])
 def test_uncheckable(self):self.assertEqual(self.case('error|0|0|0|0|none')['status'],'UNCHECKABLE')
 def test_four_os(self):
  for d,v in [('rocky','9.6'),('rocky','10'),('ubuntu','22.04'),('ubuntu','24.04')]:self.assertEqual(self.case('complete|0|0|0|0|none',d,v)['status'],'GOOD')
 def test_scope(self):s=M.read_text();[self.assertIn(x,s) for x in ['noexpn','novrfy','goaway','disable_vrfy_command']]
