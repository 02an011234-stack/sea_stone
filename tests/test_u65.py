import json,shutil,subprocess,tempfile,unittest
from pathlib import Path
from os_guard_agent import MODULE_VERSION
from os_guard_agent.manifest import load_manifest
from os_guard_agent.models import Action,OsInfo
from os_guard_agent.module_runner import ModuleRunner
R=Path(__file__).parents[1];M=R/'modules/unix/U-65.sh';MF=R/'modules/manifest.json';S=lambda:shutil.which('sh') or r'C:\Program Files\Git\bin\sh.exe';O=lambda d='rocky',v='9.6':OsInfo(d,v,v,'fixture','host','x86_64',True)
class U65Tests(unittest.TestCase):
 def case(self,row,d='rocky',v='9.6'):
  with tempfile.TemporaryDirectory() as td:
   f=Path(td)/'f';f.write_text(row+'\n',newline='\n');e={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C','OS_GUARD_DISTRO':d,'OS_GUARD_VERSION_ID':v,'OS_GUARD_MODULE_VERSION':MODULE_VERSION,'OS_GUARD_TEST_ROOT':td,'OS_GUARD_TEST_U65_FILE':str(f)};p=subprocess.run([S(),str(M)],env=e,capture_output=True,text=True,timeout=5);self.assertEqual(p.returncode,0,p.stderr);return json.loads(p.stdout),p.stdout
 def test_manifest(self):self.assertEqual(ModuleRunner(load_manifest(MF,'manifest-unix-67-v1',O()),O()).prepare_item('U-65',Action.CHECK).module_path.name,'U-65.sh')
 def test_supported_services_synchronized(self):
  for n in ['chrony','ntp','timesyncd']:self.assertEqual(self.case(f'complete|1|1|1|1|1|2|{n}')[0]['status'],'GOOD')
 def test_inactive(self):self.assertEqual(self.case('complete|0|0|0|1|0|0|none')[0]['status'],'VULNERABLE')
 def test_server_missing(self):self.assertEqual(self.case('complete|1|0|1|1|1|0|chrony')[0]['status'],'VULNERABLE')
 def test_not_synchronized(self):self.assertEqual(self.case('complete|1|1|0|1|1|2|ntp')[0]['status'],'VULNERABLE')
 def test_sync_unknown(self):self.assertIsNone(self.case('complete|1|1|0|0|1|2|chrony')[0]['status'])
 def test_approval_unknown(self):self.assertIsNone(self.case('complete|1|1|1|1|0|2|timesyncd')[0]['status'])
 def test_error(self):self.assertEqual(self.case('error|0|0|0|0|0|0|none')[0]['status'],'UNCHECKABLE')
 def test_four_os_and_privacy(self):
  for d,v,n in [('rocky','9.6','chrony'),('rocky','10','chrony'),('ubuntu','22.04','timesyncd'),('ubuntu','24.04','timesyncd')]:self.assertEqual(self.case(f'complete|1|1|1|1|1|2|{n}',d,v)[0]['status'],'GOOD')
  r,o=self.case('complete|1|1|1|1|1|2|chrony');self.assertNotIn('pool.ntp.org',o);self.assertNotIn('makestep',M.read_text())
