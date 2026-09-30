import json,shutil,subprocess,tempfile,unittest
from pathlib import Path
from os_guard_agent import MODULE_VERSION
from os_guard_agent.manifest import load_manifest
from os_guard_agent.models import Action,OsInfo
from os_guard_agent.module_runner import ModuleRunner
R=Path(__file__).parents[1];M=R/'modules/unix/U-49.sh';MF=R/'modules/manifest.json';S=lambda:shutil.which('sh') or r'C:\Program Files\Git\bin\sh.exe';O=lambda d='rocky',v='9.6':OsInfo(d,v,v,'fixture','host','x86_64',True)
class U49Tests(unittest.TestCase):
 def case(self,row,d='rocky',v='9.6'):
  with tempfile.TemporaryDirectory() as td:
   f=Path(td)/'f';f.write_text(row+'\n',newline='\n');e={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C','OS_GUARD_DISTRO':d,'OS_GUARD_VERSION_ID':v,'OS_GUARD_MODULE_VERSION':MODULE_VERSION,'OS_GUARD_TEST_U49_FILE':str(f)};p=subprocess.run([S(),str(M)],env=e,capture_output=True,text=True,timeout=5);self.assertEqual(p.returncode,0,p.stderr);return json.loads(p.stdout)
 def test_manifest(self):self.assertEqual(ModuleRunner(load_manifest(MF,'manifest-unix-67-v1',O()),O()).prepare_item('U-49',Action.CHECK).module_path.name,'U-49.sh')
 def test_unused(self):self.assertEqual(self.case('complete|0|0|0|0|0')['status'],'GOOD')
 def test_current(self):self.assertEqual(self.case('complete|1|1|0|0|1')['status'],'GOOD')
 def test_outdated(self):self.assertEqual(self.case('complete|1|0|1|0|1')['status'],'VULNERABLE')
 def test_unknown(self):self.assertIsNone(self.case('complete|1|0|0|1|1')['status'])
 def test_error(self):self.assertEqual(self.case('error|0|0|0|0|0')['status'],'UNCHECKABLE')
 def test_four_os(self):
  for d,v in [('rocky','9.6'),('rocky','10'),('ubuntu','22.04'),('ubuntu','24.04')]:self.assertEqual(self.case('complete|0|0|0|0|0',d,v)['status'],'GOOD')
 def test_offline(self):s=M.read_text();self.assertIn('--cacheonly',s);self.assertIn('--no-download',s);self.assertNotIn('curl ',s)
