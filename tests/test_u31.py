from __future__ import annotations
import json,shutil,subprocess,tempfile,unittest
from pathlib import Path
from os_guard_agent import MODULE_VERSION
from os_guard_agent.manifest import load_manifest
from os_guard_agent.models import Action,OsInfo
from os_guard_agent.module_runner import ModuleRunner
ROOT=Path(__file__).parents[1]; M=ROOT/'modules/unix/U-31.sh'; MF=ROOT/'modules/manifest.json'
def sh(): return shutil.which('sh') or (r'C:\Program Files\Git\bin\sh.exe' if Path(r'C:\Program Files\Git\bin\sh.exe').is_file() else None)
def oi(d='rocky',v='9.6'): return OsInfo(d,v,v,'fixture-kernel','host','x86_64',True)
class U31Tests(unittest.TestCase):
 def run_case(self,row,d='rocky',v='9.6'):
  if not sh(): self.skipTest('POSIX shell is unavailable')
  with tempfile.TemporaryDirectory() as td:
   f=Path(td)/'f'; f.write_text(row+'\n',newline='\n'); env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C','OS_GUARD_DISTRO':d,'OS_GUARD_VERSION_ID':v,'OS_GUARD_MODULE_VERSION':MODULE_VERSION,'OS_GUARD_TEST_ROOT':td,'OS_GUARD_TEST_HOME_SCAN_FILE':str(f)}
   cp=subprocess.run([sh(),str(M)],env=env,capture_output=True,text=True,timeout=5); self.assertEqual(cp.returncode,0,cp.stderr); self.assertEqual(cp.stdout.count('\n'),1); return json.loads(cp.stdout),cp.stdout
 def test_01_manifest(self): self.assertEqual(ModuleRunner(load_manifest(MF,'manifest-unix-67-v1',oi()),oi()).prepare_item('U-31',Action.CHECK).module_path.name,'U-31.sh')
 def test_02_good(self): self.assertEqual(self.run_case('complete|4|4|0|0|0|0')[0]['status'],'GOOD')
 def test_03_owner_vulnerable(self): self.assertEqual(self.run_case('complete|4|4|1|0|0|0')[0]['status'],'VULNERABLE')
 def test_04_write_vulnerable(self): self.assertEqual(self.run_case('complete|4|4|0|1|0|0')[0]['status'],'VULNERABLE')
 def test_05_acl_vulnerable(self): self.assertEqual(self.run_case('complete|4|4|0|0|1|0')[0]['status'],'VULNERABLE')
 def test_06_unresolved_pending(self): r,_=self.run_case('complete|4|3|0|0|0|1'); self.assertIsNone(r['status']); self.assertEqual(r['review_state'],'PENDING')
 def test_07_scan_error(self): self.assertEqual(self.run_case('scan_error|4|0|0|0|0|0')[0]['status'],'UNCHECKABLE')
 def test_08_four_os(self):
  for d,v in [('rocky','9.6'),('rocky','10.0'),('ubuntu','22.04'),('ubuntu','24.04')]: self.assertEqual(self.run_case('complete|1|1|0|0|0|0',d,v)[0]['status'],'GOOD')
 def test_09_evidence_privacy(self): r,o=self.run_case('complete|4|4|0|0|0|0'); self.assertEqual(r['evidence']['home_checked_count'],4); self.assertNotIn('/home/',o)
 def test_10_read_only(self): s=M.read_text(); self.assertIn('/etc/passwd',s); self.assertIn('getfacl',s); self.assertNotRegex(s,r'(?m)^\s*(chmod|chown|rm|mv|touch|tee)\b')
if __name__=='__main__': unittest.main()
