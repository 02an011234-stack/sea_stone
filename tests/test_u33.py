from __future__ import annotations
import json,shutil,subprocess,tempfile,unittest
from pathlib import Path
from os_guard_agent import MODULE_VERSION
from os_guard_agent.manifest import load_manifest
from os_guard_agent.models import Action,OsInfo
from os_guard_agent.module_runner import ModuleRunner
ROOT=Path(__file__).parents[1]; M=ROOT/'modules/unix/U-33.sh'; MF=ROOT/'modules/manifest.json'
def sh(): return shutil.which('sh') or (r'C:\Program Files\Git\bin\sh.exe' if Path(r'C:\Program Files\Git\bin\sh.exe').is_file() else None)
def oi(d='rocky',v='9.6'): return OsInfo(d,v,v,'fixture-kernel','host','x86_64',True)
class U33Tests(unittest.TestCase):
 def run_case(self,row,d='rocky',v='9.6'):
  if not sh(): self.skipTest('POSIX shell is unavailable')
  with tempfile.TemporaryDirectory() as td:
   f=Path(td)/'f'; f.write_text(row+'\n',newline='\n'); env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C','OS_GUARD_DISTRO':d,'OS_GUARD_VERSION_ID':v,'OS_GUARD_MODULE_VERSION':MODULE_VERSION,'OS_GUARD_TEST_ROOT':td,'OS_GUARD_TEST_HIDDEN_SCAN_FILE':str(f)}
   cp=subprocess.run([sh(),str(M)],env=env,capture_output=True,text=True,timeout=5); self.assertEqual(cp.returncode,0,cp.stderr); self.assertEqual(cp.stdout.count('\n'),1); return json.loads(cp.stdout),cp.stdout+cp.stderr
 def test_01_manifest(self): self.assertEqual(ModuleRunner(load_manifest(MF,'manifest-unix-67-v1',oi()),oi()).prepare_item('U-33',Action.CHECK).module_path.name,'U-33.sh')
 def test_02_none_good(self): self.assertEqual(self.run_case('complete|0|0|0|0|0|0')[0]['status'],'GOOD')
 def test_03_all_approved_good(self): self.assertEqual(self.run_case('complete|2|3|5|0|0|0')[0]['status'],'GOOD')
 def test_04_unresolved_pending(self): r,_=self.run_case('complete|2|3|0|0|5|0'); self.assertIsNone(r['status']); self.assertEqual(r['review_state'],'PENDING')
 def test_05_verified_suspicious_vulnerable(self): self.assertEqual(self.run_case('complete|2|3|0|1|4|0')[0]['status'],'VULNERABLE')
 def test_06_scan_error(self): self.assertEqual(self.run_case('scan_error|0|0|0|0|0|1')[0]['status'],'UNCHECKABLE')
 def test_07_timeout(self): r,_=self.run_case('timeout|0|0|0|0|0|0'); self.assertEqual(r['status'],'UNCHECKABLE'); self.assertTrue(r['evidence']['timeout'])
 def test_08_truncated(self): r,_=self.run_case('truncated|100|100|0|0|0|0'); self.assertEqual(r['status'],'UNCHECKABLE'); self.assertTrue(r['evidence']['truncated'])
 def test_09_four_os(self):
  for d,v in [('rocky','9.6'),('rocky','10.0'),('ubuntu','22.04'),('ubuntu','24.04')]: self.assertEqual(self.run_case('complete|0|0|0|0|0|0',d,v)[0]['status'],'GOOD')
 def test_10_privacy(self): r,o=self.run_case('complete|2|3|0|0|5|0'); self.assertEqual(r['evidence']['hidden_file_count'],2); self.assertNotIn('/home/',o); self.assertNotIn('.ssh',o)
 def test_11_bounded_read_only(self): s=M.read_text(); [self.assertIn(x,s) for x in ['timeout','-xdev','record_limit']]; self.assertNotRegex(s,r'(?m)^\s*(chmod|chown|rm|mv|touch|tee)\b')
if __name__=='__main__': unittest.main()
