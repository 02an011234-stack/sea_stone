import json,shutil,subprocess,tempfile,unittest
from pathlib import Path
from os_guard_agent import MODULE_VERSION
from os_guard_agent.manifest import load_manifest
from os_guard_agent.models import Action,OsInfo
from os_guard_agent.module_runner import ModuleRunner
R=Path(__file__).parents[1];M=R/'modules/unix/U-66.sh';MF=R/'modules/manifest.json';S=lambda:shutil.which('sh') or r'C:\Program Files\Git\bin\sh.exe';O=lambda d='rocky',v='9.6':OsInfo(d,v,v,'fixture','host','x86_64',True)
class U66Tests(unittest.TestCase):
 def case(self,row,d='rocky',v='9.6'):
  with tempfile.TemporaryDirectory() as td:
   f=Path(td)/'f';f.write_text(row+'\n',newline='\n');e={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C','OS_GUARD_DISTRO':d,'OS_GUARD_VERSION_ID':v,'OS_GUARD_MODULE_VERSION':MODULE_VERSION,'OS_GUARD_TEST_ROOT':td,'OS_GUARD_TEST_U66_FILE':str(f)};p=subprocess.run([S(),str(M)],env=e,capture_output=True,text=True,timeout=5);self.assertEqual(p.returncode,0,p.stderr);return json.loads(p.stdout),p.stdout
 def test_manifest(self):self.assertEqual(ModuleRunner(load_manifest(MF,'manifest-unix-67-v1',O()),O()).prepare_item('U-66',Action.CHECK).module_path.name,'U-66.sh')
 def test_inactive(self):self.assertEqual(self.case('complete|0|0|0|0|0|none')[0]['status'],'VULNERABLE')
 def test_rsyslog_policy_verified(self):self.assertEqual(self.case('complete|1|1|1|5|0|rsyslog')[0]['status'],'GOOD')
 def test_journald_policy_verified(self):self.assertEqual(self.case('complete|1|1|1|1|0|journald')[0]['status'],'GOOD')
 def test_output_absent(self):self.assertEqual(self.case('complete|1|0|1|4|0|rsyslog')[0]['status'],'VULNERABLE')
 def test_rules_absent(self):self.assertEqual(self.case('complete|1|1|0|0|0|rsyslog')[0]['status'],'VULNERABLE')
 def test_policy_unknown(self):self.assertIsNone(self.case('complete|1|1|0|4|0|rsyslog')[0]['status'])
 def test_complex_remote(self):self.assertIsNone(self.case('complete|1|1|1|4|1|mixed')[0]['status'])
 def test_error(self):self.assertEqual(self.case('error|0|0|0|0|0|none')[0]['status'],'UNCHECKABLE')
 def test_four_os_and_no_log_content(self):
  for d,v,b in [('rocky','9.6','rsyslog'),('rocky','10','rsyslog'),('ubuntu','22.04','journald'),('ubuntu','24.04','journald')]:self.assertEqual(self.case(f'complete|1|1|1|2|0|{b}',d,v)[0]['status'],'GOOD')
  r,o=self.case('complete|1|1|1|2|0|rsyslog');self.assertNotIn('authentication failure',o)
