from __future__ import annotations
import hashlib,json,shutil,subprocess,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from os_guard_agent import MODULE_VERSION
from os_guard_agent.manifest import load_manifest
from os_guard_agent.models import Action,OsInfo,ResultStatus
from os_guard_agent.module_runner import ModuleRunner,ModuleTimeoutError
R=Path(__file__).parents[1];M=R/"modules"/"manifest.json";S=R/"modules"/"unix"/"U-27.sh"
def sh():return shutil.which("sh")or next((str(p)for p in(Path(r"C:\Program Files\Git\bin\sh.exe"),Path(r"C:\Program Files\Git\usr\bin\sh.exe"))if p.is_file()),None)
def oi(d="rocky",v="9.6"):return OsInfo(d,v,v,"k","h","x86_64",True)
class U27Tests(unittest.TestCase):
 def runner(self,d="rocky",v="9.6"):x=oi(d,v);return ModuleRunner(load_manifest(M,"manifest-unix-67-v1",x),x)
 def run_module(self,rec,d="rocky",v="9.6"):
  x=sh()
  if not x:self.skipTest("no shell")
  with tempfile.TemporaryDirectory()as td:
   f=Path(td)/"f";f.write_text(rec+"\n",newline="\n");h=hashlib.sha256(f.read_bytes()).hexdigest();e={"PATH":"/usr/sbin:/usr/bin:/sbin:/bin","LC_ALL":"C","OS_GUARD_DISTRO":d,"OS_GUARD_VERSION_ID":v,"OS_GUARD_MODULE_VERSION":MODULE_VERSION,"OS_GUARD_TEST_ROOT":td,"OS_GUARD_TEST_SCAN_FILE":str(f)};c=subprocess.run([x,str(S)],env=e,capture_output=True,text=True,timeout=5);self.assertEqual(c.returncode,0,c.stderr);self.assertEqual(h,hashlib.sha256(f.read_bytes()).hexdigest());return json.loads(c.stdout),c.stdout+c.stderr
 def test_01_manifest(self):self.assertEqual(self.runner().prepare_item("U-27",Action.CHECK).module_path.name,"U-27.sh")
 def test_02_unused_good(self):self.assertEqual(self.run_module("complete|0|0|0|0|0|0|0")[0]["status"],"GOOD")
 def test_03_active_safe_good(self):self.assertEqual(self.run_module("complete|1|2|2|0|0|0|0")[0]["status"],"GOOD")
 def test_04_owner_bad_vulnerable(self):self.assertEqual(self.run_module("complete|1|1|1|1|0|0|0")[0]["status"],"VULNERABLE")
 def test_05_mode_bad_vulnerable(self):self.assertEqual(self.run_module("complete|1|1|1|0|1|0|0")[0]["status"],"VULNERABLE")
 def test_06_plus_pattern_vulnerable(self):r,o=self.run_module("complete|1|1|1|0|0|2|0");self.assertEqual(r["status"],"VULNERABLE");self.assertEqual(r["evidence"]["plus_pattern_count"],2);self.assertNotIn("+ +",o)
 def test_07_unresolved_pending(self):r,_=self.run_module("complete|1|1|0|0|0|0|1");self.assertIsNone(r["status"]);self.assertEqual(r["review_state"],"PENDING")
 def test_08_unknown_service_uncheckable(self):self.assertEqual(self.run_module("unknown|0|0|0|0|0|0|0")[0]["status"],"UNCHECKABLE")
 def test_09_scan_error_uncheckable(self):self.assertEqual(self.run_module("scan_error|1|1|0|0|0|0|0")[0]["status"],"UNCHECKABLE")
 def test_10_sources_and_privacy(self):s=S.read_text();[self.assertIn(x,s)for x in("rsh.socket","rlogin.socket","rexec.socket","/etc/xinetd.d","/etc/inetd.conf","/etc/hosts.equiv",".rhosts")];self.assertNotIn("hostname",self.run_module("complete|1|1|1|0|0|0|0")[1])
 def test_11_four_os(self):
  for d,v in(("rocky","9.6"),("rocky","10.0"),("ubuntu","22.04"),("ubuntu","24.04")):
   with self.subTest(d=d,v=v):self.assertEqual(self.run_module("complete|0|0|0|0|0|0|0",d,v)[0]["status"],"GOOD")
 def test_12_single_json_read_only(self):r,o=self.run_module("complete|0|0|0|0|0|0|0");self.assertEqual(o.count("\n"),1);self.assertNotRegex(S.read_text(),r"(?m)^\s*(chmod|chown|rm|mv|touch|tee|systemctl start)\b")
 def test_13_runner_timeout(self):
  q=self.runner();p=q.prepare_item("U-27",Action.CHECK);pl=json.dumps({"item_id":"U-27","status":"GOOD","review_state":"NOT_REQUIRED","current_value":{},"evidence":{"item_id":"U-27","os":{"distro":"rocky","version_id":"9.6"},"observed_at":"x","module_version":MODULE_VERSION},"error":None})
  with patch("os_guard_agent.module_runner.os.access",return_value=True),patch("os_guard_agent.module_runner.subprocess.run",return_value=subprocess.CompletedProcess([],0,pl,"")):self.assertEqual(q.execute_check(p).status,ResultStatus.GOOD)
  with patch("os_guard_agent.module_runner.os.access",return_value=True),patch("os_guard_agent.module_runner.subprocess.run",side_effect=subprocess.TimeoutExpired("x",1)):
   with self.assertRaises(ModuleTimeoutError):q.execute_check(p,1)
if __name__=="__main__":unittest.main()
