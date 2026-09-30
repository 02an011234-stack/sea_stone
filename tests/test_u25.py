from __future__ import annotations
import hashlib,json,shutil,subprocess,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from os_guard_agent import MODULE_VERSION
from os_guard_agent.manifest import load_manifest
from os_guard_agent.models import Action,OsInfo,ResultStatus
from os_guard_agent.module_runner import ModuleRunner,ModuleTimeoutError
ROOT=Path(__file__).parents[1]; MANIFEST=ROOT/"modules"/"manifest.json"; MODULE=ROOT/"modules"/"unix"/"U-25.sh"
def shpath(): return shutil.which("sh") or next((str(p) for p in (Path(r"C:\Program Files\Git\bin\sh.exe"),Path(r"C:\Program Files\Git\usr\bin\sh.exe")) if p.is_file()),None)
def info(d="rocky",v="9.6"): return OsInfo(d,v,v,"fixture-kernel","host","x86_64",True)
class U25Tests(unittest.TestCase):
 def runner(self,d="rocky",v="9.6"): x=info(d,v); return ModuleRunner(load_manifest(MANIFEST,"manifest-unix-67-v1",x),x)
 def run_module(self,rec,d="rocky",v="9.6"):
  sh=shpath()
  if not sh:self.skipTest("POSIX shell unavailable")
  with tempfile.TemporaryDirectory() as td:
   f=Path(td)/"fixture";f.write_text(rec+"\n",newline="\n");h=hashlib.sha256(f.read_bytes()).hexdigest();env={"PATH":"/usr/sbin:/usr/bin:/sbin:/bin","LC_ALL":"C","OS_GUARD_DISTRO":d,"OS_GUARD_VERSION_ID":v,"OS_GUARD_MODULE_VERSION":MODULE_VERSION,"OS_GUARD_TEST_ROOT":td,"OS_GUARD_TEST_SCAN_FILE":str(f)};cp=subprocess.run([sh,str(MODULE)],env=env,capture_output=True,text=True,timeout=5);self.assertEqual(cp.returncode,0,cp.stderr);self.assertEqual(h,hashlib.sha256(f.read_bytes()).hexdigest());return json.loads(cp.stdout),cp.stdout+cp.stderr
 def test_01_manifest(self): self.assertEqual(self.runner().prepare_item("U-25",Action.CHECK).module_path.name,"U-25.sh")
 def test_02_none_good(self): self.assertEqual(self.run_module("complete|0|0|0|0|0")[0]["status"],"GOOD")
 def test_03_all_approved_good(self): self.assertEqual(self.run_module("complete|2|2|0|0|0")[0]["status"],"GOOD")
 def test_04_unknown_necessity_pending(self): r,_=self.run_module("complete|2|0|0|0|0");self.assertIsNone(r["status"]);self.assertEqual(r["review_state"],"PENDING")
 def test_05_verified_unapproved_vulnerable(self): self.assertEqual(self.run_module("complete|2|0|1|0|0")[0]["status"],"VULNERABLE")
 def test_06_scan_error_uncheckable(self): self.assertEqual(self.run_module("scan_error|0|0|0|0|0")[0]["status"],"UNCHECKABLE")
 def test_07_timeout_uncheckable(self): self.assertEqual(self.run_module("timeout|0|0|0|0|0")[0]["status"],"UNCHECKABLE")
 def test_08_parse_error_uncheckable(self): self.assertEqual(self.run_module("complete|bad|0|0|0|0")[0]["status"],"UNCHECKABLE")
 def test_09_partial_warning(self): r,_=self.run_module("partial_warning|0|0|0|0|2");self.assertEqual(r["status"],"GOOD");self.assertEqual(r["evidence"]["warning_count"],2)
 def test_10_scope_and_privacy(self): r,o=self.run_module("complete|2|0|0|0|0");self.assertTrue(r["evidence"]["xdev_enabled"]);self.assertNotIn("/tmp/",o);s=MODULE.read_text();self.assertIn("-xdev -type f -perm -0002",s)
 def test_11_four_os(self):
  for d,v in (("rocky","9.6"),("rocky","10.0"),("ubuntu","22.04"),("ubuntu","24.04")):
   with self.subTest(d=d,v=v):self.assertEqual(self.run_module("complete|0|0|0|0|0",d,v)[0]["status"],"GOOD")
 def test_12_single_json_read_only(self): r,o=self.run_module("complete|0|0|0|0|0");self.assertEqual(o.count("\n"),1);self.assertNotRegex(MODULE.read_text(),r"(?m)^\s*(chmod|chown|rm|mv|touch|tee)\b")
 def test_13_runner_contract_timeout(self):
  run=self.runner();p=run.prepare_item("U-25",Action.CHECK);good=json.dumps({"item_id":"U-25","status":"GOOD","review_state":"NOT_REQUIRED","current_value":{},"evidence":{"item_id":"U-25","os":{"distro":"rocky","version_id":"9.6"},"observed_at":"x","module_version":MODULE_VERSION},"error":None})
  with patch("os_guard_agent.module_runner.os.access",return_value=True),patch("os_guard_agent.module_runner.subprocess.run",return_value=subprocess.CompletedProcess([],0,good,"")):self.assertEqual(run.execute_check(p).status,ResultStatus.GOOD)
  with patch("os_guard_agent.module_runner.os.access",return_value=True),patch("os_guard_agent.module_runner.subprocess.run",side_effect=subprocess.TimeoutExpired("x",1)):
   with self.assertRaises(ModuleTimeoutError):run.execute_check(p,1)
if __name__=="__main__":unittest.main()
