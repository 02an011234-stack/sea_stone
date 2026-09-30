from __future__ import annotations
import hashlib, json, shutil, subprocess, tempfile, unittest
from pathlib import Path
from unittest.mock import patch
from os_guard_agent import MODULE_VERSION
from os_guard_agent.manifest import load_manifest
from os_guard_agent.models import Action, OsInfo, ResultStatus
from os_guard_agent.module_runner import ModuleRunner, ModuleTimeoutError

ROOT=Path(__file__).parents[1]; MANIFEST=ROOT/"modules"/"manifest.json"; MODULE=ROOT/"modules"/"unix"/"U-24.sh"
def shell_path():
    return shutil.which("sh") or next((str(p) for p in (Path(r"C:\Program Files\Git\bin\sh.exe"),Path(r"C:\Program Files\Git\usr\bin\sh.exe")) if p.is_file()),None)
def info(d="rocky",v="9.6"): return OsInfo(d,v,v,"fixture-kernel","host","x86_64",True)
def payload(): return json.dumps({"item_id":"U-24","status":"GOOD","review_state":"NOT_REQUIRED","current_value":{},"evidence":{"item_id":"U-24","os":{"distro":"rocky","version_id":"9.6"},"observed_at":"2026-09-29T00:00:00Z","module_version":MODULE_VERSION},"error":None})
class U24Tests(unittest.TestCase):
    def runner(self,d="rocky",v="9.6"): x=info(d,v); return ModuleRunner(load_manifest(MANIFEST,"manifest-unix-67-v1",x),x)
    def run_real(self,record,d="rocky",v="9.6"):
        sh=shell_path()
        if not sh:self.skipTest("POSIX shell is unavailable")
        with tempfile.TemporaryDirectory() as td:
            f=Path(td)/"fixture"; f.write_text(record+"\n",encoding="utf-8",newline="\n"); before=hashlib.sha256(f.read_bytes()).hexdigest()
            env={"PATH":"/usr/sbin:/usr/bin:/sbin:/bin","LC_ALL":"C","OS_GUARD_DISTRO":d,"OS_GUARD_VERSION_ID":v,"OS_GUARD_MODULE_VERSION":MODULE_VERSION,"OS_GUARD_TEST_ROOT":td,"OS_GUARD_TEST_SCAN_FILE":str(f)}
            cp=subprocess.run([sh,str(MODULE)],env=env,capture_output=True,text=True,timeout=5)
            self.assertEqual(cp.returncode,0,cp.stderr); self.assertEqual(before,hashlib.sha256(f.read_bytes()).hexdigest())
            return json.loads(cp.stdout),cp.stdout+cp.stderr
    def test_01_manifest(self): self.assertEqual(self.runner().prepare_item("U-24",Action.CHECK).module_path.name,"U-24.sh")
    def test_02_safe_files_good(self): self.assertEqual(self.run_real("complete|2|3|3|1|2|0|0|0|0|0")[0]["status"],"GOOD")
    def test_03_no_environment_files_good(self): self.assertEqual(self.run_real("complete|2|0|0|0|0|0|0|0|0|0")[0]["status"],"GOOD")
    def test_04_owner_violation_vulnerable(self): self.assertEqual(self.run_real("complete|1|1|1|0|0|1|0|0|0|0")[0]["status"],"VULNERABLE")
    def test_05_group_or_other_write_vulnerable(self): self.assertEqual(self.run_real("complete|1|1|1|1|0|0|1|0|0|0")[0]["status"],"VULNERABLE")
    def test_06_acl_write_vulnerable(self): self.assertEqual(self.run_real("complete|1|1|1|1|0|0|0|1|0|0")[0]["status"],"VULNERABLE")
    def test_07_identity_or_symlink_uncertainty_pending(self):
        r,_=self.run_real("complete|1|1|0|0|0|0|0|0|1|1"); self.assertIsNone(r["status"]); self.assertEqual(r["review_state"],"PENDING")
    def test_08_scan_failure_uncheckable(self): self.assertEqual(self.run_real("scan_error|1|0|0|0|0|0|0|0|0|0")[0]["status"],"UNCHECKABLE")
    def test_09_evidence_aggregates_without_identity_paths(self):
        r,o=self.run_real("complete|2|3|3|1|2|0|0|0|0|0"); self.assertEqual(r["evidence"]["checked_file_count"],3); self.assertNotIn("/home/",o); self.assertNotIn("fixture",o)
    def test_10_bounded_environment_names(self):
        s=MODULE.read_text(); [self.assertIn(n,s) for n in (".profile",".kshrc",".cshrc",".bashrc",".bash_profile",".login",".exrc",".netrc")]
    def test_11_four_os(self):
        for d,v in (("rocky","9.6"),("rocky","10.0"),("ubuntu","22.04"),("ubuntu","24.04")):
            with self.subTest(d=d,v=v): self.assertEqual(self.run_real("complete|1|0|0|0|0|0|0|0|0|0",d,v)[0]["status"],"GOOD")
    def test_12_unsupported_os(self): self.assertEqual(self.run_real("complete|1|0|0|0|0|0|0|0|0|0","debian","12")[0]["status"],"UNCHECKABLE")
    def test_13_single_json_and_read_only(self):
        r,o=self.run_real("complete|1|0|0|0|0|0|0|0|0|0"); self.assertEqual(o.count("\n"),1); self.assertEqual(r["item_id"],"U-24"); s=MODULE.read_text(); self.assertNotRegex(s,r"(?m)^\s*(chmod|chown|rm|mv|touch|tee)\b")
    def test_14_runner_contract(self):
        run=self.runner(); p=run.prepare_item("U-24",Action.CHECK)
        with patch("os_guard_agent.module_runner.os.access",return_value=True),patch("os_guard_agent.module_runner.subprocess.run",return_value=subprocess.CompletedProcess([],0,payload(),"")) as call: self.assertEqual(run.execute_check(p).status,ResultStatus.GOOD); self.assertFalse(call.call_args.kwargs["shell"])
    def test_15_runner_timeout(self):
        run=self.runner(); p=run.prepare_item("U-24",Action.CHECK)
        with patch("os_guard_agent.module_runner.os.access",return_value=True),patch("os_guard_agent.module_runner.subprocess.run",side_effect=subprocess.TimeoutExpired("U-24",1)):
            with self.assertRaises(ModuleTimeoutError): run.execute_check(p,1)
if __name__=="__main__": unittest.main()
