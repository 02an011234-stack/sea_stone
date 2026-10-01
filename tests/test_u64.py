import json,os,shutil,subprocess,tempfile,unittest
from pathlib import Path
from os_guard_agent import MODULE_VERSION
from os_guard_agent.manifest import load_manifest
from os_guard_agent.models import Action,OsInfo
from os_guard_agent.module_runner import ModuleRunner
R=Path(__file__).parents[1];M=R/'modules/unix/U-64.sh';MF=R/'modules/manifest.json';S=lambda:shutil.which('sh') or r'C:\Program Files\Git\bin\sh.exe';O=lambda d='rocky',v='9.6':OsInfo(d,v,v,'fixture','host','x86_64',True)
class U64Tests(unittest.TestCase):
 def case(self,row,d='rocky',v='9.6'):
  with tempfile.TemporaryDirectory() as td:
   f=Path(td)/'f';f.write_text(row+'\n',newline='\n');e={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C','OS_GUARD_DISTRO':d,'OS_GUARD_VERSION_ID':v,'OS_GUARD_MODULE_VERSION':MODULE_VERSION,'OS_GUARD_TEST_ROOT':td,'OS_GUARD_TEST_U64_FILE':str(f)};p=subprocess.run([S(),str(M)],env=e,capture_output=True,text=True,timeout=5);self.assertEqual(p.returncode,0,p.stderr);return json.loads(p.stdout),p.stdout
 def test_manifest(self):self.assertEqual(ModuleRunner(load_manifest(MF,'manifest-unix-67-v1',O()),O()).prepare_item('U-64',Action.CHECK).module_path.name,'U-64.sh')
 def test_security_updates_pending(self):self.assertEqual(self.case('complete|1|3|0|1|dnf')[0]['status'],'VULNERABLE')
 def test_current_and_policy_verified(self):self.assertEqual(self.case('complete|1|0|1|1|dnf')[0]['status'],'GOOD')
 def test_current_policy_unverified(self):self.assertIsNone(self.case('complete|1|0|0|1|apt')[0]['status'])
 def test_metadata_unknown(self):self.assertEqual(self.case('complete|0|0|0|0|dnf')[0]['status'],'UNCHECKABLE')
 def test_error(self):self.assertEqual(self.case('error|0|0|0|0|unknown')[0]['status'],'UNCHECKABLE')
 def test_four_os_manager_branch(self):
  for d,v,m in [('rocky','9.6','dnf'),('rocky','10','dnf'),('ubuntu','22.04','apt'),('ubuntu','24.04','apt')]:self.assertIsNone(self.case(f'complete|1|0|0|1|{m}',d,v)[0]['status'])
 def test_ubuntu_simulation_works_when_no_download_would_fail(self):
  with tempfile.TemporaryDirectory() as td:
   root=Path(td);bin_dir=root/'bin';bin_dir.mkdir();lists=root/'var/lib/apt/lists';lists.mkdir(parents=True)
   (lists/'archive.ubuntu.com_ubuntu_dists_jammy-security_main_binary-amd64_Packages').write_text('metadata\n')
   args_file=root/'apt-args';apt=bin_dir/'apt-get'
   apt.write_text('#!/bin/sh\nprintf "%s\\n" "$*" > "$OS_GUARD_APT_ARGS_FILE"\ncase " $* " in *" --no-download "*) exit 100;; esac\nprintf "%s\\n" "Inst openssl [old] (new Ubuntu:22.04/jammy-security [amd64])" "Conf openssl (new Ubuntu:22.04/jammy-security [amd64])"\n')
   apt.chmod(0o755);env=os.environ.copy();env.update({'PATH':f'{bin_dir.as_posix()}:/usr/bin:/bin','LC_ALL':'C','OS_GUARD_DISTRO':'ubuntu','OS_GUARD_VERSION_ID':'22.04','OS_GUARD_MODULE_VERSION':MODULE_VERSION,'OS_GUARD_TEST_ROOT':root.as_posix(),'OS_GUARD_APT_ARGS_FILE':args_file.as_posix()})
   p=subprocess.run([S(),str(M)],env=env,capture_output=True,text=True,timeout=5);self.assertEqual(p.returncode,0,p.stderr);result=json.loads(p.stdout)
   self.assertEqual(result['status'],'VULNERABLE');self.assertEqual(result['current_value']['security_updates_pending_count'],1);self.assertEqual(args_file.read_text().strip(),'-s upgrade')
 def test_offline_and_privacy(self):s=M.read_text();self.assertIn('--cacheonly',s);self.assertIn('$a -s upgrade',s);self.assertNotIn('--no-download',s);self.assertNotIn('apt update',s);self.assertNotIn('dnf update',s);self.assertNotIn('package_list',self.case('complete|1|0|1|1|dnf')[1])
