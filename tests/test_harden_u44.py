from pathlib import Path

from harden_service_test_support import ROOT, ServiceHardenContractMixin


class TestU44Harden(ServiceHardenContractMixin):
    harden_module = ROOT / "modules" / "unix" / "harden" / "U-44.sh"
    primary_unit = "tftp.socket"
    secondary_unit = "tftp.service"
    legacy_relative_path = Path("etc/xinetd.d/tftp")
    legacy_content = "service tftp\n{\n disable = no\n}\n"


def test_u44_scope_is_limited_to_tftp_talk_and_ntalk():
    source = (ROOT / "modules" / "unix" / "harden" / "U-44.sh").read_text(
        encoding="utf-8"
    )
    for service_name in ("tftp", "talk", "ntalk"):
        assert service_name in source
