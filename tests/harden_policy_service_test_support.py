from __future__ import annotations

from harden_service_test_support import ServiceHardenHarness


class PolicyServiceHardenHarness(ServiceHardenHarness):
    def __init__(self, module, primary_unit, secondary_unit, fixture_policy):
        super().__init__(module, primary_unit, secondary_unit)
        self.fixture_policy = dict(fixture_policy)

    def environment(self, fixture, *, distro="rocky", version="9.6", extra=None):
        merged = dict(self.fixture_policy)
        if extra:
            merged.update(extra)
        return super().environment(
            fixture,
            distro=distro,
            version=version,
            extra=merged,
        )
