"""Fuzz every debug adapter that the host can run. See adapter_fuzz/README.md."""

import pytest

from adapter_fuzz import host_profiles
from adapter_fuzz.campaign import assert_clean
from adapter_fuzz.profile import unavailable_reason


@pytest.mark.fuzz
@pytest.mark.parametrize('adapter', host_profiles(), ids=lambda adapter: adapter.name)
def test_fuzz(adapter):
    reason = unavailable_reason(adapter)
    if reason:
        pytest.skip(reason)
    assert_clean(adapter.name, 'adapter_fuzz.machine:AdapterMachine')
