"""Policy validation and per-policy detectors. No database needed."""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.policy import PolicyDetectors, entities_for, validate_policy  # noqa: E402
from core.judged_detector import JudgedPIIDetector  # noqa: E402
from core.pii_judge import PIIJudge  # noqa: E402


def test_empty_and_none_are_fine():
    assert validate_policy(None) == {}
    assert validate_policy({}) == {}


def test_values_are_normalised():
    assert validate_policy({"regions": " IN, AU ", "judge": "OFF"}) == {"regions": "in, au", "judge": "off"}


@pytest.mark.parametrize("bad", [
    {"regions": "atlantis"}, {"judge": "maybe"}, {"judge_fail_mode": "half"},
    {"output_scan": "loud"}, {"redact_extra": "colours"}, {"nonsense": "x"}, {"regions": 5}, "text",
])
def test_bad_policy_is_rejected(bad):
    with pytest.raises(ValueError):
        validate_policy(bad)


def test_entities_follow_the_policy():
    assert "IN_AADHAAR" in entities_for({"regions": "in"})
    assert "AU_TFN" not in entities_for({"regions": "in"})
    assert "IN_AADHAAR" not in entities_for({"regions": "none"})
    assert "LOCATION" in entities_for({"redact_extra": "location"})
    assert entities_for({"redact_extra": "all"}) is None


class _Backend:
    async def complete(self, system, user):
        return "[]"


def _base(fail_closed=False):
    return JudgedPIIDetector(judge=PIIJudge(_Backend(), fail_closed=fail_closed), from_env=False)


def test_empty_policy_uses_the_shared_detector():
    base = _base()
    assert PolicyDetectors(base).for_policy({}) is base
    assert PolicyDetectors(base).for_policy({"output_scan": "redact"}) is base   # not a detector setting


def test_judge_off_removes_the_judge_for_that_customer_only():
    base = _base()
    pd = PolicyDetectors(base)
    assert pd.for_policy({"judge": "off"}).judge is None
    assert base.judge is not None


def test_fail_mode_override_keeps_the_same_backend():
    base = _base(fail_closed=False)
    d = PolicyDetectors(base).for_policy({"judge_fail_mode": "closed"})
    assert d.judge.fail_closed is True and d.judge.backend is base.judge.backend
    assert base.judge.fail_closed is False


def test_identical_policies_share_one_detector():
    pd = PolicyDetectors(_base())
    assert pd.for_policy({"regions": "in"}) is pd.for_policy({"regions": "in"})
    assert pd.for_policy({"regions": "in"}) is not pd.for_policy({"regions": "au"})


def test_a_customer_with_regions_off_does_not_redact_those_ids():
    pd = PolicyDetectors(_base())
    text = "My Aadhaar number is 7260 1815 9082."
    assert "IN_AADHAAR" in pd.for_policy({}).detect(text).redacted_text
    assert "IN_AADHAAR" not in pd.for_policy({"regions": "none"}).detect(text).redacted_text
