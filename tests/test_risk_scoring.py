
import pandas as pd

from analytics.risk_scoring import assign_risk_priority


def test_kev_and_critical_score():
    row = {"cvss_score": 9.8, "is_kev": True}
    assert assign_risk_priority(row) == "CRITICAL"


def test_kev_and_medium_score():
    row = {"cvss_score": 6.5, "is_kev": True}
    assert assign_risk_priority(row) == "HIGH"


def test_non_kev_and_critical_score():
    row = {"cvss_score": 9.8, "is_kev": False}
    assert assign_risk_priority(row) == "HIGH"


def test_non_kev_and_medium_score():
    row = {"cvss_score": 7.5, "is_kev": False}
    assert assign_risk_priority(row) == "MEDIUM"


def test_non_kev_and_low_score():
    row = {"cvss_score": 4.5, "is_kev": False}
    assert assign_risk_priority(row) == "LOW"


def test_missing_score_and_kev():
    row = {"cvss_score": None, "is_kev": True}
    assert assign_risk_priority(row) == "HIGH"


def test_missing_score_and_non_kev():
    row = {"cvss_score": None, "is_kev": False}
    assert assign_risk_priority(row) == "UNCLASSIFIED"
