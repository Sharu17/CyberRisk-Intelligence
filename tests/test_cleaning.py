
import pandas as pd
import pytest

from transformation.cleaning import validate_data


def create_sample_data():
    return pd.DataFrame({
        "cve_id": ["CVE-2025-001", "CVE-2025-002"],
        "description": ["Sample vulnerability one", "Sample vulnerability two"],
        "cvss_score": [7.5, 9.8],
        "severity": ["HIGH", "CRITICAL"],
        "cvss_version": ["cvssMetricV31", "cvssMetricV31"]
    })


def test_valid_data_passes():
    df = create_sample_data()
    validate_data(df)


def test_duplicate_cve_ids_fail():
    df = create_sample_data()
    df.loc[1, "cve_id"] = "CVE-2025-001"

    with pytest.raises(ValueError):
        validate_data(df)


def test_invalid_cvss_score_fails():
    df = create_sample_data()
    df.loc[0, "cvss_score"] = 11.5

    with pytest.raises(ValueError):
        validate_data(df)


def test_missing_cve_id_fails():
    df = create_sample_data()
    df.loc[0, "cve_id"] = None

    with pytest.raises(ValueError):
        validate_data(df)


def test_missing_cvss_score_is_allowed():
    df = create_sample_data()
    df.loc[0, "cvss_score"] = None

    validate_data(df)
