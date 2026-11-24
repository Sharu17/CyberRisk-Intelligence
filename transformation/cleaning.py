
import json
import pandas as pd
from pathlib import Path


# Locate project files
PROJECT_DIR = Path(__file__).resolve().parent.parent

INPUT_FILE = PROJECT_DIR / "data" / "raw" / "nvd_raw.json"
OUTPUT_FILE = PROJECT_DIR / "data" / "processed" / "vulnerabilities_clean.csv"


def extract_cvss(cve):
    """
    Extract CVSS score and severity.
    Supports CVSS versions 4.0, 3.1, 3.0 and 2.0.
    """

    metrics = cve.get("metrics", {})

    metric_versions = [
        "cvssMetricV40",
        "cvssMetricV31",
        "cvssMetricV30",
        "cvssMetricV2"
    ]

    for version in metric_versions:
        metric_list = metrics.get(version, [])

        if metric_list:
            metric = metric_list[0]
            cvss_data = metric.get("cvssData", {})

            score = cvss_data.get("baseScore")
            severity = (
                cvss_data.get("baseSeverity")
                or metric.get("baseSeverity")
                or "UNKNOWN"
            )

            return score, severity, version

    return None, "UNKNOWN", None


def extract_description(cve):
    """Get the English vulnerability description."""

    descriptions = cve.get("descriptions", [])

    for description in descriptions:
        if description.get("lang") == "en":
            return description.get("value", "")

    return ""


def transform_data():

    # Load raw JSON data
    with open(INPUT_FILE, "r", encoding="utf-8") as file:
        raw_data = json.load(file)

    vulnerabilities = raw_data.get("vulnerabilities", [])

    records = []

    for item in vulnerabilities:

        cve = item.get("cve", {})

        cvss_score, severity, cvss_version = extract_cvss(cve)

        record = {
            "cve_id": cve.get("id"),
            "description": extract_description(cve),
            "published_date": cve.get("published"),
            "last_modified": cve.get("lastModified"),
            "cvss_score": cvss_score,
            "severity": severity,
            "cvss_version": cvss_version
        }

        records.append(record)

    # Convert records into a DataFrame
    df = pd.DataFrame(records)

    # Remove records without a CVE ID
    df = df.dropna(subset=["cve_id"])

    # Remove duplicate vulnerabilities
    df = df.drop_duplicates(subset=["cve_id"])

    # Convert date columns
    df["published_date"] = pd.to_datetime(
        df["published_date"], errors="coerce", utc=True
    )

    df["last_modified"] = pd.to_datetime(
        df["last_modified"], errors="coerce", utc=True
    )

    # Convert scores to numeric values
    df["cvss_score"] = pd.to_numeric(
        df["cvss_score"], errors="coerce"
    )

    # Save processed data
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    df.to_csv(OUTPUT_FILE, index=False)

    # Display summary
    print("\nData transformation completed!")
    print("--------------------------------")
    print("Total cleaned records:", len(df))
    print("Duplicate records removed:", 
          len(records) - len(df))

    print("\nSeverity distribution:")
    print(df["severity"].value_counts())

    print("\nMissing values:")
    print(df.isnull().sum())

    print("\nProcessed dataset saved at:")
    print(OUTPUT_FILE)


if __name__ == "__main__":
    transform_data()
